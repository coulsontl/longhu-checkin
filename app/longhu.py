"""龙湖天街 API 客户端。

封装了三件事：
1. refresh_token —— 用 token2key + key2token 把 token 有效期滚动重置为 30 天
2. checkin       —— 每日签到，严格区分「成功 / 今日已签 / 鉴权失败」
3. fetch_profile —— 拉取成长值、等级、珑珠余额

所有请求强制直连（trust_env=False），避免宿主机的抓包代理干扰。
"""

import base64
import hashlib
import html
import json
import re
import time
from datetime import datetime, timedelta, timezone

import requests

BASE = "https://gw2c-hw-open.longfor.com"

# 小程序前端写死的签名密钥（来自 sign-in-prize 的 JS）
SIGN_SECRET_MICRO_APP = "Q74eKtH5LePYfSjIiflUbCL2gxjTa7rF"

API_KEY_MAIN = "c06753f1-3e68-437d-b592-b94656ea5517"
API_KEY_MEMBER = "98717e7a-a039-46af-8143-be7558a089c0"
API_KEY_WALLET = "f4a2290e-c382-45b7-949c-3253d07e9b5b"

# 小程序：日日签 日日赚
ACTIVITY_NO = "11111111111686241863606037740000"
# APP：APP签到 奖励翻倍（会员端「赚珑珠」里的 App 专享入口）
APP_ACTIVITY_NO = "11111111111736501868255956070000"

# 两个入口共用一个登录态（token 与 channel 都相同），只是活动号不同，
# 所以同一天可以各签一次，成长值叠加。
ACTIVITIES = (
    {"key": "mini", "name": "小程序", "activity_no": ACTIVITY_NO},
    {"key": "app", "name": "APP", "activity_no": APP_ACTIVITY_NO},
)

# 顶象设备指纹。签到接口要求带 X-LF-DXRisk-Token，缺了会被风控拦下，
# 返回 8040012 / 8040016「网络故障，请稍后再试」。
# 这个 token 由龙湖自建的 udid 服务签发，一个 GET 就能拿到，不需要跑 JS SDK。
RISK_TOKEN_URL = "https://ly-sta.longhu.net/udid/c1?"
RISK_TTL = 1800  # 半小时换一次，避免长期复用同一个指纹
_risk_cache = {"token": "", "ts": 0.0}

DEFAULT_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/144.0.0.0 Safari/537.36 MicroMessenger/7.0.20.1781(0x6700143B) NetType/WIFI "
    "MiniProgramEnv/Mac MacWechat/WMPF MacWechat/3.8.7(0x13080712) "
    "UnifiedPCMacWechat(0xf2641d55) XWEB/25561"
)

THIRTY_DAYS = 30


class LonghuError(Exception):
    """业务层可读错误"""


# --------------------------------------------------------------------------
# 底层请求
# --------------------------------------------------------------------------

def _decode(resp: requests.Response) -> dict:
    """接口有时返回裸 JSON，有时返回 base64 包裹的 JSON，两种都兼容。"""
    text = resp.text or ""
    try:
        return json.loads(text)
    except Exception:
        pass
    try:
        return json.loads(base64.b64decode(text).decode("utf-8"))
    except Exception:
        pass
    return {"code": "parse_error", "message": text[:200]}


def _request(method: str, url: str, headers: dict, body: dict | None = None,
             timeout: int = 20) -> dict:
    session = requests.Session()
    session.trust_env = False  # 忽略系统代理，直连
    clean = {k: v for k, v in headers.items() if v not in (None, "")}
    try:
        if method.upper() == "GET":
            resp = session.get(url, headers=clean, timeout=timeout)
        else:
            resp = session.post(url, headers=clean, json=body, timeout=timeout)
    except requests.RequestException as exc:
        raise LonghuError(f"网络请求失败: {exc}") from exc
    finally:
        session.close()
    return _decode(resp)


def sign_headers(body: dict | None = None) -> dict:
    """复刻小程序签名：md5(排序参数 + '&' + 毫秒时间戳 + '&' + secret)"""
    parts = []
    for key in sorted((body or {}).keys()):
        value = body[key]
        if isinstance(value, (dict, list)):
            continue
        text = str(value)
        if text.strip() and text != "null":
            parts.append(f"{key}={text}")
    joined = "|".join(parts)
    ts = str(int(time.time() * 1000))
    raw = (joined + "&" if joined else "") + ts + "&" + SIGN_SECRET_MICRO_APP
    return {
        "X-LONGZHU-TimeStamp": ts,
        "X-Client-Type": "microApp",
        "X-LONGZHU-Sign": hashlib.md5(raw.encode("utf-8")).hexdigest(),
    }


# --------------------------------------------------------------------------
# 业务接口
# --------------------------------------------------------------------------

def refresh_token(account: dict) -> tuple[bool, str]:
    """滚动续期。成功返回 (True, 新token)，失败返回 (False, 原因)。

    token 本身通常不变，但服务端会把有效期重新算成 30 天。
    """
    token = account.get("token") or ""
    if not token:
        return False, "缺少 token"

    headers = {
        "lmToken": token,
        "X-LF-Bucode": account.get("bu_code", "C20400"),
        "X-LF-Api-Version": "v2_6_0",
        "X-LF-Channel": account.get("channel", "C2"),
        "X-LF-App-Version": "2.6.0",
        "Content-Type": "application/json",
        "User-Agent": account.get("user_agent") or DEFAULT_UA,
        "Origin": "https://longzhu.longfor.com",
        "Referer": "https://longzhu.longfor.com/",
    }
    headers.update(sign_headers({}))

    res = _request("POST", f"{BASE}/supera/mine/v2_6_0/token/token2key", headers, {})
    key = (res.get("data") or {}).get("key")
    if not key:
        return False, res.get("message") or "token2key 未返回 key（token 可能已失效）"

    wallet_headers = {
        "X-Gaia-Api-Key": API_KEY_WALLET,
        "systype": "WALLET",
        "Content-Type": "application/json",
        "User-Agent": account.get("user_agent") or DEFAULT_UA,
        "Origin": "https://longball.longhu.net",
        "Referer": "https://longball.longhu.net/",
    }
    res2 = _request(
        "POST",
        f"{BASE}/lmember-lpns-api-prod/api/lpns/auth/v1/key2token",
        wallet_headers,
        {"key": key, "buCode": account.get("bu_code", "C20400"), "channel": account.get("channel", "C2")},
    )
    data = res2.get("data") or {}
    if res2.get("code") == "0000" and data.get("token"):
        return True, data["token"]
    return False, res2.get("message") or "key2token 未返回 token"


def risk_token(account: dict | None = None, force: bool = False) -> str:
    """取一个顶象设备指纹，用于 X-LF-DXRisk-Token。

    udid 服务用 JSONP 回包（`_callback({...})` 且带 HTML 实体转义），
    这里直接解析出 data 字段。拿不到就返回空串——签到请求照发，
    只是可能被风控挡成 8040012，不会因此抛异常。
    """
    now = time.time()
    if not force and _risk_cache["token"] and now - _risk_cache["ts"] < RISK_TTL:
        return _risk_cache["token"]

    headers = {
        "User-Agent": (account or {}).get("user_agent") or DEFAULT_UA,
        "Referer": "https://longzhu.longfor.com/",
    }
    session = requests.Session()
    session.trust_env = False
    token = ""
    try:
        resp = session.get(RISK_TOKEN_URL, headers=headers, timeout=15)
        text = html.unescape(resp.text or "").strip()
        match = re.search(r"\((\{.*\})\)", text, re.S)
        payload = json.loads(match.group(1) if match else text)
        token = str(payload.get("data") or "").strip()
    except Exception:
        token = ""
    finally:
        session.close()

    if token:
        _risk_cache["token"] = token
        _risk_cache["ts"] = now
    return token


def _task_headers(account: dict) -> dict:
    """活动接口（page-info / clock）共用的请求头。"""
    headers = {
        "User-Agent": account.get("user_agent") or DEFAULT_UA,
        "Origin": "https://longzhu.longfor.com",
        "Referer": "https://longzhu.longfor.com/",
        "X-LF-DXRisk-Source": "5",
        "X-LF-Bu-Code": account.get("bu_code", "C20400"),
        # 签到必须用签到专用 key（前端写死的常量）。若沿用抓包里的 key，
        # 用户粘贴的是会员接口 cURL 时会拿到 member key，导致 401。
        "X-GAIA-API-KEY": API_KEY_MAIN,
        "X-LF-UserToken": account.get("token") or "",
        "X-LF-Channel": account.get("channel", "C2"),
        # 真实 App 未过滑块时，前端就是把这个字符串原样发出去的（抓包可见）。
        # 过了滑块会变成 "<token>:<指纹>"，两个值用冒号拼接。
        "X-LF-DXRisk-Captcha-Token": "undefined",
        "token": account.get("token") or "",
        "Content-Type": "application/json;charset=UTF-8",
    }
    # 设备指纹：只认账号里存的顶象指纹（新版由 dxrisk 服务端签发，旧版来自 App），不再用 udid/c1 兜底——
    # 那个接口的缓存是进程级的，多个账号会共用同一份，本身就是风控特征。
    #
    # 2026-11-05 抓包补充：指纹本身不是门槛。同一指纹未带滑块凭证时被
    # 8040012 拦下，过完滑块立刻成功；签完之后再用同一指纹打 clock 直接
    # 0000。所以真正缺的是下面那个 captcha token，不是指纹。
    fingerprint = (account.get("dx_token") or "").strip()
    if fingerprint:
        headers["X-LF-DXRisk-Token"] = fingerprint
    return headers


def sign_state(account: dict, activity_no: str = ACTIVITY_NO) -> bool | None:
    """查询「今天是否已签到」。True=已签，False=未签，None=查不到。

    以服务端返回的日历为准，比依赖 clock 接口的 is_popup 可靠：
    clock 在「已签到」和「签到被拒」两种情况下都可能不返回奖励明细。
    """
    try:
        res = _request(
            "POST",
            f"{BASE}/lmarketing-task-api-mvc-prod/openapi/task/v1/signature/page-info",
            _task_headers(account),
            {"activity_no": activity_no},
        )
    except LonghuError:
        return None
    if res.get("code") != "0000":
        return None

    data = res.get("data") or {}
    # 用服务端时间判断“今天”，避免容器时区与龙湖不一致
    today = datetime.now()
    raw = data.get("current_date_time")
    if raw:
        try:
            today = datetime.fromtimestamp(int(raw) / 1000)
        except (TypeError, ValueError):
            pass

    for item in data.get("seven_days_signs") or []:
        try:
            day = (int(item.get("sign_year")), int(item.get("sign_month")), int(item.get("sign_day")))
        except (TypeError, ValueError):
            continue
        if day == (today.year, today.month, today.day):
            # 20 = 已签到，10 = 未签到
            return int(item.get("sign_status") or 0) == 20
    return None


CODE_HINT = {
    # 2026-11-05 抓包实测：8040012 与「指纹本身好不好」无关。
    # 同一账号、同一指纹，未带 X-LF-DXRisk-Captcha-Token 时被 8040012 拦下；
    # 过完顶象滑块、拿到 token 后立刻签到成功（+5 成长值 +10 连签）。
    #
    # 触发条件已确认（2026-11-05，其他使用者同样是本项目、纯 API 自动签）：
    # 每个「(账号, 指纹)」组合只有首次签到要过一次人机验证，之后连续多天纯 API
    # 自动签都不再弹。所以这不是每日例行事，而是一次性的入网动作。
    #
    # 2026-11-10 更正：新版手机号登录的指纹由服务端 dxrisk 签发，与 App 内那份不同。
    # 去 App 里手动签到只会让「(账号, App 指纹)」入网，帮不了「(账号, 面板指纹)」，
    # 所以会出现「按提示拖了滑块却依旧失败」。正确做法是用账号自己的 dx_token，
    # 由 LONGHU_CAPTCHA 求解器过一次滑块并重试；反复换指纹或试探会重置信任、拉低评分。
    "801810": "风控拦截：这对组合评分偏低。别换指纹；设置 LONGHU_CAPTCHA=auto/manual 用当前 dx_token 过一次滑块，之后停止一切接口试探",
    "801811": "需要滑块验证：别换指纹；设置 LONGHU_CAPTCHA=auto/manual 用当前 dx_token 过一次滑块（只需一次）",
    "801812": "风控拦截：这对组合评分偏低。别换指纹；设置 LONGHU_CAPTCHA=auto/manual 用当前 dx_token 过一次滑块，之后停止一切接口试探",
    "8040012": "新「(账号,指纹)」组合需一次性人机验证，不是网络故障也不是指纹坏了；保持当前指纹不变，设置 LONGHU_CAPTCHA=auto/manual 让看板用这份指纹过滑块并自动重试，之后长期自动签",
    "8040016": "新「(账号,指纹)」组合需一次性人机验证，不是网络故障也不是指纹坏了；保持当前指纹不变，设置 LONGHU_CAPTCHA=auto/manual 让看板用这份指纹过滑块并自动重试，之后长期自动签",
}

# 风控类拒绝不是偶发失败：文案本身就是「明日再来」，当天重试只会继续给
# 风控送样本、拉低评分。单独返回 risk 状态，让调度器不排当天重试。
RISK_CODES = {"801810", "801811", "801812", "8040012", "8040016"}


def _solve_captcha(account: dict) -> tuple[str | None, str]:
    """过滑块换 captcha token。没开启（默认）就直接返回 off。"""
    try:
        from . import captcha as captcha_mod
    except Exception as exc:  # 缺依赖不应该影响正常签到
        return None, f"求解器不可用：{exc}"
    mode = captcha_mod.mode_from_env()
    if mode == "off":
        return None, "off"
    device = (account.get("dx_token") or "").strip()
    if not device:
        return None, "缺少设备指纹"
    return captcha_mod.solve(device, mode=mode)


def _captcha_header(token: str, device: str) -> str:
    """接口要求的格式：token 在前，设备指纹在后，冒号拼接。"""
    return f"{token}:{device}" if device else token


def checkin(account: dict, activity_no: str = ACTIVITY_NO,
            label: str = "") -> tuple[str, str]:
    """每日签到。返回 (status, message)

    status: ok（签到成功）/ already（今日已签）/ risk（风控拒绝）/ fail（其他失败）
    """
    tag = f"{label}" if label else ""
    # 先查状态：已签就不要再打签到接口，免得无谓地触发风控
    before = sign_state(account, activity_no)
    if before is True:
        return "already", f"{tag}今日已签到"

    headers = _task_headers(account)
    try:
        res = _request(
            "POST",
            f"{BASE}/lmarketing-task-api-mvc-prod/openapi/task/v1/signature/clock",
            headers,
            {"activity_no": activity_no},
        )
    except LonghuError as exc:
        return "fail", f"{tag}签到请求失败：{exc}"

    code = str(res.get("code") or "")
    data = res.get("data") or {}
    message = res.get("message") or ""

    if code == "0000":
        if data.get("is_popup") == 1:
            reward = 0
            for item in (data.get("reward_info") or []):
                reward += int(item.get("reward_num") or 0)
            return "ok", f"{tag}签到成功，获得 {reward} 积分"
        # is_popup=0 有两种可能：本来已签，或接口假成功。用日历复核。
        after = sign_state(account, activity_no)
        if after is False:
            return "fail", f"{tag}签到接口返回成功但日历仍显示未签，请稍后重试"
        return "already", f"{tag}今日已签到"

    if "未登录" in message or "登录已过期" in message or code == "801001":
        return "fail", "鉴权失败：token 已失效，需要重新导入"

    # 兜底：接口报错但可能实际上已经签上（历史上出现过报错但状态已更新）
    if sign_state(account, activity_no) is True:
        return "ok", f"{tag}签到成功（接口返回 {code}，已按日历确认）"

    hint = CODE_HINT.get(code, "")
    detail = f"{message or '未知错误'}（code={code or '无'}{'，' + hint if hint else ''}）"
    if code in RISK_CODES:
        # 8040012/8040016 = 当天首次签到缺人机验证凭证。配了求解器就先过滑块再重试一次。
        # 重试只做一次：同一张图第 3 次会被判 4011 HIGH_RISK，越试越糟。
        if code in ("8040012", "8040016"):
            token, why = _solve_captcha(account)
            if token:
                device = (account.get("dx_token") or "").strip()
                retry_headers = _task_headers(account)
                retry_headers["X-LF-DXRisk-Captcha-Token"] = _captcha_header(token, device)
                try:
                    res2 = _request(
                        "POST",
                        f"{BASE}/lmarketing-task-api-mvc-prod/openapi/task/v1/signature/clock",
                        retry_headers,
                        {"activity_no": activity_no},
                    )
                except LonghuError as exc:
                    return "fail", f"{tag}过滑块后签到请求失败：{exc}"
                code2 = str(res2.get("code") or "")
                data2 = res2.get("data") or {}
                if code2 == "0000" and data2.get("is_popup") == 1:
                    reward = 0
                    for item in (data2.get("reward_info") or []):
                        reward += int(item.get("reward_num") or 0)
                    return "ok", f"{tag}签到成功（已过滑块），获得 {reward} 积分"
                if sign_state(account, activity_no) is True:
                    return "ok", f"{tag}签到成功（已过滑块，按日历确认）"
                detail = f"{detail}；过滑块后仍失败（code={code2 or '无'}）"
            elif why and why != "off":
                detail = f"{detail}；滑块求解未完成：{why}"
        # 风控拒绝：当天重试无意义，标 risk 不进入失败重试排程
        return "risk", f"{tag}签到失败：{detail}"
    return "fail", f"{tag}签到失败：{detail}"


def fetch_profile(account: dict) -> dict:
    """拉取成长值 / 等级 / 珑珠。token 无效时抛 LonghuError。"""
    headers = {
        "User-Agent": account.get("user_agent") or DEFAULT_UA,
        "lmToken": account.get("token") or "",
        "X-Gaia-Api-Key": API_KEY_MEMBER,
        "X-LF-Bucode": account.get("bu_code", "C20400"),
        "X-LF-Channel": account.get("channel", "C2"),
        "X-LF-Api-Version": "v2_6_0",
        "Content-Type": "application/json",
    }
    res = _request(
        "GET",
        f"{BASE}/supera/member/api/bff/pages/v2_6_0/v1/user-info",
        headers,
    )
    if res.get("code") != "0000":
        raise LonghuError(res.get("message") or "用户信息查询失败")

    data = res.get("data") or {}
    profile = {
        "growth_value": int(data.get("growthValue") or 0),
        "level_name": data.get("levelName") or "",
        "nickname": data.get("nickName") or data.get("nickname") or "",
        # 脱敏手机号（形如 138****0000）。昵称对所有账号都是「珑珠用户」，
        # 只有手机号能把多个账号区分开，所以默认用它当账号显示名。
        "phone": data.get("desensitizePhone") or "",
    }

    balance_headers = dict(headers)
    try:
        res2 = _request(
            "GET",
            f"{BASE}/supera/member/api/bff/pages/v2_6_0/v2/user-lz-balance",
            balance_headers,
        )
        if res2.get("code") == "0000":
            bdata = res2.get("data") or {}
            profile["balance"] = float(bdata.get("balance") or 0)
            profile["expiring_lz"] = float(bdata.get("expiringLz") or 0)
    except LonghuError:
        pass
    return profile


def probe_token(token: str, user_agent: str | None = None,
                bu_code: str = "C20400", channel: str = "C2") -> dict:
    """校验一个 token 是否可用，返回 profile。失败抛 LonghuError。"""
    return fetch_profile({
        "token": token,
        "user_agent": user_agent or DEFAULT_UA,
        "api_key": API_KEY_MAIN,
        "bu_code": bu_code,
        "channel": channel,
    })


def expire_at(seconds: int = THIRTY_DAYS * 86400) -> str:
    """按当前时间推算过期时刻（ISO 字符串，本地时区）。"""
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()
