"""【旧版路径】从 Mac 上的龙湖 App 容器里读出登录凭据与设备指纹。

新版（2026-11-07 起）已改为手机号验证码登录，设备指纹由服务端 app/dxrisk.py
自动签发并写进 dx_token；不需要 Mac App、不需要 Apple 芯片、不需要抓包。
本工具仅供旧版导入账号 / 迁移场景保留，Intel Mac 用户直接走网页添加账号即可。

App 跑在 Mac 上时（Apple 芯片装的 iOS 版），token 存在 NSUserDefaults 的
SALoginData 里，设备指纹存在 App 内 WebView 的 localStorage 里，都能直接读。

用法：
    python tools/read_mac_app.py

输出 token / lmId / 顶象指纹，照着填进看板的「换指纹」即可。
"""
import glob
import json
import os
import plistlib
import re
import sqlite3
import sys
from datetime import datetime

PREFS = os.path.expanduser(
    "~/Library/Containers/*/Data/Library/Preferences/com.longfor.supera.plist"
)
DX_KEY = "_dx_app_d1a43734fc59aeae9f1562dbd70fdf54"


def read_login(plist_path: str) -> dict:
    with open(plist_path, "rb") as fh:
        data = plistlib.load(fh)
    raw = data.get("SALoginData")
    if not raw:
        return {}
    text = raw if isinstance(raw, str) else raw.decode("utf-8", "replace")
    out = {}
    for key in ("token", "lmId"):
        m = re.search(rf'"{key}"\s*:\s*"?([\w-]+)"?', text)
        if m:
            out[key] = m.group(1)
    return out


def read_dx(container: str) -> str:
    pattern = os.path.join(
        container, "Data/Library/WebKit/WebsiteData/Default/*/*/LocalStorage/localstorage.sqlite3"
    )
    for db in glob.glob(pattern):
        try:
            con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
            row = con.execute("select value from ItemTable where key = ?", (DX_KEY,)).fetchone()
            con.close()
        except Exception:
            continue
        if not row:
            continue
        value = row[0]
        return value.decode("utf-16-le", "replace") if isinstance(value, bytes) else str(value)
    return ""


def read_identity_keys(plist_path: str) -> dict:
    """顶象设备身份真正落脚的地方。

    WebKit 里的 _dx_app_ 只是缓存：删掉它 SDK 会重新算出一个一模一样的值，
    因为源头在这里（App 自己的容器 NSUserDefaults）——或者更外层的 IDFV。
    所以「重装后指纹变不变」等价于「重装有没有重建这个容器」。
    """
    try:
        with open(plist_path, "rb") as fh:
            data = plistlib.load(fh)
    except Exception:
        return {}
    out = {}
    for key in ("DxriskAppID:appId", "MAUserDeviceIdKey"):
        if key in data:
            val = data[key]
            text = val if isinstance(val, str) else repr(val)
            out[key] = text
    return out


def container_birth(path: str) -> str:
    try:
        st = os.stat(path)
        return datetime.fromtimestamp(st.st_birthtime).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return "?"


def main() -> int:
    found = []
    for plist_path in sorted(glob.glob(PREFS)):
        container = plist_path.split("/Library/Containers/")[1].split("/")[0]
        container = os.path.expanduser(f"~/Library/Containers/{container}")
        login = read_login(plist_path)
        if not login.get("token"):
            continue
        found.append((container, plist_path, login))

    if not found:
        print("没找到已登录的龙湖 App。确认 App 在本机登录过，路径：", PREFS)
        return 1

    if len(found) > 1:
        print(f"⚠️  发现 {len(found)} 个已登录容器。说明系统里残留了旧的 App 数据，")
        print("    看板里填的指纹可能不是 App 当前真正在用的那一个。")
        print()

    for container, plist_path, login in found:
        dx = read_dx(container)
        ident = read_identity_keys(plist_path)
        print("=" * 64)
        print(f"容器      {os.path.basename(container)}")
        print(f"容器创建  {container_birth(container)}   ← 重装后这个时间没变，就说明容器被复用了")
        print(f"lmId      {login.get('lmId', '?')}")
        print(f"token     {login['token']}")
        print(f"指纹      {dx or '（没读到，App 里打开一次签到页再试）'}")
        if ident:
            for key, val in ident.items():
                shown = val if key == "MAUserDeviceIdKey" else f"{val[:16]}…（已加密）"
                print(f"身份源    {key} = {shown}")
        else:
            print("身份源    （plist 里没有顶象键，指纹可能来自更外层的 IDFV）")
        print()
        print("填进看板的信息：")
        print(json.dumps({"token": login["token"], "lmId": login.get("lmId"), "dx_token": dx},
                         ensure_ascii=False, indent=2))
        print()

    print("注意：每个账号必须用不同的指纹，共用同一指纹会触发风控。")
    print("      换指纹 = 让容器重建，不是点一下重装：")
    print("        python tools/reset_dx_identity.py --rebuild")
    return 0


if __name__ == "__main__":
    sys.exit(main())
