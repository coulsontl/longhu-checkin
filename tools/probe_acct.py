"""新号 AB 探针：同一个 token、同一套请求头，分别打小程序活动与 APP 活动的 clock。

用法：
    python probe_acct.py <token> [备注]

结论矩阵：
    小程序 0000 + APP 801810  -> 是「APP 活动」特有门槛（环境/活动端限制），账号本身没问题
    两个都 0000               -> 之前失败是「当天已参与」之类，可正常跑双入口
    两个都 801810             -> token 或设备指纹不被认可（新号更容易被判风险）
"""
import sys, json, pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from app import longhu  # noqa: E402


def describe(account, name, act, do_clock=True):
    state = longhu.sign_state(account, act)
    res = longhu._request(
        "POST",
        f"{longhu.BASE}/lmarketing-task-api-mvc-prod/openapi/task/v1/signature/page-info",
        longhu._task_headers(account),
        {"activity_no": act},
    )
    data = res.get("data") or {}
    print(f"[{name}] page-info code={res.get('code')} 今日={'已签' if state else ('未签' if state is False else '未知')} "
          f"task_show={data.get('task_show_status')} sign_again_num={data.get('sign_again_num')}")

    if not do_clock:
        return "skip"
    clock = longhu._request(
        "POST",
        f"{longhu.BASE}/lmarketing-task-api-mvc-prod/openapi/task/v1/signature/clock",
        longhu._task_headers(account),
        {"activity_no": act},
    )
    d = clock.get("data") or {}
    print(f"[{name}] clock     code={clock.get('code')} msg={clock.get('message')} "
          f"is_popup={d.get('is_popup')} rewards={d.get('reward_info')}")
    after = longhu.sign_state(account, act)
    print(f"[{name}] 复核      今日={'已签' if after else ('未签' if after is False else '未知')}")
    return str(clock.get("code") or "")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    token = sys.argv[1].strip()
    label = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith("-") else "新号"
    do_clock = "--no-clock" not in sys.argv
    dx = ""
    for arg in sys.argv[3:]:
        if arg.startswith("--dx="):
            dx = arg.split("=", 1)[1].strip()
    account = {
        "token": token,
        "user_agent": longhu.DEFAULT_UA,
        "channel": "C2",
        "bu_code": "C20400",
        "dx_token": dx,
    }
    profile = longhu.fetch_profile(account)
    print(f"== {label}  token={token[:6]}...{token[-4:]}  昵称={profile.get('nickname')} "
          f"等级={profile.get('level_name')}  成长值={profile.get('growth_value')}")
    print(f"   指纹：{dx or '未指定（用 udid/c1 现造，会被判风险）'}")
    mini = describe(account, "小程序", longhu.ACTIVITY_NO, do_clock)
    print("-" * 60)
    app_ = describe(account, "APP", longhu.APP_ACTIVITY_NO, do_clock)
    print("=" * 60)
    ok_codes = ("0000",)
    if mini in ok_codes and app_ in ok_codes:
        print("判定：两个都能签 -> 这套指纹可用，双入口可正常跑")
    elif mini in ok_codes:
        print("判定：小程序能签、APP 被拒 -> 账号正常，问题在 APP 活动的指纹要求")
    elif app_ in ok_codes:
        print("判定：APP 能签、小程序被拒 -> 少见，看看是不是小程序侧有额外限制")
    elif mini == "skip" or app_ == "skip":
        print("判定：只查了状态（--no-clock）")
    else:
        print(f"判定：两个都被拒（{mini}/{app_}）-> 换一份被认可的顶象指纹（新版由服务端签发）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
