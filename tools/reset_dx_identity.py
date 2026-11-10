"""【旧版路径】给龙湖 App 换一份顶象设备指纹，不用卸载重装。

新版手机号验证码登录会在服务端自动签发指纹，不需要本脚本；
下面内容仅适用于旧版 App 内真实指纹的维护。

背景（2026-11-05 实测）：
    指纹不是存在 WebView 的 localStorage 里 —— 删掉 `_dx_app_` 那个 key，
    SDK 会重新算出一个一模一样的新值。真正的源头在 App 容器的 NSUserDefaults：

        DxriskAppID:appId   顶象的加密 appId
        MAUserDeviceIdKey   App 自己的设备 UUID

    所以「重装 App」能不能换指纹，取决于重装有没有重建 `~/Library/Containers/<ID>`。
    容器被复用（macOS 上默认就会复用），指纹一个字符都不会变。

本脚本只清顶象相关的身份，不动登录态（SALoginData 保留）：
    1. 备份 com.longfor.supera.plist 和 localstorage.sqlite3
    2. 删 plist 里的顶象键
    3. 删 WebKit localStorage 里的 `_dx_app_*`
    4. 重启 cfprefsd，让改动落盘生效
之后打开 App 的签到页，SDK 会重新生成一份新指纹。

用法：
    python tools/reset_dx_identity.py               # 只看，不改（默认）
    python tools/reset_dx_identity.py --purge       # 删容器重建 = 卸载重装（推荐）
    python tools/reset_dx_identity.py --rebuild     # 挪走容器，保留旧的可随时挪回
    python tools/reset_dx_identity.py --apply       # 只清顶象键，已证实换不了指纹

换指纹的唯一有效手段是「让容器重建」：
    - 卸载重装：卸载会删掉容器，所以有效
    - 单纯替换 .app：容器还在，所以无效（2026-11-04 实测，一个字符都没变）
--purge 直接删容器，效果等同卸载重装，但不用重新下载 122MB 的安装包。

风险：换了指纹等于换了设备。同一账号从「新设备」登录，可能触发二次验证，
      已有的签到连续天数不受影响，但当天首次签到仍要过一次滑块。
"""
import argparse
import glob
import os
import plistlib
import shutil
import sqlite3
import subprocess
import sys
from datetime import datetime

PREFS = os.path.expanduser(
    "~/Library/Containers/*/Data/Library/Preferences/com.longfor.supera.plist"
)
BACKUP_ROOT = os.path.expanduser("~/longhu-dx-backup")
HOLD_ROOT = os.path.expanduser("~/longhu-container-hold")
APP_PATH = "/Applications/龙湖.app"
DX_PLIST_KEYS = ("DxriskAppID:appId", "MAUserDeviceIdKey")
LS_PATTERN = os.path.join(
    "Data/Library/WebKit/WebsiteData/Default/*/*/LocalStorage/localstorage.sqlite3"
)


def app_running() -> bool:
    for pat in ("龙湖.app", "com.longfor.supera"):
        if subprocess.run(["pgrep", "-f", pat], capture_output=True).returncode == 0:
            return True
    return False


def find_containers() -> list[tuple[str, str]]:
    out = []
    for plist_path in sorted(glob.glob(PREFS)):
        container = plist_path.split("/Library/Containers/")[1].split("/")[0]
        container = os.path.expanduser(f"~/Library/Containers/{container}")
        try:
            with open(plist_path, "rb") as fh:
                data = plistlib.load(fh)
        except Exception:
            continue
        if not data.get("SALoginData"):
            continue
        out.append((container, plist_path))
    return out


def read_state(plist_path: str, container: str) -> tuple[dict, str]:
    with open(plist_path, "rb") as fh:
        data = plistlib.load(fh)
    marks = {k: (data[k] if isinstance(data[k], str) else repr(data[k])) for k in DX_PLIST_KEYS if k in data}
    dx = ""
    for db in glob.glob(os.path.join(container, LS_PATTERN)):
        try:
            con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
            row = con.execute(
                "select key, value from ItemTable where key like '_dx_app_%'"
            ).fetchone()
            con.close()
        except Exception:
            continue
        if row:
            val = row[1]
            dx = val.decode("utf-16-le", "replace") if isinstance(val, bytes) else str(val)
            break
    return marks, dx


def apply(container: str, plist_path: str) -> str:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = os.path.join(BACKUP_ROOT, stamp)
    os.makedirs(backup, exist_ok=True)
    shutil.copy2(plist_path, os.path.join(backup, "com.longfor.supera.plist"))

    # 1) plist：删顶象键
    with open(plist_path, "rb") as fh:
        data = plistlib.load(fh)
    for key in DX_PLIST_KEYS:
        data.pop(key, None)
    with open(plist_path, "wb") as fh:
        plistlib.dump(data, fh)

    # 2) WebKit：删缓存指纹，否则 SDK 会直接复用旧值
    cleared = 0
    for db in glob.glob(os.path.join(container, LS_PATTERN)):
        shutil.copy2(db, os.path.join(backup, f"localstorage-{cleared}.sqlite3"))
        try:
            con = sqlite3.connect(db)
            cur = con.execute("delete from ItemTable where key like '_dx_app_%'")
            cleared += cur.rowcount
            con.commit()
            con.close()
        except Exception as exc:
            print(f"  清理 localStorage 失败：{exc}")

    # 3) 让 cfprefsd 丢掉缓存，否则它会把旧值写回去
    subprocess.run(["killall", "cfprefsd"], capture_output=True)
    return f"{backup}（清掉 {cleared} 条 localStorage 指纹）"


def purge(containers: list[tuple[str, str]]) -> int:
    """等价于「卸载重装」：删掉容器让系统重建。

    为什么卸载重装能换指纹？因为卸载会把 `~/Library/Containers/<ID>` 一起删掉，
    重装后系统新建一个空容器，SDK 只能重新生成身份。反过来，只替换 /Applications
    里的 .app、不动容器，指纹一个字符都不会变 —— 2026-11-04 那次「重装」就是这样，
    容器 birth 还是 2025-12-17。

    所以真正起作用的是「容器被删」，删 App 只是顺带的。本函数只删容器、不动 .app，
    效果与卸载重装完全一致，但省掉一次下载安装。删除前会完整备份，可回退。
    """
    if not os.path.isdir(APP_PATH):
        print(f"⚠️  {APP_PATH} 不存在。先把 App 装回来再跑。")
        return 1

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_dir = os.path.join(BACKUP_ROOT, f"{stamp}-containers")
    os.makedirs(backup_dir, exist_ok=True)

    for container, _ in containers:
        name = os.path.basename(container)
        dest = os.path.join(backup_dir, name)
        # 用 cp -R 而不是 copytree：容器里有 socket 和特殊权限文件，copytree 会炸
        r = subprocess.run(["cp", "-R", container, dest], capture_output=True)
        if r.returncode != 0 and not os.path.isdir(dest):
            print(f"❌ 备份 {name} 失败：{r.stderr.decode()[:200]}")
            return 1
        try:
            shutil.rmtree(container)
        except Exception as exc:
            print(f"❌ 删除 {name} 失败：{exc}")
            print("   确认已授予「完全磁盘访问权限」，且 App 完全退出。")
            return 1
        print(f"✅ {name} 已删除（备份 {dest}）")

    subprocess.run(["killall", "cfprefsd"], capture_output=True)
    subprocess.run(["open", "-a", APP_PATH], capture_output=True)
    print("\n已启动 App。接下来：")
    print("  1. 登录（token 与容器绑定，换容器必须重新登录）")
    print("  2. 进入签到页 —— 顶象 SDK 在这一步才会生成新指纹")
    print("  3. python tools/read_mac_app.py 读出新指纹")
    print(f"\n要回退：把 {backup_dir} 里的目录拷回 ~/Library/Containers/。")
    return 0


def rebuild(containers: list[tuple[str, str]]) -> int:
    """把容器整体挪走，让系统在下次启动时新建一个 —— 这是实测唯一能换指纹的办法。

    2026-11-05 验证：容器 `C2D9105A…`（2025-12 建）挪走后重启 App，
    系统新建了 `204A91BA…`（11:42 建），指纹从 `6ae93a6c…` 变成 `6aebfcb2…`。
    注意：容器带 containermanager 的扩展属性，命令行移动需要「完全磁盘访问权限」，
    否则会报 EPERM；App 运行中也可能失败。
    """
    if not os.path.isdir(APP_PATH):
        print(f"⚠️  {APP_PATH} 不存在。先把 App 装回来再跑。")
        return 1
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    for container, _ in containers:
        dest = os.path.join(HOLD_ROOT, f"{os.path.basename(container)}-{stamp}")
        os.makedirs(HOLD_ROOT, exist_ok=True)
        try:
            shutil.move(container, dest)
        except Exception as exc:
            print(f"❌ 移动 {os.path.basename(container)} 失败：{exc}")
            print("   多半是没给「完全磁盘访问权限」，或 App 没退干净。")
            return 1
        print(f"✅ {os.path.basename(container)} → {dest}")

    subprocess.run(["open", "-a", APP_PATH], capture_output=True)
    print("\n已启动 App。接下来：")
    print("  1. 登录（token 与容器绑定，换容器必须重新登录）")
    print("  2. 进入签到页 —— 顶象 SDK 在这一步才会生成新指纹")
    print("  3. python tools/read_mac_app.py 读出新指纹")
    print(f"\n旧容器都在 {HOLD_ROOT}，要回退就把目录挪回 ~/Library/Containers/。")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="清顶象键（诊断用，已证实换不了指纹）")
    ap.add_argument("--purge", action="store_true",
                    help="删掉容器重建，等价于卸载重装（先备份，可回退）")
    ap.add_argument("--rebuild", action="store_true", help="把容器挪走而不是删除，同样能换指纹")
    args = ap.parse_args()

    containers = find_containers()
    if not containers:
        print("没找到已登录的龙湖 App 容器。")
        return 1

    if app_running():
        print("⚠️  龙湖 App 还开着。请先完全退出（⌘Q），否则改不动。")
        return 1

    if args.purge:
        return purge(containers)

    if args.rebuild:
        return rebuild(containers)

    for container, plist_path in containers:
        marks, dx = read_state(plist_path, container)
        print("=" * 64)
        print(f"容器      {os.path.basename(container)}")
        print(f"当前指纹  {dx or '(空)'}")
        for key, val in marks.items():
            print(f"身份源    {key} = {val[:20]}…")
        if not marks and not dx:
            print("没有可清理的顶象状态，可能指纹来自更外层的 IDFV，本脚本无效。")
            continue

        if not args.apply:
            print("\n[dry-run] 将删除上面两个 plist 键和所有 `_dx_app_*` 缓存，然后重启 cfprefsd。")
            print("          加 --apply 执行。登录态 SALoginData 不会被碰。")
            continue

        where = apply(container, plist_path)
        print(f"\n✅ 已清理，备份在 {where}")
        print("   下一步：打开 App → 进入签到页 → 跑 python tools/read_mac_app.py 读新指纹。")
        print("   如果读出来还是旧值，说明源头是 IDFV，那就只能删整个容器重装。")

    return 0


if __name__ == "__main__":
    sys.exit(main())
