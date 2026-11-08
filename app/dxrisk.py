# ===========================================================================
# 脱敏版：与具体手机强绑定的设备痕迹已替换为通用机型（Pixel 7）的自洽值，
# 替换处均有 [脱敏] 注释；协议、XXTEA 加密、签名算法与请求格式与原版一致。
# 用法：python dxrisk_token_public.py --json
# ===========================================================================
#!/usr/bin/env python3
"""Standalone DXRisk token client for com.longfor.supera (ly-sta.longhu.net/udid/m1).

Full chain (all reversed from libDXRiskComm-situation_v7_6_4_oaid_a327f13d.so):
  seed   = protobuf  {1: device-msg, 2: 1002, 3: map{K451:ms, K452:ms, ...}}
  sign   = md5hex(appKey + seed + appKey)
  body   = XXTEA( zip{entry "data" -> seed}, key = b"ea8a55a43621eacd" )
  resp   = XXTEA( zip{entry "data" -> {1:1002, 2:{1:token}, 3:code}} )

Usage:  python app/dxrisk.py --longhu-token <32位龙湖token> [--json] [--set K=V]
        脱敏版不读任何模板文件，设备信息全部内联在 MAP_ITEMS / DEVICE_MSG。
"""
import argparse
import hashlib
import io
import json
import os
import re
import struct
import sys
import time
import urllib.request
import zipfile

APPKEY = '6341e15e0d8bdb6b3d20a51fb2b7c171'
APP = 'com.longfor.supera'
VER = 'situation_v7_6_4_oaid_a327f13d'
XKEY = b'ea8a55a43621eacd'          # = first 16 chars of the 40-hex keymgr key string
ENDPOINT = 'https://ly-sta.longhu.net/udid/m1'

M32 = 0xFFFFFFFF
DELTA = 0x9E3779B9


# ---------------------------------------------------------------- protobuf wire
def _varint(n):
    out = bytearray()
    if n < 0:
        n += 1 << 64
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _svarint(b, i):
    r = 0
    sh = 0
    while True:
        x = b[i]
        i += 1
        r |= (x & 0x7F) << sh
        if not (x & 0x80):
            return r, i
        sh += 7


def _pb_fields(b):
    i = 0
    out = []
    while i < len(b):
        t, i = _svarint(b, i)
        f, wt = t >> 3, t & 7
        if wt == 0:
            v, i = _svarint(b, i)
            out.append((f, 0, v))
        elif wt == 2:
            ln, i = _svarint(b, i)
            out.append((f, 2, b[i:i + ln]))
            i += ln
        elif wt == 5:
            out.append((f, 5, b[i:i + 4]))
            i += 4
        elif wt == 1:
            out.append((f, 1, b[i:i + 8]))
            i += 8
        else:
            raise ValueError('bad wiretype %d' % wt)
    return out


def _pb_str(f, v):
    v = v.encode() if isinstance(v, str) else v
    return _varint((f << 3) | 2) + _varint(len(v)) + v


def _pb_vi(f, v):
    return _varint((f << 3) | 0) + _varint(v)


# ---------------------------------------------------------------------- XXTEA
def _kw(k):
    return list(struct.unpack('<4I', k[:16].ljust(16, b'\0')))


def _enc_words(v, k):
    n = len(v) - 1
    if n < 1:
        return v
    rounds = 6 + 52 // (n + 1)
    s = 0
    z = v[n]
    while rounds:
        rounds -= 1
        s = (s + DELTA) & M32
        e = (s >> 2) & 3
        for p in range(n):
            y = v[p + 1]
            mx = ((((z >> 5) ^ ((y << 2) & M32)) + ((y >> 3) ^ ((z << 4) & M32))) & M32) ^ \
                 (((s ^ y) + (k[(p & 3) ^ e] ^ z)) & M32)
            v[p] = (v[p] + mx) & M32
            z = v[p]
        y = v[0]
        mx = ((((z >> 5) ^ ((y << 2) & M32)) + ((y >> 3) ^ ((z << 4) & M32))) & M32) ^ \
             (((s ^ y) + (k[(n & 3) ^ e] ^ z)) & M32)
        v[n] = (v[n] + mx) & M32
        z = v[n]
    return v


def _dec_words(v, k):
    n = len(v) - 1
    if n < 1:
        return v
    rounds = 6 + 52 // (n + 1)
    s = (rounds * DELTA) & M32
    y = v[0]
    while s:
        e = (s >> 2) & 3
        for p in range(n, 0, -1):
            z = v[p - 1]
            mx = ((((z >> 5) ^ ((y << 2) & M32)) + ((y >> 3) ^ ((z << 4) & M32))) & M32) ^ \
                 (((s ^ y) + (k[(p & 3) ^ e] ^ z)) & M32)
            v[p] = (v[p] - mx) & M32
            y = v[p]
        z = v[n]
        mx = ((((z >> 5) ^ ((y << 2) & M32)) + ((y >> 3) ^ ((z << 4) & M32))) & M32) ^ \
             (((s ^ y) + (k[e] ^ z)) & M32)
        v[0] = (v[0] - mx) & M32
        y = v[0]
        s = (s - DELTA) & M32
    return v


def xxtea_enc(data, key=XKEY):
    """SDK variant: pad to 4 bytes, append plaintext length as last word."""
    n = len(data)
    pad = (-n) % 4
    v = list(struct.unpack('<%dI' % ((n + pad) // 4), data + b'\0' * pad))
    v.append(n)
    v = _enc_words(v, _kw(key))
    return struct.pack('<%dI' % len(v), *v)


def xxtea_dec(ct, key=XKEY):
    v = list(struct.unpack('<%dI' % (len(ct) // 4), ct))
    v = _dec_words(v, _kw(key))
    return struct.pack('<%dI' % len(v), *v), v[-1]


# ------------------------------------------------------------------- seed I/O
# ---------------------------------------------------------------------------
# 脱敏设备模板
# ---------------------------------------------------------------------------
# 这张表是设备痕迹的「键 -> 值」。原始模板取自真机，本脱敏版的处理规则：
#   1) 与具体手机强绑定的字段（型号 / 品牌 / ROM 版本 / UA / build fingerprint /
#      UUID / 序列号类 HEX）替换为同一套通用机型（Pixel 7）的自洽值，行尾标 [脱敏]；
#   2) 纯数字字段与结构性字段（协议常量、尺寸、开关位等）原样保留，它们不指向
#      任何具体的人或机器；
#   3) K451 / K452 两个时间戳不写死，运行时按当前毫秒生成。
# 注意：品牌、机型、fingerprint、UA 必须彼此自洽，只改其中一项会被服务端判 -10005（实测）。
MAP_ITEMS = [
    ("K0000", "32768"),
    ("K1", "[]"),
    ("K100", "Dalvik/2.1.0 (Linux; U; Android 14; panther Build/UQ1A.240205.002)"),  # [脱敏] 原为真机 UA，已替换
    ("K1046", "Android"),
    ("K1060", "16"),
    ("K1061", "2026-06-01"),
    ("K1062", "google/panther/panther:14/UQ1A.240205.002/11224170:user/release-keys"),  # [脱敏] 原为真机 build fingerprint，已替换为通用机型 Pixel 7
    ("K1063", "pangu-build-component-system-647115-ltbdv-ll7d6-v7v6m"),
    ("K1064", "1779973142"),
    ("K1065", "BP2A.250605.031.A3"),
    ("K1066", "BP2A.250605.031.A3"),
    ("K1067", "release-keys"),
    ("K1068", "builder"),
    ("K1069", "missi-user 16 BP2A.250605.031.A3 16OS3.1.260528.205044822.QCPECN.S release-keys"),
    ("K1072", "1779973142"),
    ("K1073", "user"),
    ("K1074", "36"),
    ("K1077", "Thu May 28 20:59:02 CST 2026"),
    ("K1078", "nosdcard"),
    ("K1083", "REL"),
    ("K1084", "Android 14"),  # [脱敏] 原为真机 ROM 版本，已替换
    ("K1085", "0"),
    ("K1086", "36"),
    ("K11", "16"),
    ("K111", "1440x3200"),
    ("K1110", "panther"),  # [脱敏] 原含真机型号/品牌字样，已替换为通用机型
    ("K1111", "Pixel 7"),  # [脱敏] 原含真机型号/品牌字样，已替换为通用机型
    ("K1112", "google"),  # [脱敏] 原含真机型号/品牌字样，已替换为通用机型
    ("K1113", "panther"),  # [脱敏] 原含真机型号/品牌字样，已替换为通用机型
    ("K1114", "arm64-v8a"),
    ("K1116", "arm64-v8a"),
    ("K1117", "google"),  # [脱敏] 原含真机型号/品牌字样，已替换为通用机型
    ("K1118", "sun"),
    ("K112", "1440 x 3200"),
    ("K1130", "qcom"),
    ("K1135", "unknown"),
    ("K1136", "sun"),
    ("K1138", "196610"),
    ("K114", "3"),
    ("K1142", "android-google"),  # [脱敏] 原含真机型号/品牌字样，已替换为通用机型
    ("K1143", "1"),
    ("K1145", "I2C"),
    ("K115", "true"),
    ("K1193", "LOADED,LOADED"),
    ("K1197", "1,1"),
    ("K1199", "NR_SA,NR_SA"),
    ("K12", "2026-06-01"),
    ("K1201", "false,false"),
    ("K1203", "46011,46000"),
    ("K1220", "NV,RUIM"),
    ("K1272", "Asia/Shanghai"),
    ("K13", "google/panther/panther:14/UQ1A.240205.002/11224170:user/release-keys"),  # [脱敏] 原为真机 build fingerprint，已替换为通用机型 Pixel 7
    ("K1310", "running"),
    ("K1314", "0"),
    ("K1315", "unknown"),
    ("K138", "MPSS.DE.7.0-CN-3f86abc7ae,MPSS.DE.7.0-CN-3f86abc7ae"),
    ("K14", "qcom"),
    ("K15", "pangu-build-component-system-647115-ltbdv-ll7d6-v7v6m"),
    ("K16", "1779973142000"),
    ("K17", "panther"),  # [脱敏] 原含真机型号/品牌字样，已替换为通用机型
    ("K18", "Pixel 7"),  # [脱敏] 原含真机型号/品牌字样，已替换为通用机型
    ("K19", "google"),  # [脱敏] 原含真机型号/品牌字样，已替换为通用机型
    ("K2", "google"),  # [脱敏] 原为真机品牌，已替换
    ("K20", "panther"),  # [脱敏] 原含真机型号/品牌字样，已替换为通用机型
    ("K200", "1794150005956"),
    ("K201", "1794043797795"),
    ("K203", "106208161"),
    ("K204", "8"),
    ("K21", "arm64-v8a"),
    ("K21-1", "arm64-v8a"),
    ("K22", "BP2A.250605.031.A3"),
    ("K23", "BP2A.250605.031.A3"),
    ("K24", "google"),  # [脱敏] 原含真机型号/品牌字样，已替换为通用机型
    ("K2400", "u10318"),
    ("K2402", "false"),
    ("K25", "sun"),
    ("K251", "5"),
    ("K252", "1"),
    ("K26", "unknown"),
    ("K27", "MPSS.DE.7.0-CN-3f86abc7ae,MPSS.DE.7.0-CN-3f86abc7ae"),
    ("K28", "release-keys"),
    ("K281", "Snapdragon\n"),
    ("K29", "builder"),
    ("K290", "f1da0e45-0f65-4503-a904-febdc6eb07c7\n"),
    ("K291", "99eec5bf-dd65-48b5-a658-70b80c9e08de\n"),
    ("K292", "6.6.77-android15-8-gca30f3b4bef6-abogki440974771-4k"),
    ("K293", "#1 SMP PREEMPT Mon Sep  1 06:06:55 UTC 2025"),
    ("K3", "龙湖"),
    ("K30", "8"),
    ("K300", "161"),
    ("K301", "qcom"),
    ("K302", "missi-user"),
    ("K303", "Pixel 7"),  # [脱敏] 原含真机型号/品牌字样，已替换为通用机型
    ("K304", "google"),  # [脱敏] 原含真机型号/品牌字样，已替换为通用机型
    ("K305", "sun"),
    ("K306", "sun"),
    ("K307", "MPSS.DE.7.0-CN-3f86abc7ae,MPSS.DE.7.0-CN-3f86abc7ae"),
    ("K308", "4:memory:/mimd/uid_10318\n3:cpuset:/top-app\n2:cpu:/top-app\n1:blkio:/\n0::/apps/uid_10318/pid_640\n"),
    ("K309", "-1"),
    ("K31", "fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 sm3 sm4 asimddp sha512 asimdfhm dit uscat ilrcpc flagm ssbs sb paca pacg dcpodp flagm2 frint i8mm bf16 rng bti ecv afp rpres\n"),
    ("K310", "true"),
    ("K311", "true"),
    ("K312", "true"),
    ("K313", "true"),
    ("K320", "true"),
    ("K327", "true"),
    ("K327-s", "baidu_1"),
    ("K329", "false"),
    ("K331", "google"),  # [脱敏] 原为真机品牌，已替换
    ("K332", "[{capabilities=33, packageNames=null, flags=82, description=🌈🌈🌈️\n--------------\n我的作用：旨在帮助用户跳过那些被工信部提名的，影响用户体验的开屏广告和弹窗。\n--------------\n用户须知：李跳跳是一个不联网的单机应用凑字数，不会也没办法泄露你的任何隐私。\n--------------\n\n\n🐟🐠🐟, Id=hello.litiaotiao.app/.LttService, eventTypes=4194305}]"),
    ("K333", "[{\"deviceSources\":769,\"isExternal\":false,\"keyboardType\":2,\"isEnabled\":true,\"isVirtual\":true,\"deviceName\":\"Virtual\"},{\"deviceSources\":257,\"isExternal\":false,\"keyboardType\":1,\"isEnabled\":true,\"isVirtual\":false,\"deviceName\":\"gpio-keys\"},{\"deviceSources\":1281,\"isExternal\":false,\"keyboardType\":1,\"isEnabled\":true,\"isVirtual\":false,\"deviceName\":\"uinput-google\"},{\"deviceSources\":257,\"isExternal\":false,\"keyboardType\":1,\"isEnabled\":true,\"isVirtual\":false,\"deviceName\":\"pmic_pwrkey\"},{\"deviceSources\":257,\"isExternal\":false,\"keyboardType\":1,\"isEnabled\":true,\"isVirtual\":false,\"deviceName\":\"pmic_resin\"},{\"deviceSources\":257,\"isExternal\":false,\"keyboardType\":1,\"isEnabled\":true,\"isVirtual\":false,\"deviceName\":\"pmic_pwrkey_bark\"},{\"deviceSources\":257,\"isExternal\":false,\"keyboardType\":1,\"isEnabled\":true,\"isVirtual\":false,\"deviceName\":\"pmic_pwrkey_resin_bark\"},{\"deviceSources\":4355,\"isExternal\":false,\"keyboardType\":1,\"isEnabled\":true,\"isVirtual\":false,\"deviceName\":\"google_Touch_Input_0\"},{\"deviceSources\":-2147483391,\"isExternal\":false,\"keyboardType\":1,\"isEnabled\":true,\"isVirtual\":false,\"deviceName\":\"sun-mtp-snd-card Headset Jack\"}]"),  # [脱敏] 原含真机型号/品牌字样，已替换为通用机型
    ("K34", "3532800\n"),
    ("K35", "384000\n"),
    ("K39", "1996800\n"),
    ("K4", "1.30.2"),
    ("K40", "54200\n"),
    ("K41", "0-7\n"),
    ("K451", "__TS__"),  # [脱敏] 原为采集时刻，改为运行时生成
    ("K452", "__TS__"),  # [脱敏] 原为采集时刻，改为运行时生成
    ("K46", "Wi-Fi"),
    ("K47", "Wi-Fi"),
    ("K500", "cn"),
    ("K501", "46011"),
    ("K502", "中国电信"),
    ("K503", "cn"),
    ("K504", "46002"),
    ("K505", "中国电信"),
    ("K58", "a6119290-0000-4000-8000-00160c5f6505"),  # [脱敏] 原为真机 UUID，已替换为随机值
    ("K6", "google"),  # [脱敏] 原为真机品牌，已替换
    ("K60", "141000367"),
    ("K61", "3.2"),
    ("K65", "11662073856-240924995584"),
    ("K66", "11662073856,20119552"),
    ("K666", "91875735"),
    ("K667", "龙湖"),
    ("K67", "67167473664,240924995584"),
    ("K69", "[{\"dev\": \"/dev/block/dm-9\", \"free\": \"0K\", \"fs\": \"/\", \"size\": \"853M\", \"type\": \"erofs\", \"used\": \"853M\"}, {\"dev\": \"/dev/block/dm-10\", \"free\": \"0K\", \"fs\": \"/system_ext\", \"size\": \"664M\", \"type\": \"erofs\", \"used\": \"664M\"}, {\"dev\": \"/dev/block/dm-11\", \"free\": \"0K\", \"fs\": \"/product\", \"size\": \"3G\", \"type\": \"erofs\", \"used\": \"3G\"}, {\"dev\": \"/dev/block/dm-13\", \"free\": \"0K\", \"fs\": \"/vendor\", \"size\": \"743M\", \"type\": \"erofs\", \"used\": \"743M\"}, {\"dev\": \"/dev/block/dm-55\", \"free\": \"62G\", \"fs\": \"/data\", \"size\": \"224G\", \"type\": \"f2fs\", \"used\": \"161G\"}]"),
    ("K7", "470ac8003684594a0702f762bdd25d29"),  # [脱敏] 原为真机标识（HEX），已替换为随机值
    ("K8", "situation_v7_6_4_oaid_a327f13d"),
    ("K800", "15"),
    ("K801", "2"),
    ("K802", "11"),
    ("K803", "15"),
    ("K804", "20"),
    ("K805", "15"),
    ("K850", "321028183"),
    ("K851", "1793774040782"),
    ("K852", "1793774040782"),
    ("K853", "821575236"),
    ("K854", "0"),
    ("K855", "google"),  # [脱敏] 原为真机品牌，已替换
    ("K90", "3"),
    ("K902", "arm64-v8a"),
    ("K903", "user"),
    ("K904", "MPSS.DE.7.0-CN-3f86abc7ae,MPSS.DE.7.0-CN-3f86abc7ae"),
    ("K906", "36"),
    ("K907", "REL"),
    ("K908", "Android 14"),  # [脱敏] 原为真机 ROM 版本，已替换
    ("K91", "2"),
    ("K92", "true"),
    ("K93", "27"),
    ("K94", "100"),
    ("K95", "0"),
    ("K96", "3685"),
    ("K97", "358"),
    ("K98", "Li-poly"),
    ("user_K443", "5cd6e7a161e146bd"),  # [脱敏] 原为真机标识（HEX），已替换为随机值
    ("user_K443-reas", "oaid_debug: init=ok; detail=initOAIDSDKCert: ok; certPath=com.longfor.supera.cert.pem"),
    ("user_K444", "3f970c12be062f69"),  # [脱敏] 原为真机标识（HEX），已替换为随机值
    ("user_K445", "037b0d6a-0000-4000-8000-00817a57cad2"),  # [脱敏] 原为真机 UUID，已替换为随机值
    ("user_K446", "true"),
]

# ---------------------------------------------------------------------------
# 成套机型预设
# ---------------------------------------------------------------------------
# 脱敏模板原本把所有账号都写成同一套 Pixel 7 画像。为降低「一批账号看起来
# 像同一台设备」的聚类风险，这里提供几套公开机型的成套预设供添加账号时选择。
#
# 规则：品牌 / 机型 / 代号 / build fingerprint / UA / build id 必须一起换，
#       只改其中一项会被 /udid/m1 判 -10005（实测）。其余硬件与结构性字段
#       沿用脱敏模板，不引入任何真实设备痕迹。下列每套都已实测返回 code=0。
_BRAND_KEYS = ("K2", "K6", "K19", "K24", "K331", "K855", "K1112", "K1117", "K304")
_MODEL_KEYS = ("K18", "K1111", "K303")
_DEVICE_KEYS = ("K17", "K20", "K1110", "K1113")
_FP_KEYS = ("K13", "K1062")


def _profile_fields(brand, model, device, build, incremental, brand_tag):
    """生成一套自洽的机型字段覆盖表（只覆盖机型识别字段）。"""
    fields = {key: brand for key in _BRAND_KEYS}
    fields.update({key: model for key in _MODEL_KEYS})
    fields.update({key: device for key in _DEVICE_KEYS})
    fingerprint = "%s/%s/%s:14/%s/%s:user/release-keys" % (
        brand, device, device, build, incremental)
    fields.update({key: fingerprint for key in _FP_KEYS})
    fields["K100"] = "Dalvik/2.1.0 (Linux; U; Android 14; %s Build/%s)" % (device, build)
    fields["K1142"] = "android-" + brand_tag
    return fields


DEVICE_PROFILES = {
    "pixel7": {
        "name": "Google Pixel 7", "brand": "google", "model": "Pixel 7",
        # 空覆盖 = 使用 MAP_ITEMS 里原始脱敏值，保证旧行为完全一致
        "fields": {},
    },
    "xiaomi14": {
        "name": "Xiaomi 14", "brand": "Xiaomi", "model": "Xiaomi 14",
        "fields": _profile_fields("Xiaomi", "Xiaomi 14", "houji",
                                  "UKQ1.230804.001", "V816.0.1.0.UNCCNXM", "xiaomi"),
    },
    "oneplus12": {
        "name": "OnePlus 12", "brand": "OnePlus", "model": "OnePlus 12",
        "fields": _profile_fields("OnePlus", "OnePlus 12", "waffle",
                                  "UKQ1.230716.001", "2412291200", "oneplus"),
    },
    "vivo_x100": {
        "name": "vivo X100", "brand": "vivo", "model": "vivo X100",
        "fields": _profile_fields("vivo", "vivo X100", "V2309A",
                                  "UP1A.231005.007", "compiler07022220", "vivo"),
    },
    "samsung_s24": {
        "name": "Samsung Galaxy S24", "brand": "samsung", "model": "SM-S9210",
        "fields": _profile_fields("samsung", "SM-S9210", "e1q",
                                  "UP1A.231005.007", "S9210XXU1AWM9", "samsung"),
    },
}

DEFAULT_PROFILE = "pixel7"
PROFILE_KEYS = tuple(DEVICE_PROFILES)


def profiles():
    """给前端用的机型列表（只给预设，不开放字段自由填写）。"""
    return [
        {"key": key, "name": item["name"], "brand": item["brand"], "model": item["model"]}
        for key, item in DEVICE_PROFILES.items()
    ]


# 设备消息字段：1=SDK 版本串 2=顶象版本 3=App 版本号 4=appKey 5=保留 6=常量
# 7=上一枚令牌 8=常量 9=包名 10=常量
DEVICE_MSG = {
    1: b"situation_v7_6_4_oaid_a327f13d",
    2: b"1.30.2",
    3: 321028183,
    4: b"6341e15e0d8bdb6b3d20a51fb2b7c171",
    5: 0,
    6: b"36",
    7: '6aec8780Zq4dNGOFcPVdCh4moOzSwyE9LZVGC9m3',  # 协议要求携带上一枚令牌；置空或乱填会被判 -10004（实测），故保留原值
    8: 1,
    9: b"com.longfor.supera",
    10: 3,
}


class _Stream(object):
    """由龙湖 token 派生的确定性字节流：同一账号得到同一台设备，不同账号得到不同设备。"""

    def __init__(self, seed_text):
        self._seed = hashlib.sha256(('dx-device:' + seed_text).encode('utf-8')).digest()
        self._buf = b''
        self._n = 0

    def take(self, n):
        while len(self._buf) < n:
            self._buf += hashlib.sha256(self._seed + bytes([self._n])).digest()
            self._n += 1
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def hexstr(self, n):
        return self.take((n + 1) // 2).hex()[:n]

    def uuid(self):
        b = bytearray(self.take(16))
        b[6] = (b[6] & 0x0F) | 0x40
        b[8] = (b[8] & 0x3F) | 0x80
        h = b.hex()
        return '%s-%s-%s-%s-%s' % (h[:8], h[8:12], h[12:16], h[16:20], h[20:])


def _derive_value(value, stream):
    """只重写设备标识类字段（UUID、HEX 串）；纯数字与结构性字段原样保留。"""
    if stream is None or not value:
        return value
    if re.fullmatch(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', value):
        return stream.uuid()
    if value.isdigit():
        return value
    if re.fullmatch(r'[0-9a-fA-F]{8,}', value):
        return stream.hexstr(len(value))
    return value


def build_seed(template_path=None, ts1=None, ts2=None, overrides=None, longhu_token=None):
    """按脱敏模板拼出 protobuf seed；longhu_token 用于派生该账号专属的设备标识。

    注意：龙湖 token 不会发送给指纹服务端，只作为本地派生盐，让每个账号
    得到一份互不相同的设备身份。
    """
    now = int(time.time() * 1000)
    ts1 = ts1 or now
    ts2 = ts2 or now
    overrides = overrides or {}
    stream = _Stream(longhu_token) if longhu_token else None

    buf = bytearray()
    for key, value in MAP_ITEMS:
        if key in ('K451', 'K452'):
            text = str(ts1 if key == 'K451' else ts2)
        else:
            text = _derive_value(value, stream)
        if key in overrides:
            text = overrides[key]
        buf += _pb_str(1, _pb_str(1, key.encode()) + _pb_str(2, text.encode()))

    dev = bytearray()
    for field_no, value in DEVICE_MSG.items():
        if isinstance(value, (bytes, bytearray)):
            dev += _pb_str(field_no, bytes(value))
        elif isinstance(value, str):
            dev += _pb_str(field_no, value.encode())
        else:
            dev += _pb_vi(field_no, int(value))

    seed = bytearray()
    seed += _pb_str(1, bytes(dev))
    seed += _pb_vi(2, 1002)
    seed += _pb_str(3, bytes(buf))
    return bytes(seed), ts1, ts2


def _zip(data, name='data'):
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr(name, data)
    return bio.getvalue()


def _unzip(payload):
    with zipfile.ZipFile(io.BytesIO(payload)) as z:
        return z.read(z.namelist()[0])


# ------------------------------------------------------------------- protocol
def fetch_token(seed, timeout=20):
    sign = hashlib.md5(APPKEY.encode() + seed + APPKEY.encode()).hexdigest()
    url = '%s?sign=%s&appKey=%s&app=%s&version=%s' % (ENDPOINT, sign, APPKEY, APP, VER)
    body = xxtea_enc(_zip(seed))
    req = urllib.request.Request(url, data=body, method='POST', headers={
        'accept': '*/*',
        'connection': 'keep-Alive',
        'User-Agent': 'Risk-' + VER,
        'Content-type': 'application/octet-stream',
        'Host': 'ly-sta.longhu.net',
        'Accept-Encoding': 'gzip',
    })
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=timeout) as r:
        resp = r.read()
    pt, ln = xxtea_dec(resp)
    fields = _pb_fields(_unzip(pt[:ln]))
    code = next((v for f, w, v in fields if f == 3), None)
    if code is not None and code >= 1 << 63:
        code -= 1 << 64
    payload = next((v for f, w, v in fields if f == 2), b'')
    token = None
    if payload:
        token = next((v.decode() for f, w, v in _pb_fields(payload) if f == 1), None)
    return {'token': token, 'code': code, 'ms': int((time.time() - t0) * 1000),
            'resp_len': len(resp), 'sign': sign}


def issue(longhu_token, ts=None, overrides=None, timeout=20, profile=None):
    """传入设备派生盐，返回该账号的指纹 token 结果字典。

    profile 为 None 时沿用默认 Pixel 7 模板，行为与旧版完全一致；显式
    overrides 优先级高于模板字段，方便手动调试单个 K 字段。
    """
    key = (profile or DEFAULT_PROFILE).strip().lower()
    fields = dict(DEVICE_PROFILES.get(key, DEVICE_PROFILES[DEFAULT_PROFILE])["fields"])
    fields.update(overrides or {})
    seed, _t1, _t2 = build_seed(None, ts1=ts, overrides=fields,
                                 longhu_token=longhu_token)
    return fetch_token(seed, timeout=timeout)


def main(argv=None):
    ap = argparse.ArgumentParser(description='用龙湖 token 生成顶象指纹 token')
    ap.add_argument('--longhu-token', required=True, help='龙湖登录 token（32 位）')
    ap.add_argument('--ts', type=int, default=None, help='K451 epoch ms (default: now)')
    ap.add_argument('--set', action='append', default=[], metavar='K=V', help='override map field')
    ap.add_argument('--profile', choices=PROFILE_KEYS, default=DEFAULT_PROFILE,
                    help='机型预设（可选值：%s）' % ', '.join(PROFILE_KEYS))
    ap.add_argument('--json', action='store_true')
    a = ap.parse_args(argv)

    overrides = {}
    for item in a.set:
        k, _, v = item.partition('=')
        overrides[k] = v
    res = issue(a.longhu_token.strip(), ts=a.ts, overrides=overrides, profile=a.profile)
    if a.json:
        print(json.dumps(res, ensure_ascii=False))
    else:
        print('token  :', res['token'])
        print('code   :', res['code'])
        print('latency:', res['ms'], 'ms')
    return 0 if res['token'] else 1


if __name__ == '__main__':
    sys.exit(main())
