"""SQLite 存储层。单文件数据库，挂在容器卷上。"""

import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone

DB_PATH = os.path.join(os.environ.get("DATA_DIR", "./data"), "longhu.db")
_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    NOT NULL,
    token         TEXT    NOT NULL,
    user_agent    TEXT,
    api_key       TEXT,
    dx_token      TEXT,
    bu_code       TEXT DEFAULT 'C20400',
    channel       TEXT DEFAULT 'C2',
    growth_value  INTEGER DEFAULT 0,
    level_name    TEXT DEFAULT '',
    balance       REAL DEFAULT 0,
    nickname      TEXT DEFAULT '',
    expire_at     TEXT,
    last_run_at   TEXT,
    last_status   TEXT DEFAULT '',
    last_message  TEXT DEFAULT '',
    enabled       INTEGER DEFAULT 1,
    mini_time     TEXT,
    app_time      TEXT,
    created_at    TEXT,
    updated_at    TEXT
);

-- 分时签到：每个账号的每个入口（小程序 / APP）各占一行，独立排期与重试。
-- 之前所有账号两个入口在同一轮里连着跑（相隔 1 秒），容易被判成机器行为。
CREATE TABLE IF NOT EXISTS slots (
    account_id   INTEGER NOT NULL,
    entry        TEXT    NOT NULL,
    last_date    TEXT DEFAULT '',
    plan_date    TEXT DEFAULT '',
    plan_at      TEXT DEFAULT '',
    retry_at     TEXT DEFAULT '',
    retry_count  INTEGER DEFAULT 0,
    updated_at   TEXT,
    PRIMARY KEY (account_id, entry)
);

CREATE TABLE IF NOT EXISTS logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id  INTEGER,
    account_name TEXT,
    ts          TEXT,
    action      TEXT,
    status      TEXT,
    message     TEXT
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE INDEX IF NOT EXISTS idx_logs_acc ON logs(account_id, id DESC);
"""

DEFAULT_SETTINGS = {
    # 小程序入口
    "checkin_time": "08:00",
    "checkin_jitter": "60",
    # APP 专享入口：默认比小程序晚一个半小时，避免两个入口同一时刻连着打
    "app_checkin_time": "09:30",
    "app_checkin_jitter": "60",
    "last_run_date": "",
    "retry_at": "",
    "retry_count": "0",
    "webhook_url": "",
    "auto_refresh": "1",
    # APP 专享入口怎么处理：auto（默认）/ manual（只查状态、未签提醒）/ off。
    # 前提是账号里配了顶象设备指纹（dx_token，新版由服务端签发），否则自动跳过不硬打。
    "app_checkin_mode": "auto",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


@contextmanager
def connect():
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    with _lock:
        conn = sqlite3.connect(DB_PATH, timeout=15)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()


def init():
    with connect() as conn:
        conn.executescript(SCHEMA)
        _migrate(conn)
        for key, value in DEFAULT_SETTINGS.items():
            conn.execute(
                "INSERT OR IGNORE INTO settings(key, value) VALUES (?, ?)", (key, value)
            )


# 建表之后新增的列：老库用 ALTER TABLE 补，新库由 SCHEMA 直接带上
MIGRATIONS = {
    # 顶象设备指纹。新版由 dxrisk 服务端签发、旧版来自 App；udid/c1 的 40 位 token 会被判风险
    "accounts": {
        "dx_token": "ALTER TABLE accounts ADD COLUMN dx_token TEXT",
        # 单账号自定义的两个入口时间，留空表示跟随全局设置
        "mini_time": "ALTER TABLE accounts ADD COLUMN mini_time TEXT",
        "app_time": "ALTER TABLE accounts ADD COLUMN app_time TEXT",
    },
}


def _migrate(conn):
    for table, columns in MIGRATIONS.items():
        have = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        for name, ddl in columns.items():
            if name not in have:
                conn.execute(ddl)


# --------------------------------------------------------------------------
# accounts
# --------------------------------------------------------------------------

def list_accounts(only_enabled: bool = False) -> list[dict]:
    sql = "SELECT * FROM accounts"
    if only_enabled:
        sql += " WHERE enabled = 1"
    sql += " ORDER BY id"
    with connect() as conn:
        return [dict(row) for row in conn.execute(sql)]


def get_account(account_id: int) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
        return dict(row) if row else None


def create_account(data: dict) -> int:
    ts = now_iso()
    with connect() as conn:
        cur = conn.execute(
            """INSERT INTO accounts
               (name, token, user_agent, api_key, dx_token, bu_code, channel,
                growth_value, level_name, balance, nickname,
                mini_time, app_time, expire_at, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                data["name"], data["token"], data.get("user_agent"), data.get("api_key"),
                data.get("dx_token"),
                data.get("bu_code", "C20400"), data.get("channel", "C2"),
                data.get("growth_value", 0), data.get("level_name", ""),
                data.get("balance", 0), data.get("nickname", ""),
                data.get("mini_time"), data.get("app_time"),
                data.get("expire_at"), ts, ts,
            ),
        )
        return cur.lastrowid


def update_account(account_id: int, **fields):
    if not fields:
        return
    fields["updated_at"] = now_iso()
    sets = ", ".join(f"{key} = ?" for key in fields)
    with connect() as conn:
        conn.execute(
            f"UPDATE accounts SET {sets} WHERE id = ?",
            (*fields.values(), account_id),
        )


def delete_account(account_id: int):
    with connect() as conn:
        conn.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
        conn.execute("DELETE FROM logs WHERE account_id = ?", (account_id,))
        conn.execute("DELETE FROM slots WHERE account_id = ?", (account_id,))


# --------------------------------------------------------------------------
# slots：分时签到的排期状态（每个账号 × 每个入口一行）
# --------------------------------------------------------------------------

SLOT_ENTRIES = ("mini", "app")


def list_slots() -> dict[tuple[int, str], dict]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM slots").fetchall()
    return {(row["account_id"], row["entry"]): dict(row) for row in rows}


def get_slot(account_id: int, entry: str) -> dict:
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM slots WHERE account_id = ? AND entry = ?",
            (account_id, entry),
        ).fetchone()
    if row:
        return dict(row)
    return {"account_id": account_id, "entry": entry, "last_date": "",
            "plan_date": "", "plan_at": "", "retry_at": "", "retry_count": 0}


def save_slot(account_id: int, entry: str, **fields):
    """按需更新排期字段；行不存在就插一条再更新。"""
    current = get_slot(account_id, entry)
    fields["updated_at"] = now_iso()
    with connect() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO slots(account_id, entry, updated_at) VALUES (?,?,?)",
            (account_id, entry, fields["updated_at"]),
        )
        sets = ", ".join(f"{key} = ?" for key in fields)
        conn.execute(
            f"UPDATE slots SET {sets} WHERE account_id = ? AND entry = ?",
            (*fields.values(), account_id, entry),
        )
    current.update(fields)


def clear_slot_plan(account_id: int, entry: str):
    """清掉今天的排期，让调度器按新设置重新挑时间。"""
    save_slot(account_id, entry, plan_date="", plan_at="", retry_at="", retry_count=0)


def dx_usage() -> dict[str, list[dict]]:
    """按设备指纹聚合账号，用于检查是否有多账号共用同一指纹。

    实测同一指纹被多个账号使用会触发风控（2026-11-03），所以这属于
    配置错误，需要在保存和运行时都拦住。
    """
    with connect() as conn:
        rows = conn.execute(
            "SELECT id, name, enabled, dx_token FROM accounts "
            "WHERE dx_token IS NOT NULL AND TRIM(dx_token) <> '' ORDER BY id"
        ).fetchall()
    usage: dict[str, list[dict]] = {}
    for row in rows:
        usage.setdefault(row["dx_token"].strip(), []).append(dict(row))
    return usage


def accounts_with_dx(dx_token: str, exclude_id: int | None = None) -> list[dict]:
    """返回使用了指定指纹的其他账号（按 id 升序）。"""
    token = (dx_token or "").strip()
    if not token:
        return []
    with connect() as conn:
        rows = conn.execute(
            "SELECT id, name, enabled FROM accounts "
            "WHERE dx_token IS NOT NULL AND TRIM(dx_token) = ? ORDER BY id",
            (token,),
        ).fetchall()
    return [dict(row) for row in rows if row["id"] != exclude_id]


# --------------------------------------------------------------------------
# logs
# --------------------------------------------------------------------------

def add_log(account_id: int | None, account_name: str, action: str,
            status: str, message: str):
    with connect() as conn:
        conn.execute(
            "INSERT INTO logs(account_id, account_name, ts, action, status, message) "
            "VALUES (?,?,?,?,?,?)",
            (account_id, account_name, now_iso(), action, status, message),
        )


def list_logs(account_id: int | None = None, limit: int = 50) -> list[dict]:
    with connect() as conn:
        if account_id:
            rows = conn.execute(
                "SELECT * FROM logs WHERE account_id = ? ORDER BY id DESC LIMIT ?",
                (account_id, limit),
            )
        else:
            rows = conn.execute(
                "SELECT * FROM logs ORDER BY id DESC LIMIT ?", (limit,)
            )
        return [dict(row) for row in rows]


# --------------------------------------------------------------------------
# settings
# --------------------------------------------------------------------------

def get_settings() -> dict:
    with connect() as conn:
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
    data = {row["key"]: row["value"] for row in rows}
    for key, value in DEFAULT_SETTINGS.items():
        data.setdefault(key, value)
    return data


def save_settings(values: dict):
    with connect() as conn:
        for key, value in values.items():
            conn.execute(
                "INSERT INTO settings(key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, str(value)),
            )
