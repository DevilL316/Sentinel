"""SQLite storage. JSON documents with a few indexed columns; swap for Postgres/ClickHouse at scale."""

import json
import sqlite3
import threading
import time
import uuid
from typing import Any

from . import config

_lock = threading.RLock()
_conn: sqlite3.Connection | None = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY, ts INTEGER, class_uid INTEGER, doc TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY, ts INTEGER, rule_id TEXT, severity INTEGER, status TEXT, case_id TEXT, doc TEXT
);
CREATE TABLE IF NOT EXISTS cases (
  id TEXT PRIMARY KEY, ts INTEGER, status TEXT, doc TEXT
);
CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY, ts INTEGER, status TEXT, doc TEXT
);
CREATE TABLE IF NOT EXISTS audit (
  id TEXT PRIMARY KEY, ts INTEGER, actor TEXT, action TEXT, doc TEXT
);
"""


def conn() -> sqlite3.Connection:
    global _conn
    with _lock:
        if _conn is None:
            _conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
            _conn.row_factory = sqlite3.Row
            _conn.executescript(SCHEMA)
        return _conn


def reset() -> None:
    """Close the connection (tests point SENTINEL_DB at :memory: and call this)."""
    global _conn
    with _lock:
        if _conn is not None:
            _conn.close()
        _conn = None


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def now_ms() -> int:
    return int(time.time() * 1000)


def put(table: str, doc: dict[str, Any], **cols: Any) -> None:
    keys = ["id", *cols.keys(), "doc"]
    vals = [doc["id"], *cols.values(), json.dumps(doc)]
    sql = f"INSERT OR REPLACE INTO {table} ({','.join(keys)}) VALUES ({','.join('?' * len(keys))})"
    with _lock:
        conn().execute(sql, vals)
        conn().commit()


def get(table: str, id_: str) -> dict | None:
    with _lock:
        row = conn().execute(f"SELECT doc FROM {table} WHERE id=?", (id_,)).fetchone()
    return json.loads(row["doc"]) if row else None


def list_(table: str, limit: int = 100, where: str = "", args: tuple = ()) -> list[dict]:
    sql = f"SELECT doc FROM {table} {where} ORDER BY ts DESC LIMIT ?"
    with _lock:
        rows = conn().execute(sql, (*args, limit)).fetchall()
    return [json.loads(r["doc"]) for r in rows]


def count(table: str) -> int:
    with _lock:
        return conn().execute(f"SELECT COUNT(*) c FROM {table}").fetchone()["c"]


def audit(actor: str, action: str, **detail: Any) -> None:
    doc = {"id": new_id("aud"), "ts": now_ms(), "actor": actor, "action": action, "detail": detail}
    put("audit", doc, ts=doc["ts"], actor=actor, action=action)
