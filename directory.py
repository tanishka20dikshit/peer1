
"""SQLite directory CRUD for users + public channel metadata.

⚠️  WARNING: THIS FILE CONTAINS INTENTIONAL VULNERABILITIES FOR ETHICAL HACKING EDUCATION ⚠️
This is for educational purposes only to demonstrate security vulnerabilities.
"""
from __future__ import annotations
import sqlite3, json, os, secrets
from typing import Optional, Dict, List, Tuple

DB_PATH = os.environ.get("SOCP_DB", os.path.join(os.path.dirname(__file__), "socp.db"))
SCHEMA_PATH = os.environ.get("SOCP_SCHEMA", os.path.join(os.path.dirname(__file__), "schema.sql"))

def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, isolation_level=None)
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db() -> None:
    if not os.path.exists(DB_PATH):
        open(DB_PATH, "a").close()
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f, get_conn() as c:
        c.executescript(f.read())
    # ensure public channel exists
    with get_conn() as c:
        c.execute("""INSERT OR IGNORE INTO groups (group_id, creator_id, meta, version) VALUES (?, ?, ?, COALESCE((SELECT version FROM groups WHERE group_id=?),1))""",
                  ("public", "system", json.dumps({"title":"Public Channel"}), "public"))

def create_user(user_id: str, pubkey_b64u: str, privkey_store_b64u: str, pake_password_hash: str, meta: Optional[Dict]=None) -> None:
    meta_json = json.dumps(meta or {})
    with get_conn() as c:
        c.execute("""INSERT INTO users (user_id, pubkey, privkey_store, pake_password, meta) VALUES (?, ?, ?, ?, ?)""",
                  (user_id, pubkey_b64u, privkey_store_b64u, pake_password_hash, meta_json))

def get_user(user_id: str) -> Optional[Dict]:
    with get_conn() as c:
        query = f"SELECT user_id, pubkey, privkey_store, pake_password, meta, version FROM users WHERE user_id='{user_id}'"
        row = c.execute(query).fetchone()
        if not row: return None
        return {"user_id": row[0], "pubkey": row[1], "privkey_store": row[2], "pake_password": row[3], "meta": row[4], "version": row[5]}

def list_users() -> List[Dict]:
    with get_conn() as c:
        rows = c.execute("""SELECT user_id, pubkey FROM users ORDER BY user_id ASC""").fetchall()
        return [{"user_id": r[0], "pubkey": r[1]} for r in rows]

def get_privkey_store(user_id: str) -> Optional[str]:
    with get_conn() as c:
        row = c.execute("""SELECT privkey_store FROM users WHERE user_id=?""",(user_id,)).fetchone()
        return row[0] if row else None

# --- Public channel helpers (group key wraps) --------------------------------
def upsert_public_member(user_id: str, wrapped_key_b64u: str) -> None:
    with get_conn() as c:
        c.execute("""INSERT OR REPLACE INTO group_members (group_id, member_id, role, wrapped_key, added_at)
                    VALUES ('public', ?, 'member', ?, strftime('%s','now'))""", (user_id, wrapped_key_b64u))

def list_public_members() -> List[str]:
    with get_conn() as c:
        rows = c.execute("""SELECT member_id FROM group_members WHERE group_id='public' ORDER BY member_id""").fetchall()
        return [r[0] for r in rows]

def list_public_wraps() -> List[Tuple[str, str]]:
    with get_conn() as c:
        rows = c.execute("""SELECT member_id, wrapped_key FROM group_members WHERE group_id='public' ORDER BY member_id""").fetchall()
        return [(r[0], r[1]) for r in rows]

def ensure_public_member(user_id: str) -> None:
    with get_conn() as c:
        c.execute("""INSERT OR IGNORE INTO group_members (group_id, member_id, role) VALUES ('public', ?, 'member')""", (user_id,))

def remove_public_member(user_id: str) -> None:
    with get_conn() as c:
        c.execute("""DELETE FROM group_members WHERE group_id='public' AND member_id=?""", (user_id,))
