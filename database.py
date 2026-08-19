"""
database.py
-----------
Tiny synchronous SQLite persistence layer (no ORM needed for an MVP).
Stores two tables:

  1. alerts       -> every hit recorded by the tripwire/telemetry logger
  2. canaries     -> every canary token embedded into a generated decoy,
                     so we can map a triggered token back to which decoy,
                     template and timestamp it was born from.

SQLite is used because it's zero-config and perfect for a hackathon demo;
swapping to Postgres later only requires changing `get_connection()`.
"""

import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone

from config import DB_PATH

_lock = threading.Lock()


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            user_agent TEXT,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            query_params TEXT,
            headers TEXT,
            payload TEXT,
            decoy_type TEXT,
            canary_token TEXT,
            severity TEXT NOT NULL DEFAULT 'medium'
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS canaries (
            token TEXT PRIMARY KEY,
            decoy_type TEXT NOT NULL,
            created_at TEXT NOT NULL,
            triggered_count INTEGER NOT NULL DEFAULT 0,
            last_triggered_at TEXT
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts(source_ip)")
    conn.commit()


@contextmanager
def get_connection():
    """Thread-safe context-managed SQLite connection."""
    with _lock:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            _init_schema(conn)
            yield conn
        finally:
            conn.close()


def insert_alert(
    source_ip: str,
    user_agent: str,
    method: str,
    path: str,
    query_params: str,
    headers: str,
    payload: str,
    decoy_type: str,
    canary_token: str = None,
    severity: str = "medium",
) -> int:
    ts = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        cur = conn.execute(
            """
            INSERT INTO alerts
                (timestamp, source_ip, user_agent, method, path, query_params,
                 headers, payload, decoy_type, canary_token, severity)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (ts, source_ip, user_agent, method, path, query_params, headers,
             payload, decoy_type, canary_token, severity),
        )
        conn.commit()
        return cur.lastrowid


def register_canary(token: str, decoy_type: str) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO canaries (token, decoy_type, created_at) VALUES (?, ?, ?)",
            (token, decoy_type, ts),
        )
        conn.commit()


def trigger_canary(token: str) -> bool:
    """Mark a canary token as triggered. Returns True if the token was known."""
    ts = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        cur = conn.execute("SELECT token FROM canaries WHERE token = ?", (token,))
        row = cur.fetchone()
        if not row:
            return False
        conn.execute(
            """
            UPDATE canaries
            SET triggered_count = triggered_count + 1, last_triggered_at = ?
            WHERE token = ?
            """,
            (ts, token),
        )
        conn.commit()
        return True


def get_recent_alerts(limit: int = 200):
    with get_connection() as conn:
        cur = conn.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
        )
        return [dict(row) for row in cur.fetchall()]


def get_alert_stats():
    with get_connection() as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]
        unique_ips = conn.execute(
            "SELECT COUNT(DISTINCT source_ip) AS c FROM alerts"
        ).fetchone()["c"]
        top_decoys = conn.execute(
            """
            SELECT decoy_type, COUNT(*) AS hits
            FROM alerts
            GROUP BY decoy_type
            ORDER BY hits DESC
            LIMIT 10
            """
        ).fetchall()
        top_ips = conn.execute(
            """
            SELECT source_ip, COUNT(*) AS hits
            FROM alerts
            GROUP BY source_ip
            ORDER BY hits DESC
            LIMIT 10
            """
        ).fetchall()
        canaries_triggered = conn.execute(
            "SELECT COUNT(*) AS c FROM canaries WHERE triggered_count > 0"
        ).fetchone()["c"]
        return {
            "total_alerts": total,
            "unique_ips": unique_ips,
            "top_decoys": [dict(r) for r in top_decoys],
            "top_ips": [dict(r) for r in top_ips],
            "canaries_triggered": canaries_triggered,
        }
