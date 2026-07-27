"""Logging estructurado de cada consulta DNS, en SQLite."""

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path


class LoggerDB:
    def __init__(self, db_path: str):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS queries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    client_ip TEXT,
                    domain TEXT,
                    qtype TEXT,
                    blocked INTEGER NOT NULL,
                    reason TEXT,
                    source TEXT,
                    duration_ms REAL
                )
                """
            )
            conn.commit()

    def log_query(
        self,
        client_ip: str,
        domain: str,
        qtype: str,
        blocked: bool,
        reason: str = "",
        source: str = "",
        duration_ms: float = 0.0,
    ) -> None:
        timestamp = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO queries
                    (timestamp, client_ip, domain, qtype, blocked, reason, source, duration_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (timestamp, client_ip, domain, qtype, int(blocked), reason, source, duration_ms),
            )
            conn.commit()

    def recent_blocked(self, limit: int = 25) -> list[tuple]:
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                """
                SELECT timestamp, domain, reason FROM queries
                WHERE blocked = 1
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            )
            return cur.fetchall()

    def stats(self) -> dict:
        with self._lock, self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM queries").fetchone()[0]
            blocked = conn.execute(
                "SELECT COUNT(*) FROM queries WHERE blocked = 1"
            ).fetchone()[0]
            cached = conn.execute(
                "SELECT COUNT(*) FROM queries WHERE source = 'cache'"
            ).fetchone()[0]
        return {"total_queries": total, "blocked_queries": blocked, "cached_queries": cached}
