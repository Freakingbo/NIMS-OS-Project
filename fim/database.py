"""SQLite storage layer for baseline records, integrity events, and tamper-evident self-hashing."""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import sqlite3
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

logger = logging.getLogger(__name__)


@dataclass
class BaselineRecord:
    """Represents a single file entry in the FIM baseline."""

    path: str
    sha256: str
    size: int
    mtime: float
    permissions: str
    owner: str
    updated_at: str


@dataclass
class IntegrityEvent:
    """Represents a detected file system integrity change."""

    event_type: str  # CREATED, MODIFIED, DELETED, MOVED, PERMISSION_CHANGED
    path: str
    severity: str
    timestamp: str
    old_path: str | None = None
    old_hash: str | None = None
    new_hash: str | None = None
    details: str = ""
    id: int | None = None


class FimDatabase:
    """Manages SQLite persistence and HMAC-SHA256 tamper verification for FIM."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Open a SQLite connection, manage transaction commit/rollback, and always close the handle."""
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS baseline (
                    path TEXT PRIMARY KEY,
                    sha256 TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    mtime REAL NOT NULL,
                    permissions TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    path TEXT NOT NULL,
                    old_path TEXT,
                    severity TEXT NOT NULL,
                    old_hash TEXT,
                    new_hash TEXT,
                    details TEXT,
                    timestamp TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )

    def _get_or_create_hmac_key(self, conn: sqlite3.Connection) -> bytes:
        """Retrieve or generate a random HMAC key stored in metadata (or env FIM_HMAC_KEY)."""
        env_key = os.environ.get("FIM_HMAC_KEY")
        if env_key:
            return env_key.encode("utf-8")

        row = conn.execute("SELECT value FROM metadata WHERE key = 'hmac_key'").fetchone()
        if row:
            return bytes.fromhex(row["value"])

        new_key = secrets.token_bytes(32)
        conn.execute(
            "INSERT INTO metadata (key, value) VALUES ('hmac_key', ?)",
            (new_key.hex(),),
        )
        return new_key

    def _compute_baseline_hmac(self, conn: sqlite3.Connection) -> str:
        """Compute deterministic HMAC-SHA256 over all sorted baseline rows."""
        key = self._get_or_create_hmac_key(conn)
        mac = hmac.new(key, digestmod=hashlib.sha256)
        rows = conn.execute(
            "SELECT path, sha256, size, mtime, permissions, owner, updated_at FROM baseline ORDER BY path ASC"
        ).fetchall()
        for r in rows:
            canonical = (
                f"{r['path']}|{r['sha256']}|{r['size']}|"
                f"{r['mtime']:.6f}|{r['permissions']}|{r['owner']}|{r['updated_at']}\n"
            )
            mac.update(canonical.encode("utf-8"))
        return mac.hexdigest()

    def seal_baseline(self) -> str:
        """Recompute and persist the baseline integrity HMAC signature."""
        with self._connect() as conn:
            digest = self._compute_baseline_hmac(conn)
            now_iso = datetime.now(timezone.utc).isoformat()
            conn.execute(
                """
                INSERT INTO metadata (key, value) VALUES ('baseline_hmac', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (digest,),
            )
            conn.execute(
                """
                INSERT INTO metadata (key, value) VALUES ('baseline_sealed_at', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (now_iso,),
            )
            return digest

    def verify_integrity(self) -> tuple[bool, str]:
        """Verify that the baseline table has not been altered out-of-band."""
        with self._connect() as conn:
            row = conn.execute("SELECT value FROM metadata WHERE key = 'baseline_hmac'").fetchone()
            if not row:
                return False, "No baseline signature found in database (baseline not initialized or metadata wiped)."
            stored_hmac = row["value"]
            actual_hmac = self._compute_baseline_hmac(conn)
            if hmac.compare_digest(stored_hmac, actual_hmac):
                return True, f"Database integrity verified (HMAC: {actual_hmac[:16]}...)."
            return (
                False,
                f"TAMPERING DETECTED! Stored HMAC ({stored_hmac[:16]}...) != Computed HMAC ({actual_hmac[:16]}...).",
            )

    def replace_baseline(self, records: list[BaselineRecord]) -> int:
        """Atomically replace all records in the baseline table and re-seal the database."""
        with self._connect() as conn:
            conn.execute("DELETE FROM baseline;")
            conn.executemany(
                """
                INSERT INTO baseline (path, sha256, size, mtime, permissions, owner, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (r.path, r.sha256, r.size, r.mtime, r.permissions, r.owner, r.updated_at)
                    for r in records
                ],
            )
            digest = self._compute_baseline_hmac(conn)
            now_iso = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "INSERT INTO metadata (key, value) VALUES ('baseline_hmac', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (digest,),
            )
            conn.execute(
                "INSERT INTO metadata (key, value) VALUES ('baseline_sealed_at', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (now_iso,),
            )
        return len(records)

    def upsert_baseline_record(self, record: BaselineRecord) -> None:
        """Insert or update a single baseline record and re-seal."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO baseline (path, sha256, size, mtime, permissions, owner, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(path) DO UPDATE SET
                    sha256 = excluded.sha256,
                    size = excluded.size,
                    mtime = excluded.mtime,
                    permissions = excluded.permissions,
                    owner = excluded.owner,
                    updated_at = excluded.updated_at
                """,
                (
                    record.path,
                    record.sha256,
                    record.size,
                    record.mtime,
                    record.permissions,
                    record.owner,
                    record.updated_at,
                ),
            )
        self.seal_baseline()

    def get_all_baseline(self) -> dict[str, BaselineRecord]:
        """Return all baseline records keyed by normalized file path."""
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM baseline").fetchall()
        return {
            row["path"]: BaselineRecord(
                path=row["path"],
                sha256=row["sha256"],
                size=row["size"],
                mtime=row["mtime"],
                permissions=row["permissions"],
                owner=row["owner"],
                updated_at=row["updated_at"],
            )
            for row in rows
        }

    def baseline_count(self) -> int:
        """Return the number of files currently tracked in the baseline."""
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS cnt FROM baseline").fetchone()
            return int(row["cnt"]) if row else 0

    def record_events(self, events: list[IntegrityEvent]) -> None:
        """Persist one or more integrity events into the events table."""
        if not events:
            return
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT INTO events (event_type, path, old_path, severity, old_hash, new_hash, details, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        e.event_type,
                        e.path,
                        e.old_path,
                        e.severity,
                        e.old_hash,
                        e.new_hash,
                        e.details,
                        e.timestamp,
                    )
                    for e in events
                ],
            )

    def get_events(self, limit: int | None = None) -> list[IntegrityEvent]:
        """Retrieve recorded integrity events ordered newest first."""
        query = "SELECT * FROM events ORDER BY id DESC"
        params: tuple[Any, ...] = ()
        if limit is not None:
            query += " LIMIT ?"
            params = (limit,)

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()

        return [
            IntegrityEvent(
                id=row["id"],
                event_type=row["event_type"],
                path=row["path"],
                old_path=row["old_path"],
                severity=row["severity"],
                old_hash=row["old_hash"],
                new_hash=row["new_hash"],
                details=row["details"] or "",
                timestamp=row["timestamp"],
            )
            for row in rows
        ]