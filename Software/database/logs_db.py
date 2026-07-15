"""Logs database access layer for RDRS.

Stores filesystem monitoring events (created, modified, deleted, renamed).
Automatically prunes old rows when the table exceeds ``max_rows``.

Schema:
    file_events
        id          INTEGER PRIMARY KEY AUTOINCREMENT
        timestamp   REAL    NOT NULL   — epoch time of the event
        event_type  TEXT    NOT NULL   — FILE CREATED | FILE MODIFIED | FILE DELETED | FILE RENAMED
        file_path   TEXT    NOT NULL
        file_name   TEXT    NOT NULL
        process     TEXT               — process name (if resolved)
        pid         INTEGER            — process ID (if resolved)
        executable  TEXT               — full exe path (if resolved)
        parent      TEXT               — parent process name (if resolved)
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import List, Optional

from database.base_db import BaseDatabase


class LogsDatabase(BaseDatabase):
    """Access layer for the file events log SQLite database."""

    def __init__(self, db_path: Path, max_rows: int = 500_000) -> None:
        """Initialise the logs database.

        Args:
            db_path:  Absolute path to the SQLite file.
            max_rows: Maximum number of rows to keep.  When the table exceeds
                      this limit, the oldest 10 % of rows are deleted.
        """
        self._max_rows = max_rows
        super().__init__(db_path)

    def _get_schema_sql(self) -> List[str]:
        return [
            """
            CREATE TABLE IF NOT EXISTS file_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   REAL    NOT NULL,
                event_type  TEXT    NOT NULL,
                file_path   TEXT    NOT NULL,
                file_name   TEXT    NOT NULL,
                process     TEXT,
                pid         INTEGER,
                executable  TEXT,
                parent      TEXT
            );
            """,
            # Index for fast time-ordered queries and range deletes.
            "CREATE INDEX IF NOT EXISTS idx_events_ts ON file_events (timestamp);",
            "CREATE INDEX IF NOT EXISTS idx_events_type ON file_events (event_type);",
        ]

    # ------------------------------------------------------------------
    # Write operations
    # ------------------------------------------------------------------

    def log_event(
        self,
        *,
        event_type: str,
        file_path: str,
        file_name: str,
        process: Optional[str] = None,
        pid: Optional[int] = None,
        executable: Optional[str] = None,
        parent: Optional[str] = None,
        timestamp: Optional[float] = None,
    ) -> None:
        """Insert a single file-system event.

        Automatically triggers a cleanup pass if the row count exceeds the
        configured limit (checked approximately every 1 000 inserts to avoid
        expensive COUNT queries on every event).

        Args:
            event_type: One of FILE CREATED / FILE MODIFIED / FILE DELETED / FILE RENAMED.
            file_path:  Absolute path to the file.
            file_name:  Base filename.
            process:    Process name (optional).
            pid:        Process ID (optional).
            executable: Executable path (optional).
            parent:     Parent process name (optional).
            timestamp:  Event epoch time (defaults to now).
        """
        ts = timestamp or time.time()
        self.execute(
            """
            INSERT INTO file_events
                (timestamp, event_type, file_path, file_name, process, pid, executable, parent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (ts, event_type, file_path, file_name, process, pid, executable, parent),
        )
        # Throttled retention enforcement — count query is cheap when indexed.
        self._maybe_trim()

    def _maybe_trim(self) -> None:
        """Delete the oldest rows if the table exceeds ``_max_rows``.

        Deletes the oldest 10 % of rows in a single DELETE … WHERE id IN (…)
        statement to avoid full-table rewrites.
        """
        row = self.fetchone("SELECT COUNT(*) AS cnt FROM file_events")
        count = row["cnt"] if row else 0
        if count <= self._max_rows:
            return

        # Calculate how many rows to remove (at least 1).
        delete_count = max(1, count // 10)
        self.execute(
            """
            DELETE FROM file_events
             WHERE id IN (
                SELECT id FROM file_events ORDER BY id ASC LIMIT ?
             )
            """,
            (delete_count,),
        )

    # ------------------------------------------------------------------
    # Read operations
    # ------------------------------------------------------------------

    def get_recent(self, limit: int = 200) -> list:
        """Return the most-recent events.

        Args:
            limit: Maximum number of rows.

        Returns:
            List of sqlite3.Row ordered newest-first.
        """
        return self.fetchall(
            "SELECT * FROM file_events ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )

    def get_by_event_type(self, event_type: str, limit: int = 200) -> list:
        """Return events of a specific type.

        Args:
            event_type: e.g. 'FILE MODIFIED'.
            limit:      Max rows.

        Returns:
            List of sqlite3.Row.
        """
        return self.fetchall(
            "SELECT * FROM file_events WHERE event_type = ? ORDER BY timestamp DESC LIMIT ?",
            (event_type, limit),
        )

    def count_events(self) -> int:
        """Return total number of stored events.

        Returns:
            Row count.
        """
        row = self.fetchone("SELECT COUNT(*) AS cnt FROM file_events")
        return row["cnt"] if row else 0
