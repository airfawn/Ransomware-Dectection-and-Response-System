"""Base database class for RDRS SQLite databases.

All three databases (metadata, logs, alerts) inherit from this class.
It provides:
  - Automatic schema creation via subclass-defined SQL.
  - Thread-safe connection management (one connection per thread via
    threading.local so SQLite's check_same_thread restriction is satisfied).
  - A safe execute helper that commits or rolls back automatically.
  - A context-manager interface for explicit transactions.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from pathlib import Path
from typing import Any, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)


class BaseDatabase:
    """Thread-safe SQLite base class.

    Subclasses must implement :meth:`_get_schema_sql` which returns a list
    of SQL ``CREATE TABLE IF NOT EXISTS`` statements to run on first connect.

    Each thread gets its own :class:`sqlite3.Connection` via
    :class:`threading.local`.  WAL journal mode is enabled for better
    concurrent read performance.
    """

    def __init__(self, db_path: Path) -> None:
        """Initialise and create the schema if needed.

        Args:
            db_path: Absolute path to the SQLite file.  The parent directory
                     must already exist (callers are responsible for this).
        """
        self._db_path = db_path
        self._local = threading.local()
        # Ensure the parent directory exists
        db_path.parent.mkdir(parents=True, exist_ok=True)
        # Boot the schema on the calling thread
        self._ensure_schema()

    # ------------------------------------------------------------------
    # Subclass interface
    # ------------------------------------------------------------------

    def _get_schema_sql(self) -> List[str]:
        """Return a list of DDL statements executed at schema creation time.

        Subclasses must override this method.

        Returns:
            List of SQL strings (typically CREATE TABLE IF NOT EXISTS …).
        """
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    @property
    def _conn(self) -> sqlite3.Connection:
        """Return a per-thread SQLite connection, creating it if necessary.

        Connections use WAL mode for better concurrent performance and have
        a 30-second timeout to avoid hard failures under light contention.

        Returns:
            sqlite3.Connection bound to the current thread.
        """
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(
                str(self._db_path),
                timeout=30,
                check_same_thread=False,  # We manage thread safety ourselves
            )
            conn.row_factory = sqlite3.Row
            # WAL mode: readers don't block writers; writers don't block readers.
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            self._local.conn = conn
        return conn

    def _ensure_schema(self) -> None:
        """Run all schema SQL statements against the current connection."""
        conn = self._conn
        try:
            for statement in self._get_schema_sql():
                conn.execute(statement)
            conn.commit()
        except Exception as exc:
            logger.error("Schema creation failed for %s: %s", self._db_path, exc)
            conn.rollback()
            raise

    # ------------------------------------------------------------------
    # Execution helpers
    # ------------------------------------------------------------------

    def execute(
        self,
        sql: str,
        params: Sequence[Any] = (),
        *,
        commit: bool = True,
    ) -> sqlite3.Cursor:
        """Execute a single SQL statement with automatic commit/rollback.

        Args:
            sql: SQL statement string.
            params: Positional parameters for the statement.
            commit: Whether to commit after execution.

        Returns:
            sqlite3.Cursor with results.

        Raises:
            sqlite3.Error: Propagated after rollback on failure.
        """
        conn = self._conn
        try:
            cursor = conn.execute(sql, params)
            if commit:
                conn.commit()
            return cursor
        except sqlite3.Error as exc:
            logger.error("DB execute error (%s): %s — SQL: %.200s", self._db_path.name, exc, sql)
            conn.rollback()
            raise

    def executemany(
        self,
        sql: str,
        params_seq: Sequence[Sequence[Any]],
        *,
        commit: bool = True,
    ) -> None:
        """Execute a SQL statement for each item in params_seq.

        Args:
            sql: SQL statement string.
            params_seq: Sequence of parameter tuples.
            commit: Whether to commit after all executions.
        """
        conn = self._conn
        try:
            conn.executemany(sql, params_seq)
            if commit:
                conn.commit()
        except sqlite3.Error as exc:
            logger.error("DB executemany error (%s): %s", self._db_path.name, exc)
            conn.rollback()
            raise

    def fetchall(
        self,
        sql: str,
        params: Sequence[Any] = (),
    ) -> List[sqlite3.Row]:
        """Fetch all rows for a SELECT statement.

        Args:
            sql: SELECT statement.
            params: Positional parameters.

        Returns:
            List of sqlite3.Row objects.
        """
        return self.execute(sql, params, commit=False).fetchall()

    def fetchone(
        self,
        sql: str,
        params: Sequence[Any] = (),
    ) -> Optional[sqlite3.Row]:
        """Fetch the first row for a SELECT statement.

        Args:
            sql: SELECT statement.
            params: Positional parameters.

        Returns:
            sqlite3.Row or None.
        """
        return self.execute(sql, params, commit=False).fetchone()

    def close(self) -> None:
        """Close the per-thread connection if open."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None
