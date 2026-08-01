"""Metadata database access layer for RDRS.

Stores the entropy cache and optional legacy file metadata.

Schema:
        entropy_cache
                path             TEXT PRIMARY KEY   — absolute, normalised path
                entropy          REAL               — Shannon entropy (bits/byte)
                file_size        INTEGER            — bytes
                modified_time    REAL               — mtime epoch
                last_scan        REAL               — epoch of our last scan
                exists           INTEGER            — 1 = file exists, 0 = deleted

        file_metadata
                file_path           TEXT PRIMARY KEY   — absolute, normalised path
                file_name           TEXT               — basename only
                sha256_hash         TEXT               — hex digest (future use; may be NULL)
                current_entropy     REAL               — Shannon entropy (bits/byte) of current scan
                previous_entropy    REAL               — entropy from the previous scan
                file_size           INTEGER            — bytes
                last_modified_ts    REAL               — mtime epoch
                last_scan_ts        REAL               — epoch of our last scan
                exists              INTEGER            — 1 = file exists, 0 = deleted
                deleted_ts          REAL               — epoch when deletion was detected (NULL if exists)

Behaviour:
        - The entropy cache is durable across restarts and reused whenever the
            file size and modification time are unchanged.
        - File deletions are retained so historical entropy can still be queried.
        - Legacy file metadata remains available for compatibility with existing
            callers and UI code.
"""

from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path
from typing import List, Optional

from database.base_db import BaseDatabase


class MetadataDatabase(BaseDatabase):
    """Access layer for the file metadata SQLite database."""

    def __init__(self, db_path: Path) -> None:
        super().__init__(db_path)
        self._ensure_identity_map_schema()
        self._ensure_file_metadata_columns()

    @staticmethod
    def _normalize_path(file_path: str) -> str:
        """Normalize path to a canonical absolute form for stable DB keys.

        On macOS, filesystem events may report `/private/var/...` while callers
        query `/var/...` (symlinked).  Using `realpath` here ensures both forms
        map to the same key.
        """
        try:
            return os.path.realpath(os.path.abspath(file_path))
        except Exception:
            return str(Path(file_path))

    def _get_schema_sql(self) -> List[str]:
        return [
            """
            CREATE TABLE IF NOT EXISTS entropy_cache (
                path           TEXT    NOT NULL PRIMARY KEY,
                entropy        REAL,
                file_size      INTEGER,
                modified_time  REAL,
                last_scan      REAL    NOT NULL,
                "exists"      INTEGER NOT NULL DEFAULT 1
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_entropy_cache_scan ON entropy_cache (last_scan);",
            "CREATE INDEX IF NOT EXISTS idx_entropy_cache_exists ON entropy_cache (\"exists\");",
            """
            CREATE TABLE IF NOT EXISTS file_metadata (
                file_path        TEXT    NOT NULL PRIMARY KEY,
                file_name        TEXT    NOT NULL,
                sha256_hash      TEXT,
                first_seen       REAL,
                current_entropy  REAL,
                previous_entropy REAL,
                file_size        INTEGER,
                last_modified_ts REAL,
                last_scan_ts     REAL    NOT NULL,
                "exists"         INTEGER NOT NULL DEFAULT 1,
                deleted_ts       REAL
            );
            """,
            # Index for quickly querying deleted files by deletion time.
            "CREATE INDEX IF NOT EXISTS idx_metadata_deleted ON file_metadata (deleted_ts);",
            # Index for sorting by last scan time (GUI refresh).
            "CREATE INDEX IF NOT EXISTS idx_metadata_scan ON file_metadata (last_scan_ts);",
            """
            CREATE TABLE IF NOT EXISTS entropy_identity_map (
                file_id   TEXT    NOT NULL PRIMARY KEY,
                path      TEXT    NOT NULL,
                last_scan REAL    NOT NULL,
                "exists" INTEGER NOT NULL DEFAULT 1
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_entropy_identity_path ON entropy_identity_map (path);",
            "CREATE INDEX IF NOT EXISTS idx_entropy_identity_exists ON entropy_identity_map (\"exists\");",
            """
            CREATE TABLE IF NOT EXISTS entropy_runtime_baseline (
                id                       INTEGER PRIMARY KEY CHECK (id = 1),
                initial_average_entropy  REAL,
                initial_max_entropy      REAL,
                baseline_file_count      INTEGER NOT NULL DEFAULT 0,
                source_roots             TEXT,
                computed_at              REAL NOT NULL
            );
            """,
        ]

    def _ensure_identity_map_schema(self) -> None:
        """Ensure identity map table exists for older database files."""
        self.execute(
            """
            CREATE TABLE IF NOT EXISTS entropy_identity_map (
                file_id   TEXT    NOT NULL PRIMARY KEY,
                path      TEXT    NOT NULL,
                last_scan REAL    NOT NULL,
                "exists" INTEGER NOT NULL DEFAULT 1
            );
            """
        )
        self.execute("CREATE INDEX IF NOT EXISTS idx_entropy_identity_path ON entropy_identity_map (path);")
        self.execute("CREATE INDEX IF NOT EXISTS idx_entropy_identity_exists ON entropy_identity_map (\"exists\");")

    def _ensure_file_metadata_columns(self) -> None:
        """Apply non-destructive schema upgrades for legacy database files."""
        self.execute("ALTER TABLE file_metadata ADD COLUMN file_id TEXT", commit=False)
        self.execute("ALTER TABLE file_metadata ADD COLUMN current_path TEXT", commit=False)
        self.execute("ALTER TABLE file_metadata ADD COLUMN current_filename TEXT", commit=False)
        self.execute("ALTER TABLE file_metadata ADD COLUMN current_extension TEXT", commit=False)
        self.execute("ALTER TABLE file_metadata ADD COLUMN baseline_entropy REAL", commit=False)
        self.execute("ALTER TABLE file_metadata ADD COLUMN first_seen REAL", commit=False)
        self.execute(
            "CREATE INDEX IF NOT EXISTS idx_metadata_file_id ON file_metadata (file_id)",
            commit=False,
        )
        self.execute(
            "UPDATE file_metadata SET current_path = file_path WHERE current_path IS NULL",
            commit=False,
        )
        self.execute(
            "UPDATE file_metadata SET current_filename = file_name WHERE current_filename IS NULL",
            commit=False,
        )
        self.execute(
            "UPDATE file_metadata SET current_extension = lower(trim(substr(file_name, instr(file_name, '.') + 1))) "
            "WHERE current_extension IS NULL AND instr(file_name, '.') > 0",
            commit=False,
        )
        self.execute(
            "UPDATE file_metadata SET baseline_entropy = current_entropy WHERE baseline_entropy IS NULL",
            commit=True,
        )
        self.execute(
            "UPDATE file_metadata SET first_seen = COALESCE(first_seen, last_scan_ts) WHERE first_seen IS NULL",
            commit=True,
        )

    def execute(
        self,
        sql: str,
        params=(),
        *,
        commit: bool = True,
    ):
        """Execute SQL while tolerating idempotent ALTER TABLE column-additions."""
        if "alter table" in sql.lower() and "add column" in sql.lower():
            conn = self._conn
            try:
                cursor = conn.execute(sql, params)
                if commit:
                    conn.commit()
                return cursor
            except sqlite3.Error as exc:
                if "duplicate column name" in str(exc).lower():
                    return conn.execute("SELECT 1")
                conn.rollback()
                raise
        try:
            return super().execute(sql, params, commit=commit)
        except Exception as exc:
            if "duplicate column name" in str(exc).lower() and "alter table" in sql.lower():
                return self._conn.execute("SELECT 1")
            raise

    # ------------------------------------------------------------------
    # Write operations
    # ------------------------------------------------------------------

    def upsert_file(
        self,
        *,
        file_path: str,
        file_name: str,
        current_entropy: Optional[float],
        previous_entropy: Optional[float],
        file_size: Optional[int],
        last_modified_ts: Optional[float],
        sha256_hash: Optional[str] = None,
        file_id: Optional[str] = None,
        baseline_entropy: Optional[float] = None,
        first_seen: Optional[float] = None,
    ) -> None:
        """Insert or update a file metadata record.

        Behaviour:
          - If the record does not exist, it is inserted as exists=1.
          - If it exists, current/previous entropy, size, mtime, and scan time
            are updated.  sha256_hash is only updated when a new value is given.
          - Calling this method implicitly marks the file as existing (exists=1).

        Args:
            file_path:        Absolute normalised path string.
            file_name:        Base filename.
            current_entropy:  Freshly computed entropy value.
            previous_entropy: Previous entropy value (before this scan).
            file_size:        Current file size in bytes.
            last_modified_ts: mtime epoch.
            sha256_hash:      SHA-256 hex digest (optional; future use).
        """
        now = time.time()
        file_path = self._normalize_path(file_path)
        extension = ""
        if "." in file_name:
            extension = file_name.rsplit(".", 1)[-1].lower()
        first_seen_value = first_seen if first_seen is not None else now
        self.execute(
            """
            INSERT INTO file_metadata
                (file_path, file_name, sha256_hash, first_seen, current_entropy,
                 previous_entropy, file_size, last_modified_ts, last_scan_ts,
                 "exists", deleted_ts, file_id, current_path, current_filename,
                 current_extension, baseline_entropy)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, NULL, ?, ?, ?, ?, ?)
            ON CONFLICT(file_path) DO UPDATE SET
                file_name        = excluded.file_name,
                sha256_hash      = COALESCE(excluded.sha256_hash, sha256_hash),
                current_entropy  = excluded.current_entropy,
                previous_entropy = excluded.previous_entropy,
                file_size        = excluded.file_size,
                last_modified_ts = excluded.last_modified_ts,
                last_scan_ts     = excluded.last_scan_ts,
                file_id          = COALESCE(excluded.file_id, file_id),
                current_path     = excluded.current_path,
                current_filename = excluded.current_filename,
                current_extension = excluded.current_extension,
                baseline_entropy = COALESCE(baseline_entropy, excluded.baseline_entropy),
                "exists"         = 1,
                deleted_ts       = NULL
            """,
            (
                file_path,
                file_name,
                sha256_hash,
                first_seen_value,
                current_entropy,
                previous_entropy,
                file_size,
                last_modified_ts,
                now,
                file_id,
                file_path,
                file_name,
                extension,
                baseline_entropy if baseline_entropy is not None else current_entropy,
            ),
        )

    def update_file_by_identifier(
        self,
        *,
        file_id: str,
        file_path: str,
        file_name: str,
        current_entropy: Optional[float],
        previous_entropy: Optional[float],
        file_size: Optional[int],
        last_modified_ts: Optional[float],
        sha256_hash: Optional[str] = None,
        current_path: Optional[str] = None,
        current_filename: Optional[str] = None,
        current_extension: Optional[str] = None,
        exists: bool = True,
    ) -> bool:
        """Update an existing file row in place when identity is unchanged."""
        if not file_id:
            return False

        now = time.time()
        normalized_path = self._normalize_path(file_path)
        if current_path is None:
            current_path = normalized_path
        if current_filename is None:
            current_filename = file_name
        if current_extension is None and "." in file_name:
            current_extension = file_name.rsplit(".", 1)[-1].lower()

        cursor = self.execute(
            """
            UPDATE file_metadata
               SET file_path         = ?,
                   file_name         = ?,
                   sha256_hash       = COALESCE(?, sha256_hash),
                   current_entropy   = ?,
                   previous_entropy  = ?,
                   file_size         = ?,
                   last_modified_ts  = ?,
                   last_scan_ts      = ?,
                   file_id           = COALESCE(file_id, ?),
                   current_path      = ?,
                   current_filename  = ?,
                   current_extension = ?,
                   "exists"          = ?,
                   deleted_ts        = NULL
             WHERE file_id = ?
            """,
            (
                normalized_path,
                file_name,
                sha256_hash,
                current_entropy,
                previous_entropy,
                file_size,
                last_modified_ts,
                now,
                file_id,
                normalized_path,
                current_filename,
                current_extension,
                1 if exists else 0,
                file_id,
            ),
        )
        return cursor.rowcount > 0

    def get_file_by_identifier(self, file_id: Optional[str], file_path: str, *, include_deleted: bool = False):
        """Fetch a file row by stable identifier, falling back to canonical path."""
        normalized_path = self._normalize_path(file_path)
        if file_id:
            if include_deleted:
                row = self.fetchone(
                    "SELECT * FROM file_metadata WHERE file_id = ?",
                    (file_id,),
                )
            else:
                row = self.fetchone(
                    'SELECT * FROM file_metadata WHERE file_id = ? AND "exists" = 1',
                    (file_id,),
                )
            if row is not None:
                return row
        if include_deleted:
            return self.fetchone(
                "SELECT * FROM file_metadata WHERE file_path = ?",
                (normalized_path,),
            )
        return self.fetchone(
            'SELECT * FROM file_metadata WHERE file_path = ? AND "exists" = 1',
            (normalized_path,),
        )

    def reset_runtime_state(self) -> None:
        """Clear runtime metadata so startup can rebuild from filesystem truth."""
        self.execute("DELETE FROM file_metadata")
        self.execute("DELETE FROM entropy_cache")
        self.execute("DELETE FROM entropy_identity_map")
        self.execute("DELETE FROM entropy_runtime_baseline")

    def set_runtime_entropy_baseline(
        self,
        *,
        initial_average_entropy: Optional[float],
        initial_max_entropy: Optional[float],
        baseline_file_count: int,
        source_roots: Optional[str] = None,
    ) -> None:
        """Persist one startup entropy baseline snapshot for the current run."""
        self.execute(
            """
            INSERT INTO entropy_runtime_baseline (
                id,
                initial_average_entropy,
                initial_max_entropy,
                baseline_file_count,
                source_roots,
                computed_at
            )
            VALUES (1, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                initial_average_entropy = excluded.initial_average_entropy,
                initial_max_entropy = excluded.initial_max_entropy,
                baseline_file_count = excluded.baseline_file_count,
                source_roots = excluded.source_roots,
                computed_at = excluded.computed_at
            """,
            (
                initial_average_entropy,
                initial_max_entropy,
                max(0, int(baseline_file_count)),
                source_roots,
                time.time(),
            ),
        )

    def get_runtime_entropy_baseline(self):
        """Return the persisted startup entropy baseline snapshot."""
        return self.fetchone(
            "SELECT * FROM entropy_runtime_baseline WHERE id = 1"
        )

    # ------------------------------------------------------------------
    # Entropy cache operations
    # ------------------------------------------------------------------

    def upsert_entropy_cache(
        self,
        *,
        path: str,
        entropy: Optional[float],
        file_size: Optional[int],
        modified_time: Optional[float],
        exists: bool = True,
    ) -> None:
        """Insert or update a persistent entropy cache record."""
        now = time.time()
        path = self._normalize_path(path)
        self.execute(
            """
            INSERT INTO entropy_cache
                (path, entropy, file_size, modified_time, last_scan, "exists")
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(path) DO UPDATE SET
                entropy       = excluded.entropy,
                file_size     = excluded.file_size,
                modified_time = excluded.modified_time,
                last_scan     = excluded.last_scan,
                "exists"     = excluded."exists"
            """,
            (path, entropy, file_size, modified_time, now, 1 if exists else 0),
        )

    def mark_entropy_deleted(self, path: str) -> None:
        """Mark a cached entropy entry as deleted without removing it."""
        now = time.time()
        path = self._normalize_path(path)
        self.execute(
            """
            INSERT INTO entropy_cache (path, entropy, file_size, modified_time, last_scan, "exists")
            VALUES (?, NULL, NULL, NULL, ?, 0)
            ON CONFLICT(path) DO UPDATE SET
                "exists" = 0,
                last_scan = excluded.last_scan
            """,
            (path, now),
        )
        self.execute(
            """
            UPDATE entropy_identity_map
               SET "exists" = 0,
                   last_scan = ?
             WHERE path = ?
            """,
            (now, path),
        )

    def rename_entropy_path(self, old_path: str, new_path: str) -> None:
        """Move an entropy cache entry to a new path after rename/move."""
        old_path = self._normalize_path(old_path)
        new_path = self._normalize_path(new_path)
        row = self.fetchone("SELECT * FROM entropy_cache WHERE path = ?", (old_path,))
        if row is None:
            return
        self.execute(
            "DELETE FROM entropy_cache WHERE path = ?",
            (old_path,),
        )
        self.execute(
            """
            INSERT INTO entropy_cache (path, entropy, file_size, modified_time, last_scan, "exists")
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                new_path,
                row["entropy"],
                row["file_size"],
                row["modified_time"],
                time.time(),
                row["exists"],
            ),
        )
        self.execute(
            """
            UPDATE entropy_identity_map
               SET path = ?,
                   last_scan = ?,
                   "exists" = 1
             WHERE path = ?
            """,
            (new_path, time.time(), old_path),
        )

    def get_entropy_record(self, path: str):
        """Fetch a single entropy cache record."""
        path = self._normalize_path(path)
        return self.fetchone("SELECT * FROM entropy_cache WHERE path = ?", (path,))

    def get_entropy_records(self, directory: Optional[str] = None):
        """Return entropy cache rows, optionally filtered by directory prefix."""
        if directory is None:
            return self.fetchall("SELECT * FROM entropy_cache ORDER BY last_scan DESC")
        directory = self._normalize_path(directory)
        return self.fetchall(
            "SELECT * FROM entropy_cache WHERE path LIKE ? ORDER BY last_scan DESC",
            (directory.rstrip("/\\") + "%",),
        )

    def get_entropy_existing(self):
        """Return only existing entropy cache rows."""
        return self.fetchall('SELECT * FROM entropy_cache WHERE "exists" = 1 ORDER BY last_scan DESC')

    def cleanup_old_deleted_entropy(self, retention_days: int) -> int:
        """Remove old deleted entropy cache records."""
        cutoff = time.time() - retention_days * 86_400
        cursor = self.execute(
            'DELETE FROM entropy_cache WHERE "exists" = 0 AND last_scan < ?',
            (cutoff,),
        )
        return cursor.rowcount

    def mark_deleted(self, file_path: str) -> None:
        """Mark a file as deleted without removing its metadata record.

        Args:
            file_path: Absolute normalised path string.
        """
        now = time.time()
        file_path = self._normalize_path(file_path)
        self.execute(
            """
            UPDATE file_metadata
               SET "exists"   = 0,
                   deleted_ts = ?
             WHERE file_path  = ?
               AND "exists"   = 1
            """,
            (now, file_path),
        )

    def delete_file(self, file_path: str) -> None:
        """Remove a file metadata row entirely when it no longer exists."""
        file_path = self._normalize_path(file_path)
        self.execute("DELETE FROM file_metadata WHERE file_path = ?", (file_path,))

    def delete_entropy_cache(self, path: str) -> None:
        """Remove an entropy cache row entirely when the file no longer exists."""
        path = self._normalize_path(path)
        self.execute("DELETE FROM entropy_cache WHERE path = ?", (path,))
        self.execute("DELETE FROM entropy_identity_map WHERE path = ?", (path,))

    def upsert_entropy_identity(self, file_id: str, path: str, *, exists: bool = True) -> None:
        """Upsert a durable mapping from stable file identity to current path."""
        if not file_id:
            return
        path = self._normalize_path(path)
        now = time.time()
        self.execute(
            """
            INSERT INTO entropy_identity_map (file_id, path, last_scan, "exists")
            VALUES (?, ?, ?, ?)
            ON CONFLICT(file_id) DO UPDATE SET
                path = excluded.path,
                last_scan = excluded.last_scan,
                "exists" = excluded."exists"
            """,
            (file_id, path, now, 1 if exists else 0),
        )

    def resolve_entropy_path(self, file_id: str) -> Optional[str]:
        """Return the most recent known path for a stable file identity."""
        if not file_id:
            return None
        row = self.fetchone(
            "SELECT path FROM entropy_identity_map WHERE file_id = ? AND \"exists\" = 1",
            (file_id,),
        )
        if row is None:
            return None
        return self._normalize_path(row["path"])

    def mark_entropy_identity_deleted(self, file_id: str) -> None:
        """Mark a tracked identity as deleted when a delete event is observed."""
        if not file_id:
            return
        self.execute(
            """
            UPDATE entropy_identity_map
               SET "exists" = 0,
                   last_scan = ?
             WHERE file_id = ?
            """,
            (time.time(), file_id),
        )

    def cleanup_old_deleted(self, retention_days: int) -> int:
        """Remove deleted file records older than ``retention_days``.

        Args:
            retention_days: Records deleted more than this many days ago are purged.

        Returns:
            Number of rows deleted.
        """
        cutoff = time.time() - retention_days * 86_400
        cursor = self.execute(
            """
            DELETE FROM file_metadata
             WHERE "exists"   = 0
               AND deleted_ts IS NOT NULL
               AND deleted_ts < ?
            """,
            (cutoff,),
        )
        return cursor.rowcount

    # ------------------------------------------------------------------
    # Read operations
    # ------------------------------------------------------------------

    def get_file(self, file_path: str):
        """Fetch a single file record.

        Args:
            file_path: Absolute normalised path string.

        Returns:
            sqlite3.Row or None.
        """
        file_path = self._normalize_path(file_path)
        return self.fetchone(
            "SELECT * FROM file_metadata WHERE file_path = ?",
            (file_path,),
        )

    def get_all_existing(self):
        """Return all records where exists=1, ordered by last scan descending.

        Returns:
            List of sqlite3.Row.
        """
        return self.fetchall(
            'SELECT * FROM file_metadata WHERE "exists" = 1 ORDER BY last_scan_ts DESC'
        )

    def get_by_directory(self, directory: str):
        """Return all records whose path starts with ``directory``.

        Args:
            directory: Directory path prefix (with trailing slash).

        Returns:
            List of sqlite3.Row.
        """
        directory = self._normalize_path(directory)
        return self.fetchall(
            "SELECT * FROM file_metadata WHERE file_path LIKE ? ORDER BY last_scan_ts DESC",
            (directory.rstrip("/\\") + "%",),
        )

    def count_existing(self) -> int:
        """Return the number of currently-existing monitored files.

        Returns:
            Row count.
        """
        row = self.fetchone('SELECT COUNT(*) AS cnt FROM file_metadata WHERE "exists" = 1')
        return row["cnt"] if row else 0
