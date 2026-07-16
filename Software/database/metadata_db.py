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
import time
from pathlib import Path
from typing import List, Optional

from database.base_db import BaseDatabase


class MetadataDatabase(BaseDatabase):
    """Access layer for the file metadata SQLite database."""

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
        ]

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
        self.execute(
            """
            INSERT INTO file_metadata
                (file_path, file_name, sha256_hash, current_entropy,
                 previous_entropy, file_size, last_modified_ts, last_scan_ts,
                 "exists", deleted_ts)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, NULL)
            ON CONFLICT(file_path) DO UPDATE SET
                file_name        = excluded.file_name,
                sha256_hash      = COALESCE(excluded.sha256_hash, sha256_hash),
                current_entropy  = excluded.current_entropy,
                previous_entropy = excluded.previous_entropy,
                file_size        = excluded.file_size,
                last_modified_ts = excluded.last_modified_ts,
                last_scan_ts     = excluded.last_scan_ts,
                "exists"         = 1,
                deleted_ts       = NULL
            """,
            (
                file_path,
                file_name,
                sha256_hash,
                current_entropy,
                previous_entropy,
                file_size,
                last_modified_ts,
                now,
            ),
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
