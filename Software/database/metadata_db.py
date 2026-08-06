"""Metadata database access layer for RDRS.

The entropy subsystem stores aggregate values only:
- one startup baseline average per runtime session
- one latest validation snapshot from score-threshold entropy validation

Per-file entropy persistence is intentionally not supported.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import List, Optional

from database.base_db import BaseDatabase


class MetadataDatabase(BaseDatabase):
    """SQLite access layer for aggregate entropy runtime metadata."""

    def __init__(self, db_path: Path) -> None:
        super().__init__(db_path)
        self._migrate_legacy_schema()

    def _table_columns(self, table_name: str) -> set:
        """Return a set of column names for a table."""
        rows = self.fetchall(f"PRAGMA table_info({table_name})")
        return {row["name"] for row in rows}

    def _ensure_column(self, table_name: str, column_name: str, column_sql: str) -> None:
        """Add a column if it is missing."""
        columns = self._table_columns(table_name)
        if column_name in columns:
            return
        self.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_sql}")

    def _migrate_legacy_schema(self) -> None:
        """Backfill schema changes for legacy metadata DB files.

        Older builds used column names like ``initial_average_entropy`` and
        ``baseline_file_count``. Ensure current columns exist and copy values
        forward so startup can read/write without manual DB resets.
        """
        # runtime baseline table
        baseline_table = "entropy_runtime_baseline"
        baseline_columns = self._table_columns(baseline_table)

        if "average_entropy" not in baseline_columns:
            self._ensure_column(baseline_table, "average_entropy", "REAL")
            if "initial_average_entropy" in baseline_columns:
                self.execute(
                    """
                    UPDATE entropy_runtime_baseline
                    SET average_entropy = initial_average_entropy
                    WHERE average_entropy IS NULL
                    """
                )

        if "file_count" not in baseline_columns:
            self._ensure_column(baseline_table, "file_count", "INTEGER NOT NULL DEFAULT 0")
            if "baseline_file_count" in baseline_columns:
                self.execute(
                    """
                    UPDATE entropy_runtime_baseline
                    SET file_count = COALESCE(baseline_file_count, 0)
                    WHERE file_count IS NULL OR file_count = 0
                    """
                )

        self._ensure_column(baseline_table, "source_roots", "TEXT")
        self._ensure_column(baseline_table, "created_at", "REAL")
        if "computed_at" in baseline_columns:
            self.execute(
                """
                UPDATE entropy_runtime_baseline
                SET created_at = computed_at
                WHERE created_at IS NULL
                """
            )
        self.execute(
            """
            UPDATE entropy_runtime_baseline
            SET created_at = ?
            WHERE created_at IS NULL
            """,
            (time.time(),),
        )

        # last validation table
        validation_table = "entropy_last_validation"
        self._ensure_column(validation_table, "validation_average_entropy", "REAL")
        self._ensure_column(validation_table, "validation_file_count", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column(validation_table, "triggered_process_pid", "INTEGER")
        self._ensure_column(validation_table, "triggered_process_name", "TEXT")
        self._ensure_column(validation_table, "triggered_process_executable", "TEXT")
        self._ensure_column(validation_table, "baseline_average_entropy", "REAL")
        self._ensure_column(validation_table, "entropy_increase", "REAL")
        self._ensure_column(validation_table, "score_delta", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column(validation_table, "validated_at", "REAL")
        self.execute(
            """
            UPDATE entropy_last_validation
            SET validated_at = ?
            WHERE validated_at IS NULL
            """,
            (time.time(),),
        )

    def _get_schema_sql(self) -> List[str]:
        return [
            """
            CREATE TABLE IF NOT EXISTS entropy_runtime_baseline (
                id               INTEGER PRIMARY KEY CHECK (id = 1),
                average_entropy  REAL,
                file_count       INTEGER NOT NULL DEFAULT 0,
                source_roots     TEXT,
                created_at       REAL NOT NULL
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS entropy_last_validation (
                id                           INTEGER PRIMARY KEY CHECK (id = 1),
                validation_average_entropy   REAL,
                validation_file_count        INTEGER NOT NULL DEFAULT 0,
                triggered_process_pid        INTEGER,
                triggered_process_name       TEXT,
                triggered_process_executable TEXT,
                baseline_average_entropy     REAL,
                entropy_increase             REAL,
                score_delta                  INTEGER NOT NULL DEFAULT 0,
                validated_at                 REAL NOT NULL
            );
            """,
        ]

    def reset_runtime_state(self) -> None:
        """Clear aggregate runtime metadata for a fresh startup session."""
        self.execute("DELETE FROM entropy_runtime_baseline")
        self.execute("DELETE FROM entropy_last_validation")

    def set_runtime_entropy_baseline(
        self,
        *,
        average_entropy: Optional[float],
        file_count: int,
        source_roots: Optional[str] = None,
    ) -> None:
        """Persist startup entropy baseline aggregate values."""
        self.execute("DELETE FROM entropy_last_validation")
        baseline_columns = self._table_columns("entropy_runtime_baseline")
        timestamp = time.time()
        normalized_file_count = max(0, int(file_count))

        columns = [
            "id",
            "average_entropy",
            "file_count",
            "source_roots",
            "created_at",
        ]
        values = [
            average_entropy,
            normalized_file_count,
            source_roots,
            timestamp,
        ]
        updates = [
            "average_entropy = excluded.average_entropy",
            "file_count = excluded.file_count",
            "source_roots = excluded.source_roots",
            "created_at = excluded.created_at",
        ]

        # Legacy metadata DBs still enforce NOT NULL on computed_at and may
        # keep alias columns. Populate both shapes in one UPSERT.
        if "initial_average_entropy" in baseline_columns:
            columns.append("initial_average_entropy")
            values.append(average_entropy)
            updates.append("initial_average_entropy = excluded.initial_average_entropy")
        if "baseline_file_count" in baseline_columns:
            columns.append("baseline_file_count")
            values.append(normalized_file_count)
            updates.append("baseline_file_count = excluded.baseline_file_count")
        if "computed_at" in baseline_columns:
            columns.append("computed_at")
            values.append(timestamp)
            updates.append("computed_at = excluded.computed_at")

        placeholders = ", ".join(["?"] * len(values))
        insert_columns_sql = ",\n                ".join(columns)
        updates_sql = ",\n                ".join(updates)

        self.execute(
            f"""
            INSERT INTO entropy_runtime_baseline (
                {insert_columns_sql}
            )
            VALUES (1, {placeholders})
            ON CONFLICT(id) DO UPDATE SET
                {updates_sql}
            """,
            tuple(values),
        )

    def get_runtime_entropy_baseline(self):
        """Return the current session baseline snapshot."""
        return self.fetchone("SELECT * FROM entropy_runtime_baseline WHERE id = 1")

    def set_last_entropy_validation(
        self,
        *,
        validation_average_entropy: float,
        validation_file_count: int,
        triggered_process_pid: Optional[int],
        triggered_process_name: Optional[str],
        triggered_process_executable: Optional[str],
        baseline_average_entropy: Optional[float],
        entropy_increase: Optional[float],
        score_delta: int,
    ) -> None:
        """Persist the latest validation snapshot triggered at score >= 50."""
        self.execute(
            """
            INSERT INTO entropy_last_validation (
                id,
                validation_average_entropy,
                validation_file_count,
                triggered_process_pid,
                triggered_process_name,
                triggered_process_executable,
                baseline_average_entropy,
                entropy_increase,
                score_delta,
                validated_at
            )
            VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                validation_average_entropy = excluded.validation_average_entropy,
                validation_file_count = excluded.validation_file_count,
                triggered_process_pid = excluded.triggered_process_pid,
                triggered_process_name = excluded.triggered_process_name,
                triggered_process_executable = excluded.triggered_process_executable,
                baseline_average_entropy = excluded.baseline_average_entropy,
                entropy_increase = excluded.entropy_increase,
                score_delta = excluded.score_delta,
                validated_at = excluded.validated_at
            """,
            (
                float(validation_average_entropy),
                max(0, int(validation_file_count)),
                triggered_process_pid,
                triggered_process_name,
                triggered_process_executable,
                baseline_average_entropy,
                entropy_increase,
                int(score_delta),
                time.time(),
            ),
        )

    def get_last_entropy_validation(self):
        """Return latest validation snapshot or None if never triggered."""
        return self.fetchone("SELECT * FROM entropy_last_validation WHERE id = 1")
