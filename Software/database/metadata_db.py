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
        self.execute(
            """
            INSERT INTO entropy_runtime_baseline (
                id,
                average_entropy,
                file_count,
                source_roots,
                created_at
            )
            VALUES (1, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                average_entropy = excluded.average_entropy,
                file_count = excluded.file_count,
                source_roots = excluded.source_roots,
                created_at = excluded.created_at
            """,
            (
                average_entropy,
                max(0, int(file_count)),
                source_roots,
                time.time(),
            ),
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
