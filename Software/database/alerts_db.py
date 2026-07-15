"""Alerts database access layer for RDRS.

Stores triggered alerts and suspicious-process records.  Unlike the logs
database this table is NOT automatically pruned — alerts are persistent.

Schema:
    alerts
        id              INTEGER PRIMARY KEY AUTOINCREMENT
        timestamp       REAL    NOT NULL   — epoch when alert was triggered
        alert_type      TEXT    NOT NULL   — e.g. ENTROPY_INCREASE, FILE_BURST, …
        process_name    TEXT
        pid             INTEGER
        executable      TEXT
        process_score   INTEGER
        triggered_rules TEXT               — comma-separated rule names
        file_path       TEXT               — relevant file (if applicable)
        previous_entropy REAL
        current_entropy  REAL
        entropy_delta    REAL
        notes           TEXT               — free-text description / reason
"""

from __future__ import annotations

import time
from typing import List, Optional

from database.base_db import BaseDatabase


class AlertsDatabase(BaseDatabase):
    """Access layer for the alerts SQLite database."""

    def _get_schema_sql(self) -> List[str]:
        return [
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp        REAL    NOT NULL,
                alert_type       TEXT    NOT NULL,
                process_name     TEXT,
                pid              INTEGER,
                executable       TEXT,
                process_score    INTEGER,
                triggered_rules  TEXT,
                file_path        TEXT,
                previous_entropy REAL,
                current_entropy  REAL,
                entropy_delta    REAL,
                notes            TEXT
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts (timestamp);",
            "CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts (alert_type);",
        ]

    # ------------------------------------------------------------------
    # Write operations
    # ------------------------------------------------------------------

    def log_alert(
        self,
        *,
        alert_type: str,
        process_name: Optional[str] = None,
        pid: Optional[int] = None,
        executable: Optional[str] = None,
        process_score: Optional[int] = None,
        triggered_rules: Optional[List[str]] = None,
        file_path: Optional[str] = None,
        previous_entropy: Optional[float] = None,
        current_entropy: Optional[float] = None,
        entropy_delta: Optional[float] = None,
        notes: Optional[str] = None,
        timestamp: Optional[float] = None,
    ) -> int:
        """Insert an alert record.

        Args:
            alert_type:       Short identifier, e.g. 'ENTROPY_INCREASE'.
            process_name:     Process name that triggered the alert.
            pid:              Process ID.
            executable:       Executable path.
            process_score:    Cumulative score at the time of the alert.
            triggered_rules:  List of rule names; stored as comma-joined string.
            file_path:        File path relevant to the alert.
            previous_entropy: Entropy before the event.
            current_entropy:  Entropy after the event.
            entropy_delta:    current - previous (negative if entropy dropped).
            notes:            Human-readable description.
            timestamp:        Epoch time; defaults to now.

        Returns:
            Row ID of the newly inserted alert.
        """
        ts = timestamp or time.time()
        rules_str = ", ".join(triggered_rules) if triggered_rules else None
        cursor = self.execute(
            """
            INSERT INTO alerts
                (timestamp, alert_type, process_name, pid, executable,
                 process_score, triggered_rules, file_path,
                 previous_entropy, current_entropy, entropy_delta, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ts,
                alert_type,
                process_name,
                pid,
                executable,
                process_score,
                rules_str,
                file_path,
                previous_entropy,
                current_entropy,
                entropy_delta,
                notes,
            ),
        )
        return cursor.lastrowid

    # ------------------------------------------------------------------
    # Read operations
    # ------------------------------------------------------------------

    def get_recent(self, limit: int = 200) -> list:
        """Return the most-recent alerts.

        Args:
            limit: Maximum number of rows.

        Returns:
            List of sqlite3.Row ordered newest-first.
        """
        return self.fetchall(
            "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )

    def get_by_type(self, alert_type: str, limit: int = 200) -> list:
        """Return alerts of a given type.

        Args:
            alert_type: e.g. 'ENTROPY_INCREASE'.
            limit:      Max rows.

        Returns:
            List of sqlite3.Row.
        """
        return self.fetchall(
            "SELECT * FROM alerts WHERE alert_type = ? ORDER BY timestamp DESC LIMIT ?",
            (alert_type, limit),
        )

    def count_alerts(self) -> int:
        """Return total number of stored alerts.

        Returns:
            Row count.
        """
        row = self.fetchone("SELECT COUNT(*) AS cnt FROM alerts")
        return row["cnt"] if row else 0
