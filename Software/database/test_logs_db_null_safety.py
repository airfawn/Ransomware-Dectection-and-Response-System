from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from database.logs_db import LogsDatabase


class LogsDatabaseNullSafetyTests(unittest.TestCase):
    def test_log_event_normalizes_required_columns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = LogsDatabase(Path(tmp) / "logs.db")
            self.addCleanup(db.close)

            db.log_event(
                event_type=None,
                file_path=None,
                file_name=None,
                process=None,
                pid=None,
                executable=None,
                parent=None,
            )

            rows = db.get_recent(limit=1)
            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertEqual(row["event_type"], "UNKNOWN")
            self.assertEqual(row["file_path"], "")
            self.assertEqual(row["file_name"], "(unknown)")

    def test_log_events_batch_normalizes_required_columns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = LogsDatabase(Path(tmp) / "logs.db")
            self.addCleanup(db.close)

            db.log_events_batch(
                [
                    {
                        "event_type": None,
                        "file_path": None,
                        "file_name": None,
                    }
                ]
            )

            rows = db.get_recent(limit=1)
            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertEqual(row["event_type"], "UNKNOWN")
            self.assertEqual(row["file_path"], "")
            self.assertEqual(row["file_name"], "(unknown)")


if __name__ == "__main__":
    unittest.main()
