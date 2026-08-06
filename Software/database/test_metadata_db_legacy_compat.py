from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from database.metadata_db import MetadataDatabase


class MetadataDatabaseLegacyCompatibilityTests(unittest.TestCase):
    def test_set_runtime_entropy_baseline_supports_legacy_not_null_computed_at(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "metadata.db"

            conn = sqlite3.connect(str(db_path))
            conn.execute(
                """
                CREATE TABLE entropy_runtime_baseline (
                    id                       INTEGER PRIMARY KEY CHECK (id = 1),
                    initial_average_entropy  REAL,
                    initial_max_entropy      REAL,
                    baseline_file_count      INTEGER NOT NULL DEFAULT 0,
                    source_roots             TEXT,
                    computed_at              REAL NOT NULL
                );
                """
            )
            conn.commit()
            conn.close()

            metadata_db = MetadataDatabase(db_path)
            self.addCleanup(metadata_db.close)

            metadata_db.set_runtime_entropy_baseline(
                average_entropy=3.84,
                file_count=500,
                source_roots="/tmp/scope",
            )

            row = metadata_db.get_runtime_entropy_baseline()
            self.assertIsNotNone(row)
            self.assertAlmostEqual(float(row["average_entropy"]), 3.84)
            self.assertEqual(int(row["file_count"]), 500)

            # Legacy alias columns should stay populated for old readers.
            self.assertAlmostEqual(float(row["initial_average_entropy"]), 3.84)
            self.assertEqual(int(row["baseline_file_count"]), 500)

            # Critical regression guard: old NOT NULL column must still be set.
            self.assertIsNotNone(row["computed_at"])


if __name__ == "__main__":
    unittest.main()
