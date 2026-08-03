import time
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from config import get_config
from monitor.filesystem_monitor import ProcessBehaviorTracker, ProcessMetadata
from database.metadata_db import MetadataDatabase


class FileSystemMonitorScoringTest(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._metadata_db = MetadataDatabase(Path(self._tmpdir.name) / "metadata.db")
        self._metadata_db.set_runtime_entropy_baseline(
            average_entropy=3.0,
            file_count=20,
            source_roots=self._tmpdir.name,
        )
        self._db_patcher = patch("monitor.filesystem_monitor.get_metadata_db", return_value=self._metadata_db)
        self._db_patcher.start()

        logger = type(
            "L",
            (),
            {
                "info": lambda *args, **kwargs: None,
                "error": lambda *args, **kwargs: None,
                "debug": lambda *args, **kwargs: None,
                "warning": lambda *args, **kwargs: None,
            },
        )()
        self.tracker = ProcessBehaviorTracker(logger=logger)
        self.meta = ProcessMetadata(
            pid=999,
            name="testproc",
            executable="/usr/bin/testproc",
            parent_name=None,
            start_time="now",
        )

    def tearDown(self):
        self._db_patcher.stop()
        self._metadata_db.close()
        self._tmpdir.cleanup()

    def test_high_operation_rate_activates_once(self):
        record = None
        for i in range(11):
            record = self.tracker.record_event("FILE CREATED", f"/tmp/test/file{i}.txt", self.meta)

        self.assertEqual(record.score, 20)
        self.assertEqual(record.active_rules, {"Rule1_FileBurst"})

        record = self.tracker.record_event("FILE MODIFIED", "/tmp/test/file11.txt", self.meta)
        self.assertEqual(record.score, 20)
        self.assertEqual(record.active_rules, {"Rule1_FileBurst"})

    def test_multiple_directories_rule_activates_based_on_window(self):
        record = self.tracker.record_event("FILE CREATED", "/tmp/a/file1.txt", self.meta)
        self.assertEqual(record.score, 0)
        self.assertEqual(record.active_rules, set())

        record = self.tracker.record_event("FILE CREATED", "/tmp/b/file2.txt", self.meta)
        self.assertEqual(record.score, 30)
        self.assertEqual(record.active_rules, {"Rule2_MultipleDirectories"})

    def test_rules_reset_after_window_expires(self):
        record = None
        for i in range(11):
            record = self.tracker.record_event("FILE MODIFIED", f"/tmp/test/file{i}.txt", self.meta)

        self.assertEqual(record.score, 20)
        time.sleep(1.1)
        record = self.tracker.record_event("FILE CREATED", "/tmp/test/file99.txt", self.meta)
        self.assertEqual(record.score, 0)
        self.assertEqual(record.active_rules, set())

    def test_young_process_bonus_applies_once(self):
        young_meta = ProcessMetadata(
            pid=1000,
            name="youngproc",
            executable="/usr/bin/youngproc",
            parent_name=None,
            start_time="2026-07-14 20:00:00",
            start_time_epoch=time.time() - 1200,
        )
        record = None
        for i in range(11):
            record = self.tracker.record_event("FILE CREATED", f"/tmp/young/file{i}.txt", young_meta)

        weights = get_config().detection.rule_weights
        expected_score = weights["Rule1_FileBurst"] + weights["Rule3_YoungProcessBurst"]
        self.assertEqual(record.score, expected_score)
        self.assertIn("Rule3_YoungProcessBurst", record.active_rules)
        self.assertIn("Rule1_FileBurst", record.active_rules)
        self.assertEqual(record.classification, "Suspicious")


if __name__ == "__main__":
    unittest.main()
