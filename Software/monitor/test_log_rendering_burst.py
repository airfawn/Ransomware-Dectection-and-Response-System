import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from database.metadata_db import MetadataDatabase
from monitor.filesystem_monitor import ProcessBehaviorTracker, ProcessMetadata


class _CountingLogger:
    def __init__(self):
        self.process_state_count = 0
        self.detection_count = 0

    def info(self, msg, *args, **kwargs):
        text = msg % args if args else str(msg)
        if "[ProcessState]" in text:
            self.process_state_count += 1
        if "[Detection]" in text:
            self.detection_count += 1

    def warning(self, *args, **kwargs):
        pass

    def error(self, *args, **kwargs):
        pass

    def debug(self, *args, **kwargs):
        pass

    def exception(self, *args, **kwargs):
        pass


class LogRenderingBurstRegressionTests(unittest.TestCase):
    def _proc(self, pid=4242):
        return ProcessMetadata(
            pid=pid,
            name="python",
            executable="/usr/bin/python",
            parent_name="zsh",
            start_time="2026-08-01 10:00:00",
            start_time_epoch=time.time() - 120,
        )

    def test_process_state_logging_is_throttled_but_score_changes_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata_db = MetadataDatabase(root / "metadata.db")
            self.addCleanup(metadata_db.close)
            metadata_db.set_runtime_entropy_baseline(average_entropy=3.0, file_count=20, source_roots=str(root))

            logger = _CountingLogger()
            with patch("monitor.filesystem_monitor.get_metadata_db", return_value=metadata_db):
                tracker = ProcessBehaviorTracker(logger=logger)
            tracker._wait_for_file_stable = lambda path: path.stat()  # type: ignore[method-assign]

            proc = self._proc()
            files = []
            for i in range(600):
                path = root / f"group_{i % 5}" / f"f_{i}.txt"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"x")
                files.append(path)

            with patch("monitor.filesystem_monitor.calculate_entropy", return_value=7.0):
                for path in files:
                    tracker.record_event("FILE MODIFIED", str(path), proc)

            self.assertLess(logger.process_state_count, 600)
            self.assertGreater(logger.process_state_count, 0)

            state = tracker.get_process_state(proc)
            self.assertIsNotNone(state)
            self.assertGreaterEqual(state.score, 50)
            self.assertIn(state.classification, {"Suspicious", "Alert"})

    def test_stale_cleanup_removes_entropy_arm_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata_db = MetadataDatabase(root / "metadata.db")
            self.addCleanup(metadata_db.close)
            metadata_db.set_runtime_entropy_baseline(average_entropy=1.0, file_count=5, source_roots=str(root))

            logger = _CountingLogger()
            with patch("monitor.filesystem_monitor.get_metadata_db", return_value=metadata_db):
                tracker = ProcessBehaviorTracker(logger=logger)
            tracker._wait_for_file_stable = lambda path: path.stat()  # type: ignore[method-assign]

            proc = self._proc(pid=666)
            path = root / "d" / "f.txt"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"x")

            with patch("monitor.filesystem_monitor.calculate_entropy", return_value=7.0):
                for _ in range(12):
                    tracker.record_event("FILE MODIFIED", str(path), proc)

            self.assertGreaterEqual(len(tracker._entropy_validation_armed), 1)

            tracker._inactivity_threshold = 0.0
            tracker._cleanup_interval = 0.0
            tracker._last_cleanup_time = 0.0
            tracker._cleanup_stale_processes(time.time() + 10.0)

            self.assertEqual(len(tracker.records), 0)
            self.assertEqual(len(tracker._entropy_validation_armed), 0)


if __name__ == "__main__":
    unittest.main()
