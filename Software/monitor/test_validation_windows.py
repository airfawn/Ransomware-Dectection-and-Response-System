from __future__ import annotations

import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from database.metadata_db import MetadataDatabase
from entropy.calculator import calculate_entropy
from entropy_loader import build_entropy_cache
from monitor.filesystem_monitor import ProcessBehaviorTracker, ProcessMetadata


class _DummyLogger:
    def info(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        pass

    def error(self, *args, **kwargs):
        pass

    def debug(self, *args, **kwargs):
        pass

    def exception(self, *args, **kwargs):
        pass


class EntropyValidationArchitectureTests(unittest.TestCase):
    def _proc(self, pid: int = 9001) -> ProcessMetadata:
        return ProcessMetadata(
            pid=pid,
            name="python",
            executable="/usr/bin/python",
            parent_name="zsh",
            start_time="2026-08-01 10:00:00",
            start_time_epoch=time.time() - 120,
        )

    @staticmethod
    def _write_bytes(path: Path, payload: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)

    def _new_tracker(self, metadata_db: MetadataDatabase) -> ProcessBehaviorTracker:
        with patch("monitor.filesystem_monitor.get_metadata_db", return_value=metadata_db):
            tracker = ProcessBehaviorTracker(logger=_DummyLogger())
        tracker._wait_for_file_stable = lambda path: path.stat()  # type: ignore[method-assign]
        return tracker

    def _trigger_with_11_modifications(
        self,
        tracker: ProcessBehaviorTracker,
        files: list[Path],
        *,
        proc: ProcessMetadata,
    ):
        record = None
        for file_path in files[:11]:
            record = tracker.record_event("FILE MODIFIED", str(file_path), proc)
        return record

    def test_01_startup_baseline_stores_aggregate_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for i in range(20):
                self._write_bytes(root / f"doc_{i}.txt", b"A" * 2048)

            metadata_db = MetadataDatabase(root / "metadata.db")
            self.addCleanup(metadata_db.close)

            summary = build_entropy_cache(
                metadata_db=metadata_db,
                roots=[root],
                allowed_extensions={"txt"},
                sample_size_bytes=5 * 1024 * 1024,
            )

            baseline = metadata_db.get_runtime_entropy_baseline()
            self.assertIsNotNone(baseline)
            self.assertIsNotNone(baseline["average_entropy"])
            self.assertEqual(int(baseline["file_count"]), summary.processed_files)

            legacy = metadata_db.fetchall(
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('file_metadata', 'entropy_cache')"
            )
            self.assertEqual(len(legacy), 0)

    def test_02_normal_monitoring_below_threshold_does_not_calculate_entropy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata_db = MetadataDatabase(root / "metadata.db")
            self.addCleanup(metadata_db.close)
            metadata_db.set_runtime_entropy_baseline(average_entropy=3.0, file_count=12, source_roots=str(root))

            tracker = self._new_tracker(metadata_db)
            target = root / "single" / "file.txt"
            self._write_bytes(target, b"normal content")

            with patch("monitor.filesystem_monitor.calculate_entropy") as entropy_mock:
                record = None
                for _ in range(5):
                    record = tracker.record_event("FILE MODIFIED", str(target), self._proc())

            self.assertIsNotNone(record)
            self.assertLess(record.score, 50)
            self.assertEqual(entropy_mock.call_count, 0)

    def test_03_score_50_triggers_validation_immediately(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata_db = MetadataDatabase(root / "metadata.db")
            self.addCleanup(metadata_db.close)
            metadata_db.set_runtime_entropy_baseline(average_entropy=1.0, file_count=20, source_roots=str(root))
            tracker = self._new_tracker(metadata_db)

            files = []
            for i in range(12):
                sub = "a" if i % 2 == 0 else "b"
                path = root / sub / f"f_{i}.txt"
                self._write_bytes(path, os.urandom(2048))
                files.append(path)

            triggered = False
            with patch("monitor.filesystem_monitor.calculate_entropy", return_value=7.8) as entropy_mock:
                record = None
                previous = 0
                for path in files[:11]:
                    record = tracker.record_event("FILE MODIFIED", str(path), self._proc())
                    if previous < 50 <= record.score:
                        triggered = True
                        self.assertGreater(entropy_mock.call_count, 0)
                    previous = record.score

            self.assertTrue(triggered)
            self.assertIsNotNone(record)
            self.assertGreaterEqual(record.score, 50)

    def test_04_trigger_scans_only_last_10_unique_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata_db = MetadataDatabase(root / "metadata.db")
            self.addCleanup(metadata_db.close)
            metadata_db.set_runtime_entropy_baseline(average_entropy=1.0, file_count=20, source_roots=str(root))
            tracker = self._new_tracker(metadata_db)

            files = []
            for i in range(51):
                sub = "a" if i % 2 == 0 else "b"
                path = root / sub / f"bulk_{i}.txt"
                self._write_bytes(path, os.urandom(2048))
                files.append(path)

            proc = self._proc(pid=333)
            tracker._entropy_trigger_score = 999
            for path in files[:50]:
                tracker.record_event("FILE MODIFIED", str(path), proc)

            tracker._entropy_trigger_score = 50
            with patch("monitor.filesystem_monitor.calculate_entropy", return_value=7.9) as entropy_mock:
                tracker.record_event("FILE MODIFIED", str(files[50]), proc)

            scanned = [os.path.normcase(os.path.realpath(str(call.args[0]))) for call in entropy_mock.call_args_list]
            self.assertEqual(len(scanned), 10)
            expected = [os.path.normcase(os.path.realpath(str(p))) for p in reversed(files[41:51])]
            self.assertEqual(scanned, expected)

    def test_05_validation_reads_current_bytes_and_detects_entropy_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline_root = root / "baseline"
            for i in range(20):
                self._write_bytes(baseline_root / f"base_{i}.txt", b"A" * 4096)

            metadata_db = MetadataDatabase(root / "metadata.db")
            self.addCleanup(metadata_db.close)
            build_entropy_cache(
                metadata_db=metadata_db,
                roots=[baseline_root],
                allowed_extensions={"txt"},
                sample_size_bytes=5 * 1024 * 1024,
            )

            baseline_row = metadata_db.get_runtime_entropy_baseline()
            self.assertIsNotNone(baseline_row)
            startup_avg = float(baseline_row["average_entropy"])

            tracker = self._new_tracker(metadata_db)
            files = []
            for i in range(11):
                sub = "x" if i % 2 == 0 else "y"
                path = root / sub / f"live_{i}.txt"
                self._write_bytes(path, b"A" * 4096)
                files.append(path)

            low_entropy = calculate_entropy(files[0], 5 * 1024 * 1024)
            self._write_bytes(files[0], os.urandom(4096))
            high_entropy = calculate_entropy(files[0], 5 * 1024 * 1024)
            self.assertIsNotNone(low_entropy)
            self.assertIsNotNone(high_entropy)
            self.assertGreater(high_entropy, low_entropy)

            for path in files[1:]:
                self._write_bytes(path, os.urandom(4096))

            record = self._trigger_with_11_modifications(tracker, files, proc=self._proc(pid=500))
            self.assertIsNotNone(record)

            validation = metadata_db.get_last_entropy_validation()
            self.assertIsNotNone(validation)
            validation_avg = float(validation["validation_average_entropy"])
            self.assertGreater(validation_avg, startup_avg)
            self.assertEqual(int(validation["score_delta"]), 30)

    def test_06_entropy_scoring_rule_plus30_or_plus0(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            high_base_db = MetadataDatabase(root / "high.db")
            self.addCleanup(high_base_db.close)
            high_base_db.set_runtime_entropy_baseline(average_entropy=7.0, file_count=10, source_roots=str(root))
            high_tracker = self._new_tracker(high_base_db)
            high_files = []
            for i in range(11):
                d = "high_a" if i % 2 == 0 else "high_b"
                p = root / d / f"h_{i}.txt"
                self._write_bytes(p, b"A" * 1024)
                high_files.append(p)
            with patch("monitor.filesystem_monitor.calculate_entropy", return_value=6.0):
                high_record = self._trigger_with_11_modifications(high_tracker, high_files, proc=self._proc(pid=701))
            self.assertEqual(high_record.entropy_score_bonus, 0)

            low_base_db = MetadataDatabase(root / "low.db")
            self.addCleanup(low_base_db.close)
            low_base_db.set_runtime_entropy_baseline(average_entropy=2.0, file_count=10, source_roots=str(root))
            low_tracker = self._new_tracker(low_base_db)
            low_files = []
            for i in range(11):
                d = "low_a" if i % 2 == 0 else "low_b"
                p = root / d / f"l_{i}.txt"
                self._write_bytes(p, os.urandom(1024))
                low_files.append(p)
            with patch("monitor.filesystem_monitor.calculate_entropy", return_value=7.0):
                low_record = self._trigger_with_11_modifications(low_tracker, low_files, proc=self._proc(pid=702))
            self.assertEqual(low_record.entropy_score_bonus, 30)

    def test_07_validation_does_not_overwrite_startup_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata_db = MetadataDatabase(root / "metadata.db")
            self.addCleanup(metadata_db.close)
            metadata_db.set_runtime_entropy_baseline(average_entropy=3.84, file_count=500, source_roots=str(root))

            tracker = self._new_tracker(metadata_db)
            files = []
            for i in range(11):
                p = root / ("u" if i % 2 == 0 else "v") / f"f_{i}.txt"
                self._write_bytes(p, os.urandom(4096))
                files.append(p)

            with patch("monitor.filesystem_monitor.calculate_entropy", return_value=7.8):
                self._trigger_with_11_modifications(tracker, files, proc=self._proc(pid=777))

            baseline = metadata_db.get_runtime_entropy_baseline()
            self.assertIsNotNone(baseline)
            self.assertAlmostEqual(float(baseline["average_entropy"]), 3.84)
            self.assertEqual(int(baseline["file_count"]), 500)

    def test_08_restart_creates_new_startup_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata_db = MetadataDatabase(root / "metadata.db")
            self.addCleanup(metadata_db.close)

            run1 = root / "run1"
            run2 = root / "run2"
            for i in range(10):
                self._write_bytes(run1 / f"r1_{i}.txt", b"A" * 4096)
                self._write_bytes(run2 / f"r2_{i}.txt", os.urandom(4096))

            build_entropy_cache(
                metadata_db=metadata_db,
                roots=[run1],
                allowed_extensions={"txt"},
                sample_size_bytes=5 * 1024 * 1024,
            )
            first = metadata_db.get_runtime_entropy_baseline()
            self.assertIsNotNone(first)
            first_avg = float(first["average_entropy"])
            first_created = float(first["created_at"])

            time.sleep(0.01)
            build_entropy_cache(
                metadata_db=metadata_db,
                roots=[run2],
                allowed_extensions={"txt"},
                sample_size_bytes=5 * 1024 * 1024,
            )
            second = metadata_db.get_runtime_entropy_baseline()
            self.assertIsNotNone(second)
            second_avg = float(second["average_entropy"])
            second_created = float(second["created_at"])

            self.assertNotEqual(first_avg, second_avg)
            self.assertGreater(second_created, first_created)


if __name__ == "__main__":
    unittest.main()
