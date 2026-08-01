from __future__ import annotations

import os
import platform
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from database.metadata_db import MetadataDatabase
from entropy_loader import build_entropy_cache
from monitor.filesystem_monitor import FileSystemMonitor
from monitor.filesystem_monitor import ProcessBehaviorTracker, ProcessMetadata
from monitor.windows_entropy_simulator import SafeEntropyChangeSimulator
from startup_worker import StartupWorker


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


class SafeWindowsEntropySimulatorTests(unittest.TestCase):
    def test_simulator_stays_in_sandbox_and_cleans_up(self):
        simulator = SafeEntropyChangeSimulator(file_count=20, preserve_directory=False, seed=99)
        root = simulator.create_sandbox()
        created = simulator.create_low_entropy_baseline_files()
        modified = simulator.modify_files_high_entropy(count=20)
        simulator.assert_all_touches_inside_sandbox()

        self.assertEqual(len(created), 20)
        self.assertEqual(len(modified), 20)
        self.assertTrue(root.exists())

        simulator.cleanup()
        self.assertFalse(root.exists())


class ValidationBasedEntropyWindowsTests(unittest.TestCase):
    @staticmethod
    def _norm(path: Path | str) -> str:
        return os.path.normcase(os.path.realpath(str(path)))

    def _build_tracker(self, metadata_db: MetadataDatabase) -> ProcessBehaviorTracker:
        with patch("monitor.filesystem_monitor.get_metadata_db", return_value=metadata_db):
            tracker = ProcessBehaviorTracker(_DummyLogger())
        self.addCleanup(tracker._metadata_db.close)
        return tracker

    @staticmethod
    def _proc(pid: int = 9001) -> ProcessMetadata:
        return ProcessMetadata(
            pid=pid,
            name="powershell.exe",
            executable=r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            parent_name="explorer.exe",
            start_time="2026-08-01 10:00:00",
            start_time_epoch=time.time() - 120,
        )

    @staticmethod
    def _write_file(path: Path, payload: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)

    @staticmethod
    def _config() -> SimpleNamespace:
        return SimpleNamespace(entropy=SimpleNamespace(file_extensions=["txt"], sample_size_bytes=1024))

    def _startup_baseline_with_worker(self, metadata_db: MetadataDatabase, entropy_root: Path) -> dict:
        worker = StartupWorker(entropy_dir=entropy_root, file_monitor_dir=entropy_root)
        ctx = {
            "config": self._config(),
            "metadata_db": metadata_db,
        }
        worker._step_build_entropy(ctx)
        baseline = metadata_db.get_runtime_entropy_baseline()
        self.assertIsNotNone(baseline)
        return {
            "initial_average_entropy": baseline["initial_average_entropy"],
            "initial_max_entropy": baseline["initial_max_entropy"],
            "baseline_file_count": baseline["baseline_file_count"],
        }

    def test_startup_persists_initial_average_and_max_entropy_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            simulator = SafeEntropyChangeSimulator(file_count=25, preserve_directory=False, seed=123)
            try:
                simulator_root = simulator.create_sandbox()
                created = simulator.create_low_entropy_baseline_files()
                self.assertGreaterEqual(len(created), 20)

                metadata_db = MetadataDatabase(root / "metadata.db")
                self.addCleanup(metadata_db.close)
                baseline = self._startup_baseline_with_worker(metadata_db, simulator_root)
                self.assertIsNotNone(baseline["initial_average_entropy"])
                self.assertIsNotNone(baseline["initial_max_entropy"])
                self.assertGreaterEqual(
                    baseline["initial_max_entropy"] + 1e-12,
                    baseline["initial_average_entropy"],
                )
                self.assertGreaterEqual(baseline["baseline_file_count"], 20)
            finally:
                simulator.cleanup()

    def test_startup_build_reuses_cached_entropy_for_unchanged_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "stable.txt"
            self._write_file(target, b"RDRS_STABLE" * 512)

            metadata_db = MetadataDatabase(root / "metadata.db")
            self.addCleanup(metadata_db.close)

            with patch("entropy_loader.calculate_entropy", return_value=4.25) as entropy_mock:
                first = build_entropy_cache(
                    metadata_db=metadata_db,
                    roots=[root],
                    allowed_extensions={"txt"},
                    sample_size_bytes=1024,
                )
                second = build_entropy_cache(
                    metadata_db=metadata_db,
                    roots=[root],
                    allowed_extensions={"txt"},
                    sample_size_bytes=1024,
                )

            self.assertEqual(entropy_mock.call_count, 1)
            self.assertEqual(first.processed_files, 1)
            self.assertEqual(second.processed_files, 1)

    def test_no_entropy_calculation_before_score_50(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata_db = MetadataDatabase(root / "metadata.db")
            self.addCleanup(metadata_db.close)
            metadata_db.set_runtime_entropy_baseline(
                initial_average_entropy=3.0,
                initial_max_entropy=7.5,
                baseline_file_count=10,
                source_roots=str(root),
            )
            tracker = self._build_tracker(metadata_db)

            file_path = root / "single" / "doc.txt"
            self._write_file(file_path, b"hello world")

            with patch("monitor.filesystem_monitor.calculate_entropy") as entropy_mock:
                record = None
                for _ in range(5):
                    record = tracker.record_event("FILE MODIFIED", str(file_path), self._proc())

            self.assertIsNotNone(record)
            self.assertLess(record.score, 50)
            self.assertEqual(entropy_mock.call_count, 0)
            self.assertNotIn("EntropyIncrease", record.active_rules)

    def test_score_50_triggers_validation_once_per_crossing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata_db = MetadataDatabase(root / "metadata.db")
            self.addCleanup(metadata_db.close)
            metadata_db.set_runtime_entropy_baseline(
                initial_average_entropy=1.0,
                initial_max_entropy=2.0,
                baseline_file_count=8,
                source_roots=str(root),
            )
            tracker = self._build_tracker(metadata_db)

            files = []
            for idx in range(12):
                directory = "a" if idx % 2 == 0 else "b"
                target = root / directory / f"f{idx}.txt"
                self._write_file(target, os.urandom(2048))
                files.append(target)

            with patch("monitor.filesystem_monitor.calculate_entropy", return_value=7.8) as entropy_mock:
                for idx in range(11):
                    tracker.record_event("FILE MODIFIED", str(files[idx]), self._proc())
                calls_after_crossing = entropy_mock.call_count
                self.assertGreater(calls_after_crossing, 0)

                # Still above threshold: should not re-trigger entropy validation.
                for idx in range(11, 12):
                    tracker.record_event("FILE MODIFIED", str(files[idx]), self._proc())

            self.assertEqual(entropy_mock.call_count, calls_after_crossing)

    def test_validation_uses_exactly_last_10_modified_unique_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata_db = MetadataDatabase(root / "metadata.db")
            self.addCleanup(metadata_db.close)
            metadata_db.set_runtime_entropy_baseline(
                initial_average_entropy=1.0,
                initial_max_entropy=2.0,
                baseline_file_count=10,
                source_roots=str(root),
            )
            tracker = self._build_tracker(metadata_db)

            files = []
            for idx in range(15):
                directory = "left" if idx % 2 == 0 else "right"
                target = root / directory / f"doc_{idx}.txt"
                self._write_file(target, os.urandom(2048))
                files.append(target)

            with patch("monitor.filesystem_monitor.calculate_entropy", return_value=7.9) as entropy_mock:
                for idx in range(11):
                    tracker.record_event("FILE MODIFIED", str(files[idx]), self._proc())

            selected_paths = [self._norm(call.args[0]) for call in entropy_mock.call_args_list]
            self.assertEqual(len(selected_paths), 10)
            expected = [self._norm(path) for path in reversed(files[1:11])]
            self.assertEqual(selected_paths, expected)

    def test_validation_file_selection_is_process_local_not_global(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata_db = MetadataDatabase(root / "metadata.db")
            self.addCleanup(metadata_db.close)
            metadata_db.set_runtime_entropy_baseline(
                initial_average_entropy=1.0,
                initial_max_entropy=2.0,
                baseline_file_count=10,
                source_roots=str(root),
            )
            tracker = self._build_tracker(metadata_db)

            files_a = []
            files_b = []
            for idx in range(12):
                a_path = root / "proc_a" / f"a_{idx}.txt"
                b_path = root / "proc_b" / f"b_{idx}.txt"
                self._write_file(a_path, os.urandom(2048))
                self._write_file(b_path, os.urandom(2048))
                files_a.append(a_path)
                files_b.append(b_path)

            proc_a = self._proc(pid=501)
            proc_b = self._proc(pid=777)
            with patch("monitor.filesystem_monitor.calculate_entropy", return_value=7.6) as entropy_mock:
                for idx in range(3):
                    tracker.record_event("FILE MODIFIED", str(files_b[idx]), proc_b)
                for idx in range(11):
                    tracker.record_event("FILE MODIFIED", str(files_a[idx]), proc_a)

            selected_paths = {self._norm(call.args[0]) for call in entropy_mock.call_args_list}
            proc_a_paths = {self._norm(path) for path in files_a}
            proc_b_paths = {self._norm(path) for path in files_b}
            self.assertTrue(selected_paths.issubset(proc_a_paths))
            self.assertFalse(selected_paths.intersection(proc_b_paths))

    def test_validation_handles_fewer_than_10_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata_db = MetadataDatabase(root / "metadata.db")
            self.addCleanup(metadata_db.close)
            metadata_db.set_runtime_entropy_baseline(
                initial_average_entropy=1.0,
                initial_max_entropy=2.0,
                baseline_file_count=10,
                source_roots=str(root),
            )
            tracker = self._build_tracker(metadata_db)

            proc = self._proc()
            only_files = []
            for idx in range(4):
                target = root / ("a" if idx % 2 == 0 else "b") / f"few_{idx}.txt"
                self._write_file(target, os.urandom(2048))
                only_files.append(target)

            with patch("monitor.filesystem_monitor.calculate_entropy", return_value=7.8) as entropy_mock:
                for idx in range(11):
                    tracker.record_event("FILE MODIFIED", str(only_files[idx % len(only_files)]), proc)

            self.assertLessEqual(entropy_mock.call_count, 4)
            self.assertGreater(entropy_mock.call_count, 0)

    def test_higher_modified_average_adds_entropy_score(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata_db = MetadataDatabase(root / "metadata.db")
            self.addCleanup(metadata_db.close)
            metadata_db.set_runtime_entropy_baseline(
                initial_average_entropy=2.0,
                initial_max_entropy=3.5,
                baseline_file_count=10,
                source_roots=str(root),
            )
            tracker = self._build_tracker(metadata_db)

            files = []
            for idx in range(11):
                target = root / ("d1" if idx % 2 == 0 else "d2") / f"hi_{idx}.txt"
                self._write_file(target, os.urandom(2048))
                files.append(target)

            record = None
            with patch("monitor.filesystem_monitor.calculate_entropy", return_value=7.9):
                for file_path in files:
                    record = tracker.record_event("FILE MODIFIED", str(file_path), self._proc())

            self.assertIsNotNone(record)
            self.assertIn("EntropyIncrease", record.active_rules)
            self.assertEqual(record.entropy_score_bonus, tracker._entropy_score_delta)

    def test_lower_or_equal_modified_average_does_not_add_entropy_score(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata_db = MetadataDatabase(root / "metadata.db")
            self.addCleanup(metadata_db.close)
            metadata_db.set_runtime_entropy_baseline(
                initial_average_entropy=6.5,
                initial_max_entropy=7.0,
                baseline_file_count=10,
                source_roots=str(root),
            )
            tracker = self._build_tracker(metadata_db)

            files = []
            for idx in range(11):
                target = root / ("x" if idx % 2 == 0 else "y") / f"lo_{idx}.txt"
                self._write_file(target, b"A" * 2048)
                files.append(target)

            record = None
            with patch("monitor.filesystem_monitor.calculate_entropy", return_value=6.5):
                for file_path in files:
                    record = tracker.record_event("FILE MODIFIED", str(file_path), self._proc())

            self.assertIsNotNone(record)
            self.assertNotIn("EntropyIncrease", record.active_rules)
            self.assertEqual(record.entropy_score_bonus, 0)

    def test_ghost_files_are_ignored_safely(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata_db = MetadataDatabase(root / "metadata.db")
            self.addCleanup(metadata_db.close)
            metadata_db.set_runtime_entropy_baseline(
                initial_average_entropy=1.0,
                initial_max_entropy=2.0,
                baseline_file_count=10,
                source_roots=str(root),
            )
            tracker = self._build_tracker(metadata_db)

            live_files = []
            for idx in range(8):
                target = root / ("live_a" if idx % 2 == 0 else "live_b") / f"live_{idx}.txt"
                self._write_file(target, os.urandom(2048))
                live_files.append(target)

            ghost_paths = [root / "ghost_a" / "missing_1.txt", root / "ghost_b" / "missing_2.txt", root / "ghost_c" / "missing_3.txt"]

            all_paths = live_files + ghost_paths
            proc = self._proc()
            with patch("monitor.filesystem_monitor.calculate_entropy", return_value=7.7) as entropy_mock:
                for idx in range(11):
                    path = all_paths[idx % len(all_paths)]
                    tracker.record_event("FILE MODIFIED", str(path), proc)

            self.assertLess(entropy_mock.call_count, 10)
            self.assertGreater(entropy_mock.call_count, 0)

    def test_files_changing_during_validation_do_not_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata_db = MetadataDatabase(root / "metadata.db")
            self.addCleanup(metadata_db.close)
            metadata_db.set_runtime_entropy_baseline(
                initial_average_entropy=1.0,
                initial_max_entropy=2.0,
                baseline_file_count=10,
                source_roots=str(root),
            )
            tracker = self._build_tracker(metadata_db)

            files = []
            for idx in range(11):
                target = root / ("busy_a" if idx % 2 == 0 else "busy_b") / f"busy_{idx}.txt"
                self._write_file(target, os.urandom(2048))
                files.append(target)

            record = None
            with patch.object(ProcessBehaviorTracker, "_wait_for_file_stable", side_effect=[None, None] + [object()] * 20):
                with patch("monitor.filesystem_monitor.calculate_entropy", return_value=7.8):
                    for file_path in files:
                        record = tracker.record_event("FILE MODIFIED", str(file_path), self._proc())

            self.assertIsNotNone(record)
            self.assertGreaterEqual(record.score, 50)

    @unittest.skipUnless(os.name == "nt", "Windows integration test is only executed on Windows hosts")
    def test_windows_integration_score50_entropy_validation_flow(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata_db = MetadataDatabase(root / "metadata.db")
            self.addCleanup(metadata_db.close)
            metadata_db.set_runtime_entropy_baseline(
                initial_average_entropy=2.5,
                initial_max_entropy=6.0,
                baseline_file_count=12,
                source_roots=str(root),
            )
            tracker = self._build_tracker(metadata_db)

            files = []
            for idx in range(12):
                target = root / ("w1" if idx % 2 == 0 else "w2") / f"win_{idx}.txt"
                self._write_file(target, os.urandom(2048))
                files.append(target)

            proc = self._proc(pid=4444)
            record = None
            with patch("monitor.filesystem_monitor.calculate_entropy", return_value=7.9):
                for file_path in files:
                    record = tracker.record_event("FILE MODIFIED", str(file_path), proc)

            self.assertIsNotNone(record)
            self.assertIn("EntropyIncrease", record.active_rules)
            self.assertEqual(record.entropy_score_bonus, tracker._entropy_score_delta)

    @unittest.skipUnless(os.name == "nt", "Windows runtime simulation runs only on Windows hosts")
    def test_windows_runtime_simulator_against_monitor_pipeline(self):
        simulator = SafeEntropyChangeSimulator(file_count=25, preserve_directory=True, seed=2026)
        root = simulator.create_sandbox()
        simulator.create_low_entropy_baseline_files()

        with tempfile.TemporaryDirectory() as tmpdb:
            metadata_db = MetadataDatabase(Path(tmpdb) / "metadata.db")
            self.addCleanup(metadata_db.close)
            baseline = self._startup_baseline_with_worker(metadata_db, root)

            logger = _DummyLogger()
            with patch("monitor.filesystem_monitor.get_metadata_db", return_value=metadata_db):
                monitor = FileSystemMonitor(
                    target_path=root,
                    recursive=True,
                    logger=logger,
                    event_callback=None,
                )

            entropy_hits = []
            original_log = monitor.behavior_tracker._log_legacy_detection

            def _capture_entropy(record, rule_name, reason, score):
                if rule_name == "EntropyIncrease":
                    entropy_hits.append((record.pid, score, reason))
                return original_log(record, rule_name, reason, score)

            monitor.behavior_tracker._log_legacy_detection = _capture_entropy

            try:
                monitor.start()
                time.sleep(0.6)

                modified = simulator.modify_files_high_entropy(count=25)
                self.assertEqual(len(modified), 25)
                time.sleep(2.5)

                states = list(monitor.behavior_tracker.records.values())
                self.assertTrue(states)
                max_state = max(states, key=lambda state: state.score)
                self.assertGreaterEqual(max_state.score, 50)
                self.assertTrue(baseline["initial_average_entropy"] is not None)

                if max_state.entropy_score_bonus > 0:
                    self.assertEqual(max_state.entropy_score_bonus, monitor.behavior_tracker._entropy_score_delta)
                    self.assertLessEqual(len(entropy_hits), 1)
            finally:
                monitor.stop()
                simulator.assert_all_touches_inside_sandbox()
                simulator.cleanup()

        self.assertFalse(root.exists())


class WindowsRuntimeMetadataSnapshotTest(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Metadata snapshot is collected only on Windows hosts")
    def test_print_runtime_environment_snapshot(self):
        print(f"OS version: {platform.platform()}")
        print(f"Python version: {sys.version}")


if __name__ == "__main__":
    unittest.main()
