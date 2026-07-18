import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from database.alerts_db import AlertsDatabase
from database.logs_db import LogsDatabase
from database.metadata_db import MetadataDatabase
from entropy.loader import build_entropy_cache
from entropy.monitor import EntropyMonitor
from monitor.filesystem_monitor import FileSystemMonitorHandler, ProcessMetadata, ProcessResolver


class _DummyLogger:
    def info(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        pass

    def error(self, *args, **kwargs):
        pass

    def debug(self, *args, **kwargs):
        pass


class _DummyTracker:
    def __init__(self):
        self.events = []

    def record_event(self, event_type, src_path, process_metadata, previous_path=None):
        self.events.append((event_type, src_path, process_metadata, previous_path))
        return None


class _DummyEvent:
    def __init__(self, src_path, dest_path=None, is_directory=False):
        self.src_path = src_path
        self.dest_path = dest_path or src_path
        self.is_directory = is_directory


class WindowsPipelineValidationTest(unittest.TestCase):
    def test_handler_emits_all_event_types_and_previous_path(self):
        tracker = _DummyTracker()
        handler = FileSystemMonitorHandler(_DummyLogger(), tracker)
        handler._process_resolver.resolve = lambda path, **kwargs: ProcessMetadata(
            pid=1234,
            name="python.exe",
            executable="C:\\Python\\python.exe",
            parent_name="cmd.exe",
            start_time="2026-07-16 10:00:00",
            start_time_epoch=1.0,
        )

        captured = []

        def callback(event_type, file_path, process_name, pid, executable, parent, previous_path=None):
            captured.append((event_type, file_path, process_name, pid, executable, parent, previous_path))

        handler._event_callback = callback

        handler.on_created(_DummyEvent(r"C:\temp\created.txt"))
        handler.on_modified(_DummyEvent(r"C:\temp\created.txt"))
        handler.on_deleted(_DummyEvent(r"C:\temp\created.txt"))
        handler.on_moved(_DummyEvent(r"C:\temp\old.txt", dest_path=r"C:\temp\new.txt"))

        self.assertEqual([item[0] for item in captured], ["FILE CREATED", "FILE MODIFIED", "FILE DELETED", "FILE MOVED"])
        self.assertEqual(captured[-1][-1], r"C:\temp\old.txt")
        self.assertEqual(len(tracker.events), 4)
        self.assertEqual(tracker.events[-1][-1], r"C:\temp\old.txt")

    def test_process_resolver_reuses_directory_and_previous_path_cache(self):
        resolver = ProcessResolver()
        metadata = ProcessMetadata(
            pid=4321,
            name="powershell.exe",
            executable="/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
            parent_name="explorer.exe",
            start_time="2026-07-16 11:00:00",
            start_time_epoch=2.0,
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            resolver.remember(root / "sample.txt", metadata)

            directory_hit = resolver.resolve(root / "other.txt")
            previous_hit = resolver.resolve(root / "deleted.txt", previous_path=root / "sample.txt", event_type="FILE DELETED")

            self.assertEqual(directory_hit.pid, 4321)
            self.assertEqual(previous_hit.executable, metadata.executable)
        self.assertEqual(directory_hit.pid, 4321)
        self.assertEqual(previous_hit.executable, metadata.executable)

    def test_entropy_cache_reuse_and_delta_update(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data_file = root / "sample.txt"
            data_file.write_text("hello world\n", encoding="utf-8")

            metadata_db = MetadataDatabase(root / "metadata.db")
            logs_db = LogsDatabase(root / "logs.db")
            alerts_db = AlertsDatabase(root / "alerts.db")

            monitor = EntropyMonitor(
                metadata_db=metadata_db,
                logs_db=logs_db,
                alerts_db=alerts_db,
                allowed_extensions={"txt"},
                monitored_roots=[root],
                threshold=1.0,
            )

            with patch("entropy.monitor.calculate_entropy", side_effect=[1.25, 7.75]) as entropy_mock:
                monitor._scan_file_for_cache(data_file)
                monitor._scan_file_for_cache(data_file)
                self.assertEqual(entropy_mock.call_count, 1)

                data_file.write_text("".join(chr(i % 26 + 65) for i in range(4096)), encoding="utf-8")
                os.utime(data_file, None)
                monitor._scan_file_for_cache(data_file)
                self.assertEqual(entropy_mock.call_count, 2)

            row = metadata_db.get_entropy_record(str(data_file))
            self.assertIsNotNone(row)
            self.assertTrue(row["exists"])
            self.assertAlmostEqual(row["entropy"], 7.75)

            legacy = metadata_db.get_file(str(data_file))
            self.assertIsNotNone(legacy)
            self.assertAlmostEqual(legacy["current_entropy"], 7.75)
            self.assertAlmostEqual(legacy["previous_entropy"], 1.25)

            monitor.stop()
            metadata_db.close()
            logs_db.close()
            alerts_db.close()

    def test_build_entropy_cache_rebuilds_from_filesystem_and_removes_deleted_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            keep_file = root / "keep.txt"
            keep_file.write_text("keep me", encoding="utf-8")

            metadata_db = MetadataDatabase(root / "metadata.db")
            try:
                summary = build_entropy_cache(
                    metadata_db=metadata_db,
                    roots=[root],
                    allowed_extensions={"txt"},
                    sample_size_bytes=1024,
                )
                self.assertEqual(summary.total_files, 1)
                self.assertIsNotNone(metadata_db.get_file(str(keep_file)))

                keep_file.unlink()
                new_file = root / "new.txt"
                new_file.write_text("brand new", encoding="utf-8")

                summary = build_entropy_cache(
                    metadata_db=metadata_db,
                    roots=[root],
                    allowed_extensions={"txt"},
                    sample_size_bytes=1024,
                )

                self.assertIsNone(metadata_db.get_file(str(keep_file)))
                self.assertIsNotNone(metadata_db.get_file(str(new_file)))
                self.assertEqual(summary.total_files, 1)
            finally:
                metadata_db.close()

    def test_modified_file_events_force_entropy_recalculation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data_file = root / "sample.txt"
            data_file.write_text("hello world\n", encoding="utf-8")

            metadata_db = MetadataDatabase(root / "metadata.db")
            logs_db = LogsDatabase(root / "logs.db")
            alerts_db = AlertsDatabase(root / "alerts.db")
            monitor = EntropyMonitor(
                metadata_db=metadata_db,
                logs_db=logs_db,
                alerts_db=alerts_db,
                allowed_extensions={"txt"},
                monitored_roots=[root],
                threshold=1.0,
            )
            metadata_db.upsert_entropy_cache(path=str(data_file), entropy=1.0, file_size=data_file.stat().st_size, modified_time=data_file.stat().st_mtime, exists=True)
            metadata_db.upsert_file(file_path=str(data_file), file_name=data_file.name, current_entropy=1.0, previous_entropy=None, file_size=data_file.stat().st_size, last_modified_ts=data_file.stat().st_mtime)

            try:
                with patch("entropy.monitor.calculate_entropy", return_value=4.25) as entropy_mock:
                    monitor._process_event(
                        type("Evt", (), {"event_type": "FILE MODIFIED", "file_path": str(data_file), "previous_path": None, "process_name": None, "pid": None, "executable": None, "parent": None})
                    )
                self.assertEqual(entropy_mock.call_count, 1)
            finally:
                monitor.stop()
                metadata_db.close()
                logs_db.close()
                alerts_db.close()

    def test_burst_queue_coalesces_duplicate_modification_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data_file = root / "sample.txt"
            data_file.write_text("hello world\n", encoding="utf-8")

            class DummyTracker:
                def __init__(self):
                    self.events = []

                def record_event(self, event_type, src_path, process_metadata, previous_path=None):
                    self.events.append((event_type, src_path, previous_path))

            tracker = DummyTracker()
            handler = FileSystemMonitorHandler(_DummyLogger(), tracker)
            handler._process_resolver.resolve = lambda path, **kwargs: ProcessMetadata(
                pid=111,
                name="python.exe",
                executable="C:/python/python.exe",
                parent_name=None,
                start_time=None,
                start_time_epoch=None,
            )

            handler._report_event("FILE MODIFIED", str(data_file))
            handler._report_event("FILE MODIFIED", str(data_file))

            self.assertEqual(len(handler._queued_event_keys), 1)
            time.sleep(0.15)
            self.assertEqual(len(tracker.events), 1)


if __name__ == "__main__":
    unittest.main()
