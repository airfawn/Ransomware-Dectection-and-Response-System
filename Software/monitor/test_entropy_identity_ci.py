import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from database.alerts_db import AlertsDatabase
from database.logs_db import LogsDatabase
from database.metadata_db import MetadataDatabase
from entropy.monitor import EntropyMonitor
from monitor.filesystem_monitor import FileSystemMonitorHandler, ProcessMetadata


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


class _DummyTracker:
    def record_event(self, event_type, src_path, process_metadata, previous_path=None):
        class _State:
            score = 0
            pid = process_metadata.pid
            process_name = process_metadata.name
            executable = process_metadata.executable
            unique_files_touched = set()

        return _State()


class _DummyEvent:
    def __init__(self, src_path, dest_path):
        self.src_path = src_path
        self.dest_path = dest_path
        self.is_directory = False


class EntropyIdentityTrackingTests(unittest.TestCase):
    def test_entropy_tracking_survives_extension_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "sample.txt"
            renamed = root / "sample.locked"
            original.write_text("baseline\n", encoding="utf-8")

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

            try:
                monitor._scan_file_for_cache(original)
                initial_row = metadata_db.get_entropy_record(str(original))
                self.assertIsNotNone(initial_row)

                original.rename(renamed)

                with patch("entropy.monitor.calculate_entropy", return_value=6.5) as entropy_mock:
                    monitor._process_event(
                        type(
                            "Evt",
                            (),
                            {
                                "event_type": "FILE MODIFIED",
                                "file_path": str(renamed),
                                "previous_path": None,
                                "file_id": None,
                                "process_name": None,
                                "pid": None,
                                "executable": None,
                                "parent": None,
                            },
                        )
                    )

                self.assertEqual(entropy_mock.call_count, 1)
                row = metadata_db.get_entropy_record(str(renamed))
                self.assertIsNotNone(row)
                self.assertTrue(row["exists"])
            finally:
                monitor.stop()
                metadata_db.close()
                logs_db.close()
                alerts_db.close()

    def test_filesystem_handler_emits_explicit_extension_change_event(self):
        tracker = _DummyTracker()
        handler = FileSystemMonitorHandler(_DummyLogger(), tracker)
        handler._process_resolver.resolve = lambda path, **kwargs: ProcessMetadata(
            pid=1234,
            name="python",
            executable="/usr/bin/python",
            parent_name="zsh",
            start_time="2026-07-18 12:00:00",
            start_time_epoch=1.0,
        )

        captured = []

        def callback(event_type, file_path, process_name, pid, executable, parent, previous_path=None, file_identifier=None):
            captured.append((event_type, file_path, previous_path, file_identifier))

        handler._event_callback = callback

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "report.txt"
            dst = root / "report.locked"
            src.write_text("x", encoding="utf-8")
            os.rename(src, dst)
            handler.on_moved(_DummyEvent(str(src), str(dst)))

            deadline = time.time() + 2.0
            while time.time() < deadline:
                names = [e[0] for e in captured]
                if "FILE MOVED" in names and "FILE EXTENSION CHANGED" in names:
                    break
                time.sleep(0.02)

        names = [e[0] for e in captured]
        self.assertIn("FILE MOVED", names)
        self.assertIn("FILE EXTENSION CHANGED", names)

        ext_events = [e for e in captured if e[0] == "FILE EXTENSION CHANGED"]
        self.assertEqual(len(ext_events), 1)
        self.assertTrue(ext_events[0][2].endswith("report.txt"))
        self.assertIsNotNone(ext_events[0][3])
        handler.stop()


if __name__ == "__main__":
    unittest.main()
