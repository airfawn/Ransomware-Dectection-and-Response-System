import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from database.metadata_db import MetadataDatabase
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


class EntropyValidationProcessScopingTests(unittest.TestCase):
    @staticmethod
    def _proc(pid: int) -> ProcessMetadata:
        return ProcessMetadata(
            pid=pid,
            name="python",
            executable="/usr/bin/python",
            parent_name="zsh",
            start_time="2026-08-01 10:00:00",
            start_time_epoch=time.time() - 300,
        )

    @staticmethod
    def _write(path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(os.urandom(2048))

    def test_validation_scans_only_triggering_process_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata_db = MetadataDatabase(root / "metadata.db")
            self.addCleanup(metadata_db.close)
            metadata_db.set_runtime_entropy_baseline(average_entropy=1.0, file_count=10, source_roots=str(root))

            with patch("monitor.filesystem_monitor.get_metadata_db", return_value=metadata_db):
                tracker = ProcessBehaviorTracker(logger=_DummyLogger())
            tracker._wait_for_file_stable = lambda path: path.stat()  # type: ignore[method-assign]

            files_a = []
            files_b = []
            for i in range(12):
                pa = root / "proc_a" / f"a_{i}.txt"
                pb = root / "proc_b" / f"b_{i}.txt"
                self._write(pa)
                self._write(pb)
                files_a.append(pa)
                files_b.append(pb)

            proc_a = self._proc(501)
            proc_b = self._proc(777)
            with patch("monitor.filesystem_monitor.calculate_entropy", return_value=7.6) as entropy_mock:
                for idx in range(3):
                    tracker.record_event("FILE MODIFIED", str(files_b[idx]), proc_b)
                for idx in range(11):
                    tracker.record_event("FILE MODIFIED", str(files_a[idx]), proc_a)

            selected_paths = {str(call.args[0]) for call in entropy_mock.call_args_list}
            proc_a_paths = {str(path) for path in files_a}
            proc_b_paths = {str(path) for path in files_b}
            self.assertTrue(selected_paths.issubset(proc_a_paths))
            self.assertFalse(selected_paths.intersection(proc_b_paths))


if __name__ == "__main__":
    unittest.main()
