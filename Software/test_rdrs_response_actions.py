import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import ransomwaredetector as rd


class _SelectedItem:
    def __init__(self, row: int):
        self._row = row

    def row(self) -> int:
        return self._row


class _HomeTableStub:
    def __init__(self, selected_row=None):
        self._selected_row = selected_row

    def selectedItems(self):
        if self._selected_row is None:
            return []
        return [_SelectedItem(self._selected_row)]


class RdrsResponseActionsTest(unittest.TestCase):
    def _make_gui_shell(self):
        gui = rd.RdrsGui.__new__(rd.RdrsGui)
        gui.suspicious_process_rows = {}
        gui.process_state_cache = {}
        gui._last_alert_process_key = None
        gui._auto_quarantine_attempted = set()
        gui._selected_home_process_key = None
        gui._pending_process_state_refresh = False
        gui._pending_metrics_refresh = False
        gui.home_table = _HomeTableStub()
        gui._alerts_db = None
        return gui

    def test_get_response_target_prefers_selected_suspicious_row(self):
        gui = self._make_gui_shell()
        key_selected = ("111", "/tmp/procA")
        key_other = ("222", "/tmp/procB")

        gui.suspicious_process_rows = {key_selected: 0, key_other: 1}
        gui.process_state_cache = {
            key_selected: {"pid": "111", "process": "procA", "score": "10"},
            key_other: {"pid": "222", "process": "procB", "score": "99"},
        }
        gui.home_table = _HomeTableStub(selected_row=0)

        target = gui._get_response_target_process()
        self.assertIsNotNone(target)
        self.assertEqual(target.get("pid"), "111")

    def test_get_response_target_falls_back_to_highest_score(self):
        gui = self._make_gui_shell()
        key_low = ("111", "/tmp/low")
        key_high = ("222", "/tmp/high")

        gui.process_state_cache = {
            key_low: {"pid": "111", "process": "low", "score": "20"},
            key_high: {"pid": "222", "process": "high", "score": "80"},
        }

        target = gui._get_response_target_process()
        self.assertIsNotNone(target)
        self.assertEqual(target.get("pid"), "222")

    def test_quarantine_moves_executable_and_logs_action(self):
        gui = self._make_gui_shell()

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            exe = tmp_path / "suspect.bin"
            exe.write_bytes(b"malicious")

            target = {
                "pid": "321",
                "process": "evilproc",
                "executable": str(exe),
                "score": "95",
            }

            banner_messages = []
            logged_actions = []
            errors = []

            gui._get_response_target_process = lambda: target
            gui._suspend_process_if_running = lambda pid: "PID 321 suspended"
            gui._kill_process_if_running = lambda pid: "PID 321 killed"
            gui._show_alert_banner = lambda msg: banner_messages.append(msg)
            gui._log_response_action = lambda action, process, notes, **kwargs: logged_actions.append((action, process, notes, kwargs))
            gui.show_error = lambda msg: errors.append(msg)

            with patch.object(rd, "get_data_dir", return_value=tmp_path), patch.object(
                rd.QMessageBox, "information", return_value=rd.QMessageBox.Ok
            ):
                gui._on_quarantine_alert_process()

            quarantine_dir = tmp_path / "quarantine"
            moved_files = list(quarantine_dir.glob("*_suspect.bin"))

            self.assertFalse(exe.exists())
            self.assertEqual(len(moved_files), 1)
            self.assertEqual(errors, [])
            self.assertEqual(len(banner_messages), 1)
            self.assertEqual(len(logged_actions), 1)
            self.assertEqual(logged_actions[0][0], "QUARANTINE_ACTION")
            self.assertEqual(logged_actions[0][3]["status"], "SUCCEEDED")

    def test_delete_removes_executable_and_logs_action(self):
        gui = self._make_gui_shell()

        with tempfile.TemporaryDirectory() as tmp_dir:
            exe = Path(tmp_dir) / "suspect_del.bin"
            exe.write_bytes(b"malicious")

            target = {
                "pid": "654",
                "process": "evilproc2",
                "executable": str(exe),
                "score": "90",
            }

            banner_messages = []
            logged_actions = []
            errors = []

            gui._get_response_target_process = lambda: target
            gui._kill_process_if_running = lambda pid: "PID 654 killed"
            gui._show_alert_banner = lambda msg: banner_messages.append(msg)
            gui._log_response_action = lambda action, process, notes, **kwargs: logged_actions.append((action, process, notes, kwargs))
            gui.show_error = lambda msg: errors.append(msg)

            with patch.object(rd.QMessageBox, "question", return_value=rd.QMessageBox.Yes), patch.object(
                rd.QMessageBox, "information", return_value=rd.QMessageBox.Ok
            ):
                gui._on_delete_alert_process()

            self.assertFalse(exe.exists())
            self.assertEqual(errors, [])
            self.assertEqual(len(banner_messages), 1)
            self.assertEqual(len(logged_actions), 1)
            self.assertEqual(logged_actions[0][0], "DELETE_ACTION")
            self.assertEqual(logged_actions[0][3]["status"], "SUCCEEDED")

    def test_auto_quarantine_triggers_once_at_score_50(self):
        gui = self._make_gui_shell()

        calls = []
        gui._perform_quarantine_for_target = lambda target, automatic=False: calls.append((target, automatic)) or True

        entry = {
            "event_type": "PROCESS_STATE",
            "pid": "999",
            "process": "suspect",
            "executable": "/tmp/suspect.exe",
            "score": "50",
        }

        gui._update_process_state_table(entry)
        gui._update_process_state_table(entry)

        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0][1])


if __name__ == "__main__":
    unittest.main()
