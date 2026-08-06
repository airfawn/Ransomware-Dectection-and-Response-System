import queue
import unittest
from unittest.mock import patch

import ransomwaredetector as rd


class _PageStackStub:
    def __init__(self, index=1):
        self._index = index

    def currentIndex(self):
        return self._index

    def setCurrentIndex(self, index):
        self._index = index


class _LabelStub:
    def __init__(self):
        self.text = ""
        self.style = ""

    def setText(self, text):
        self.text = text

    def setStyleSheet(self, style):
        self.style = style


class _ButtonStub:
    def __init__(self):
        self.text = ""
        self.style = ""

    def setText(self, text):
        self.text = text

    def setStyleSheet(self, style):
        self.style = style


class GuiRedrawGatingRegressionTests(unittest.TestCase):
    def _make_gui(self, page_index=1):
        gui = rd.RdrsGui.__new__(rd.RdrsGui)
        gui.page_stack = _PageStackStub(page_index)
        gui._filesystem_event_gui_queue = queue.Queue(maxsize=10000)
        gui.event_rows = []
        gui.event_count = 0

        gui._pending_log_refresh = False
        gui._pending_counter_refresh = False
        gui._pending_process_state_refresh = False
        gui._pending_suspicious_refresh = False
        gui._pending_metrics_refresh = False
        gui._pending_total_events_refresh = False
        gui._selected_home_process_key = None

        gui.total_events_label = _LabelStub()
        gui.home_button = _ButtonStub()
        gui.incident_button = _ButtonStub()
        gui.monitoring_button = _ButtonStub()
        gui.processes_button = _ButtonStub()
        gui.entropy_button = _ButtonStub()
        gui.rules_button = _ButtonStub()

        counters = {
            "trim": 0,
            "log_refresh": 0,
            "counter_refresh": 0,
            "process_refresh": 0,
            "suspicious_refresh": 0,
            "metrics_refresh": 0,
            "incident_refresh": 0,
        }
        gui._trim_gui_event_cache = lambda: counters.__setitem__("trim", counters["trim"] + 1)
        gui._refresh_log_table_view = lambda: counters.__setitem__("log_refresh", counters["log_refresh"] + 1)
        gui._refresh_file_event_counters = lambda: counters.__setitem__("counter_refresh", counters["counter_refresh"] + 1)
        gui._refresh_process_state_tables = lambda: counters.__setitem__("process_refresh", counters["process_refresh"] + 1)
        gui._refresh_suspicious_process_table = lambda: counters.__setitem__("suspicious_refresh", counters["suspicious_refresh"] + 1)
        gui._refresh_dashboard_metrics = lambda: counters.__setitem__("metrics_refresh", counters["metrics_refresh"] + 1)
        gui._populate_incident_page = lambda *_args, **_kwargs: counters.__setitem__("incident_refresh", counters["incident_refresh"] + 1)
        gui._refresh_entropy_table = lambda: None

        return gui, counters

    def _enqueue_event(self, gui, idx=1):
        gui._filesystem_event_gui_queue.put_nowait(
            {
                "event_type": "FILE MODIFIED",
                "timestamp": f"t{idx}",
                "file": f"/tmp/f{idx}.txt",
                "file_name": f"f{idx}.txt",
                "message": "burst",
            }
        )

    def test_case_a_visible_page_triggers_redraw(self):
        gui, counters = self._make_gui(page_index=1)
        self._enqueue_event(gui)

        rd.RdrsGui._flush_pending_gui_updates(gui)

        self.assertEqual(counters["log_refresh"], 1)
        self.assertEqual(counters["counter_refresh"], 1)
        self.assertEqual(gui.event_count, 1)

    def test_case_b_hidden_page_skips_expensive_redraw(self):
        gui, counters = self._make_gui(page_index=0)
        self._enqueue_event(gui)

        rd.RdrsGui._flush_pending_gui_updates(gui)

        self.assertEqual(counters["log_refresh"], 0)
        self.assertEqual(counters["counter_refresh"], 0)
        self.assertTrue(gui._pending_log_refresh)
        self.assertTrue(gui._pending_counter_refresh)

    def test_case_c_page_reentry_forces_refresh(self):
        gui, counters = self._make_gui(page_index=0)
        self._enqueue_event(gui)

        rd.RdrsGui._flush_pending_gui_updates(gui)
        self.assertEqual(counters["log_refresh"], 0)

        rd.RdrsGui.select_page(gui, 1)
        rd.RdrsGui._flush_pending_gui_updates(gui)

        self.assertGreaterEqual(counters["log_refresh"], 1)
        self.assertGreaterEqual(counters["counter_refresh"], 1)

    def test_case_d_rapid_switching_no_duplicate_redraw_backlog(self):
        gui, counters = self._make_gui(page_index=1)

        for i in range(120):
            self._enqueue_event(gui, idx=i)
            if i % 4 == 0:
                rd.RdrsGui.select_page(gui, 0)
            elif i % 4 == 1:
                rd.RdrsGui.select_page(gui, 1)
            elif i % 4 == 2:
                rd.RdrsGui.select_page(gui, 2)
            else:
                rd.RdrsGui.select_page(gui, 1)
            rd.RdrsGui._flush_pending_gui_updates(gui)

        rd.RdrsGui.select_page(gui, 1)
        rd.RdrsGui._flush_pending_gui_updates(gui)

        self.assertEqual(gui._filesystem_event_gui_queue.qsize(), 0)
        self.assertEqual(gui._pending_log_refresh, False)
        self.assertEqual(gui._pending_counter_refresh, False)
        self.assertLess(counters["log_refresh"], gui.event_count)


class GuiEntropyDbPollingRegressionTests(unittest.TestCase):
    def _make_gui_for_entropy(self):
        gui = rd.RdrsGui.__new__(rd.RdrsGui)
        gui._startup_baseline_average = 3.25
        gui._startup_baseline_file_count = 42
        gui.process_state_cache = {
            ("100", "/bin/test"): {
                "pid": "100",
                "process": "test",
                "score": "55",
                "behavior_score_component": "20",
                "extension_score_component": "5",
                "entropy_validation_trigger": "30",
                "entropy_baseline_average": "3.25",
                "entropy_baseline_file_count": "42",
                "entropy_validation_average": "3.90",
                "entropy_validation_file_count": "10",
                "entropy_validation_increase": "0.65",
            }
        }
        gui.suspicious_process_rows = {}
        gui.home_table = type("HomeTable", (), {"selectedItems": lambda self: []})()

        gui.detection_score_label = _LabelStub()
        gui.detection_state_label = _LabelStub()
        gui.entropy_baseline_value = _LabelStub()
        gui.entropy_validation_value = _LabelStub()
        gui.entropy_increase_value = _LabelStub()
        gui.entropy_trigger_value = _LabelStub()
        gui.summary_behavior_value = _LabelStub()
        gui.summary_extension_value = _LabelStub()
        gui.summary_entropy_value = _LabelStub()
        gui.summary_total_value = _LabelStub()

        gui._refresh_entropy_activity_table = lambda: None
        gui._resize_entropy_columns = lambda: None
        return gui

    def test_entropy_refresh_does_not_query_metadata_db(self):
        gui = self._make_gui_for_entropy()

        with patch.object(rd, "_DATABASE_AVAILABLE", False):
            rd.RdrsGui._refresh_entropy_table(gui)

        self.assertIn("Baseline Average Entropy", gui.entropy_baseline_value.text)
        self.assertIn("Last Validation Average", gui.entropy_validation_value.text)


class GuiExtensionChangeNormalizationTests(unittest.TestCase):
    def _make_gui_shell(self):
        gui = rd.RdrsGui.__new__(rd.RdrsGui)
        gui.event_rows = []
        gui.event_count = 0
        gui._pending_total_events_refresh = False
        gui._pending_log_refresh = False
        gui._pending_counter_refresh = False
        gui._pending_metrics_refresh = False

        gui._trim_gui_event_cache = lambda: None
        gui._update_process_state_table = lambda *_args, **_kwargs: None
        gui._update_suspicious_process_table = lambda *_args, **_kwargs: None

        persisted = {"count": 0}
        gui._persist_extension_change = lambda _entry: persisted.__setitem__("count", persisted["count"] + 1)
        return gui, persisted

    def test_normalize_event_type_maps_extension_alias(self):
        self.assertEqual(rd.RdrsGui._normalize_event_type("FILE EXTENSION CHANGED"), "EXTENSION_CHANGE")

    def test_add_log_row_keeps_extension_change_events(self):
        gui, persisted = self._make_gui_shell()

        rd.RdrsGui.add_log_row(
            gui,
            {
                "event_type": "FILE EXTENSION CHANGED",
                "file": "/tmp/report.locked",
                "file_name": "report.locked",
                "process": "proc",
            },
        )

        self.assertEqual(len(gui.event_rows), 1)
        self.assertEqual(gui.event_rows[0]["event_type"], "EXTENSION_CHANGE")
        self.assertEqual(persisted["count"], 1)
        self.assertEqual(gui.event_count, 1)


if __name__ == "__main__":
    unittest.main()
