#!/usr/bin/env python3
import re
import sys
import subprocess
import threading
import time
from pathlib import Path
from typing import List

try:
    import psutil
except Exception:
    psutil = None

from PyQt5.QtCore import Qt, pyqtSignal, QObject, QTimer
from PyQt5.QtGui import QColor, QFont, QBrush
from PyQt5.QtWidgets import (
    QApplication,
    QWidget,
    QMainWindow,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QLineEdit,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QPlainTextEdit,
    QCheckBox,
    QMessageBox,
    QScrollArea,
    QDialog,
    QStackedWidget,
)


class OutputBridge(QObject):
    new_raw_line = pyqtSignal(str)
    new_log_entry = pyqtSignal(dict)
    process_started = pyqtSignal()
    process_stopped = pyqtSignal()
    error_occurred = pyqtSignal(str)


class RawOutputWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RDRS Raw Output")
        self.setGeometry(100, 100, 800, 600)

        self.output_area = QPlainTextEdit()
        self.output_area.setReadOnly(True)
        self.output_area.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.output_area.setFont(QFont("Courier", 9))

        self.setCentralWidget(self.output_area)

    def append_line(self, line: str) -> None:
        self.output_area.appendPlainText(line)

    def clear_output(self) -> None:
        self.output_area.clear()


class EventDetailsDialog(QDialog):
    def __init__(self, parent, entry: dict):
        super().__init__(parent)
        self.setWindowTitle("Event Details")
        self.setGeometry(200, 200, 700, 500)
        self.setModal(True)

        layout = QVBoxLayout()

        text_edit = QPlainTextEdit()
        text_edit.setReadOnly(True)
        text_edit.setFont(QFont("Courier", 11))
        text_edit.setLineWrapMode(QPlainTextEdit.NoWrap)

        raw_event = entry.get("raw_event", "")
        if raw_event:
            text_edit.setPlainText(raw_event)
        else:
            details = []
            for key in ["timestamp", "level", "event_type", "file", "file_name", "process", "pid", "executable", "parent_process", "message"]:
                value = entry.get(key, "")
                if value:
                    details.append(f"{key.replace('_', ' ').title()}: {value}")
            text_edit.setPlainText("\n".join(details))

        layout.addWidget(text_edit)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)

        self.setLayout(layout)


class RdrsGui(QWidget):
    def __init__(self):
        super().__init__()
        self.process = None
        self.reader_thread = None
        self.event_rows: List[dict] = []
        self.raw_output_window = None
        self.event_count = 0
        self.start_time = None
        self.runtime_timer = QTimer()
        self.runtime_timer.setInterval(1000)
        self.runtime_timer.timeout.connect(self._update_runtime_display)
        self.output_bridge = OutputBridge()
        self.output_bridge.new_raw_line.connect(self.append_raw_line)
        self.output_bridge.new_log_entry.connect(self.add_log_row)
        self.output_bridge.process_started.connect(self.on_process_started)
        self.output_bridge.process_stopped.connect(self.on_process_stopped)
        self.output_bridge.error_occurred.connect(self.show_error)

        self.setWindowTitle("RDRS GUI Monitor")
        self.setStyleSheet(
            "QWidget { background: #171b25; color: #f0f0f0; font-family: Segoe UI, Arial, sans-serif; }"
            "QPushButton { border: none; padding: 10px 12px; text-align: left; }"
            "QPushButton:hover { background: #2b3140; }"
            "QHeaderView::section { background: #242b3a; color: white; padding: 8px; border: none; }"
            "QTableWidget { background: #1f2430; gridline-color: #2d3547; }"
        )
        self.build_ui()

    def build_ui(self):
        main_layout = QHBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        sidebar = QWidget()
        sidebar_layout = QVBoxLayout()
        sidebar_layout.setContentsMargins(16, 16, 16, 16)
        sidebar_layout.setSpacing(10)
        sidebar.setLayout(sidebar_layout)
        sidebar.setMaximumWidth(280)
        sidebar.setStyleSheet("background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #171b25, stop:1 #20263a);")

        header = QLabel("RDRS Monitor")
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("font-size: 20px; font-weight: 900; margin-bottom: 18px; color: #ffffff;")
        sidebar_layout.addWidget(header)

        self.home_button = QPushButton("▶ Home")
        self.home_button.clicked.connect(lambda: self.select_page(0))
        self.home_button.setStyleSheet("font-weight: bold; color: white; background: transparent;")
        sidebar_layout.addWidget(self.home_button)

        self.monitoring_button = QPushButton("▶ File Monitoring")
        self.monitoring_button.clicked.connect(lambda: self.select_page(1))
        self.monitoring_button.setStyleSheet("font-weight: bold; color: white; background: transparent;")
        sidebar_layout.addWidget(self.monitoring_button)

        sidebar_layout.addSpacing(12)

        controls_label = QLabel("Monitor Settings")
        controls_label.setStyleSheet("font-weight: bold; color: #d9d9d9; margin-top: 12px;")
        sidebar_layout.addWidget(controls_label)

        path_label = QLabel("Monitor Path:")
        path_label.setStyleSheet("font-size: 10px; color: #d1d1d1;")
        sidebar_layout.addWidget(path_label)

        self.path_input = QLineEdit(str(Path.home()))
        self.path_input.setPlaceholderText("Directory")
        self.path_input.setStyleSheet("background: #222938; color: white; border: 1px solid #2f3a59; padding: 6px;")
        sidebar_layout.addWidget(self.path_input)

        self.recursive_checkbox = QCheckBox("Recursive")
        self.recursive_checkbox.setChecked(True)
        self.recursive_checkbox.setStyleSheet("color: #f0f0f0;")
        sidebar_layout.addWidget(self.recursive_checkbox)

        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #d9d9d9; margin-top: 14px; font-size: 11px;")
        self.status_label.setWordWrap(True)
        sidebar_layout.addWidget(self.status_label)

        sidebar_layout.addStretch()

        self.page_stack = QStackedWidget()
        self.page_stack.setStyleSheet("background: #121720; border: none;")

        self.home_page = QWidget()
        home_layout = QVBoxLayout()
        home_layout.setContentsMargins(24, 24, 24, 24)
        home_layout.setSpacing(14)
        self.home_page.setLayout(home_layout)

        home_title = QLabel("Suspicious Behaviour")
        home_title.setStyleSheet("font-size: 18px; font-weight: bold; color: #ffffff;")
        home_layout.addWidget(home_title)

        self.home_table = QTableWidget(0, 3)
        self.home_table.setHorizontalHeaderLabels(["Process Name", "PID", "Reason"])
        self.home_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.home_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.home_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.home_table.setSelectionMode(QTableWidget.SingleSelection)
        self.home_table.setStyleSheet("QTableWidget { background: #1f2430; }")
        home_layout.addWidget(self.home_table)
        self.page_stack.addWidget(self.home_page)

        self.file_monitoring_page = QWidget()
        file_layout = QVBoxLayout()
        file_layout.setContentsMargins(24, 24, 24, 24)
        file_layout.setSpacing(14)
        self.file_monitoring_page.setLayout(file_layout)

        file_title = QLabel("File Monitoring")
        file_title.setStyleSheet("font-size: 18px; font-weight: bold; color: #ffffff;")
        file_layout.addWidget(file_title)

        self.log_table = QTableWidget(0, 10)
        self.log_table.setHorizontalHeaderLabels([
            "Timestamp",
            "Level",
            "Event Type",
            "File",
            "File Name",
            "Process",
            "PID",
            "Executable",
            "Parent Process",
            "Message",
        ])
        self.log_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.log_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.log_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.log_table.setSelectionMode(QTableWidget.SingleSelection)
        self.log_table.itemSelectionChanged.connect(self.on_table_selection_changed)
        self.log_table.setColumnCount(10)
        self.log_table.setStyleSheet("QTableWidget { background: #1f2430; }")
        file_layout.addWidget(self.log_table)

        raw_output_btn = QPushButton("View Raw Output")
        raw_output_btn.clicked.connect(self.show_raw_output_window)
        raw_output_btn.setStyleSheet("background: #2f3a59; color: #ffffff; font-weight: bold; margin-top: 8px; padding: 10px;")
        file_layout.addWidget(raw_output_btn)

        self.page_stack.addWidget(self.file_monitoring_page)

        bottom_bar = QWidget()
        bottom_layout = QHBoxLayout()
        bottom_layout.setContentsMargins(18, 12, 18, 12)
        bottom_layout.setSpacing(16)
        bottom_bar.setLayout(bottom_layout)
        bottom_bar.setStyleSheet("background: #1f2430; border-top: 1px solid #2d3547;")

        self.start_button = QPushButton("Start Monitor")
        self.start_button.clicked.connect(self.start_monitor)
        self.start_button.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold; padding: 12px 16px; font-size: 14px; border-radius: 8px;")
        bottom_layout.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop Monitor")
        self.stop_button.clicked.connect(self.stop_monitor)
        self.stop_button.setEnabled(False)
        self.stop_button.setStyleSheet("background-color: #f44336; color: white; font-weight: bold; padding: 12px 16px; font-size: 14px; border-radius: 8px;")
        bottom_layout.addWidget(self.stop_button)

        status_container = QWidget()
        status_layout = QVBoxLayout()
        status_layout.setContentsMargins(0, 0, 0, 0)
        status_layout.setSpacing(6)
        status_container.setLayout(status_layout)
        status_layout.addWidget(self.status_label)

        self.runtime_label = QLabel("Runtime: 00:00:00")
        self.runtime_label.setStyleSheet("color: white; font-size: 14px; font-weight: bold;")
        status_layout.addWidget(self.runtime_label)

        self.total_events_label = QLabel("Total events: 0")
        self.total_events_label.setStyleSheet("color: white; font-size: 14px; font-weight: bold;")
        status_layout.addWidget(self.total_events_label)

        bottom_layout.addWidget(status_container, 1)

        content = QWidget()
        content_layout = QVBoxLayout()
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)
        content.setLayout(content_layout)
        content_layout.addWidget(self.page_stack)
        content_layout.addWidget(bottom_bar)

        main_layout.addWidget(sidebar)
        main_layout.addWidget(content, 1)
        self.setLayout(main_layout)
        self.select_page(0)

        self.select_page(0)

    def select_page(self, index: int):
        self.page_stack.setCurrentIndex(index)
        if index == 0:
            self.home_button.setText("▼ Home")
            self.monitoring_button.setText("▶ File Monitoring")
            self.home_button.setStyleSheet("font-weight: bold; color: white; background: #2d3a5a; border-radius: 8px;")
            self.monitoring_button.setStyleSheet("font-weight: bold; color: #ffffff; background: transparent;")
        else:
            self.home_button.setText("▶ Home")
            self.monitoring_button.setText("▼ File Monitoring")
            self.home_button.setStyleSheet("font-weight: bold; color: #ffffff; background: transparent;")
            self.monitoring_button.setStyleSheet("font-weight: bold; color: white; background: #2d3a5a; border-radius: 8px;")

    def start_monitor(self):
        if self.process is not None:
            return
        script_path = self._resolve_main_script()
        if not script_path.exists():
            self.handle_error(f"Could not find main.py at {script_path}")
            return

        monitor_path = self.path_input.text().strip() or str(Path.home())
        self.append_raw_line(f"Starting monitor for: {monitor_path}")

        cmd = [sys.executable, str(script_path), "--path", monitor_path]
        if self.recursive_checkbox.isChecked():
            cmd.append("--recursive")

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
            )
        except Exception as exc:
            try:
                self.runtime_timer.stop()
            except Exception:
                pass
            self.handle_error(f"Failed to start monitor: {exc}")
            self.process = None
            return

        self.start_time = time.time()
        self.event_count = 0
        self.total_events_label.setText("Total events: 0")
        self._update_runtime_display()
        self.runtime_timer.start()

        self.reader_thread = threading.Thread(target=self.read_process_output, daemon=True)
        self.reader_thread.start()
        self.output_bridge.process_started.emit()

    def stop_monitor(self):
        if self.process is None:
            return
        if self.process.poll() is None:
            try:
                self.process.terminate()
            except Exception as exc:
                self.handle_error(f"Failed to stop monitor: {exc}")
        self.process = None
        self.output_bridge.process_stopped.emit()
        self.append_raw_line("Monitor stopped.")
        try:
            self.runtime_timer.stop()
        except Exception:
            pass

    def on_process_started(self):
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.status_label.setText("Monitoring...")
        self.status_label.setStyleSheet("color: #00a000; margin-top: 12px; font-size: 10px; font-weight: bold;")

    def on_process_stopped(self):
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.status_label.setText("Stopped")
        self.status_label.setStyleSheet("color: #d9d9d9; margin-top: 12px; font-size: 10px;")

    def handle_error(self, message: str) -> None:
        self.output_bridge.error_occurred.emit(message)

    def show_error(self, message: str) -> None:
        self.status_label.setText(f"Error: {message}")
        self.status_label.setStyleSheet("color: #c00000; margin-top: 12px; font-size: 10px; font-weight: bold;")
        if self.raw_output_window:
            self.raw_output_window.append_line(f"ERROR: {message}")
        QMessageBox.critical(self, "RDRS Monitor Error", message)

    def append_raw_line(self, line: str) -> None:
        if self.raw_output_window:
            self.raw_output_window.append_line(line)

    def add_log_row(self, entry: dict) -> None:
        row = self.log_table.rowCount()
        self.log_table.insertRow(row)
        self.event_rows.append(entry)

        columns = [
            "timestamp",
            "level",
            "event_type",
            "file",
            "file_name",
            "process",
            "pid",
            "executable",
            "parent_process",
            "message",
        ]

        self.event_count += 1
        try:
            self.total_events_label.setText(f"Total events: {self.event_count}")
        except Exception:
            pass

        text_color = self._text_color_for_event(entry.get("event_type", ""))
        for col_index, key in enumerate(columns):
            value = entry.get(key, "") or ""
            item = QTableWidgetItem(value)
            if text_color is not None:
                item.setForeground(QBrush(text_color))
            self.log_table.setItem(row, col_index, item)

    def on_table_selection_changed(self):
        selected_items = self.log_table.selectedItems()
        if not selected_items:
            return
        row = selected_items[0].row()
        if 0 <= row < len(self.event_rows):
            entry = self.event_rows[row]
            dialog = EventDetailsDialog(self, entry)
            dialog.exec_()

    def read_process_output(self):
        if self.process is None or self.process.stdout is None:
            return

        entry_lines: List[str] = []
        try:
            while self.process.poll() is None:
                raw_line = self.process.stdout.readline()
                if raw_line == "":
                    break
                line = raw_line.rstrip("\n")
                self.output_bridge.new_raw_line.emit(line)

                if self._is_timestamped_header(line):
                    if entry_lines:
                        self._emit_log_entry(entry_lines)
                    entry_lines = [line]
                else:
                    entry_lines.append(line)

            if entry_lines:
                self._emit_log_entry(entry_lines)
        except Exception as exc:
            self.handle_error(f"Error reading monitor output: {exc}")
        finally:
            self.process = None
            self.output_bridge.process_stopped.emit()
            self.output_bridge.new_raw_line.emit("main.py process exited.")

    @staticmethod
    def _is_timestamped_header(line: str) -> bool:
        return bool(re.match(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} (INFO|ERROR|WARNING|DEBUG|CRITICAL)\b", line))

    def _emit_log_entry(self, lines: List[str]) -> None:
        entry = self._parse_logger_entry(lines)
        entry["raw_event"] = "\n".join(lines)
        # try to enrich record (best-effort; will not alter main.py behavior)
        try:
            self._enrich_record(entry)
        except Exception:
            pass
        self.output_bridge.new_log_entry.emit(entry)

    def _enrich_record(self, record: dict) -> None:
        # Heuristics to fill missing pid/process/parent_process where possible
        raw = record.get("raw_event", "") or ""
        # look for PID patterns
        if not record.get("pid"):
            m = re.search(r"\bPID[: ]+([0-9]+)\b", raw, re.IGNORECASE)
            if m:
                record["pid"] = m.group(1)

        # If psutil available, try to map pid -> parent/process
        if psutil and record.get("pid"):
            try:
                pid = int(record.get("pid"))
                p = psutil.Process(pid)
                if not record.get("process"):
                    record["process"] = p.name()
                parent = p.parent()
                if parent and not record.get("parent_process"):
                    record["parent_process"] = parent.name()
            except Exception:
                pass

        # If pid not found but executable available, try to match running processes by exe/name
        if psutil and not record.get("pid") and record.get("executable"):
            exe = record.get("executable")
            try:
                for p in psutil.process_iter(["pid", "name", "exe"]):
                    try:
                        pexe = p.info.get("exe") or ""
                        pname = p.info.get("name") or ""
                        if pexe and exe and (exe.lower() in pexe.lower() or pexe.lower().endswith(exe.lower())):
                            if not record.get("pid"):
                                record["pid"] = str(p.info.get("pid"))
                            if not record.get("process"):
                                record["process"] = pname
                            parent = p.parent()
                            if parent and not record.get("parent_process"):
                                record["parent_process"] = parent.name()
                            break
                        # fallback match on process name
                        if not record.get("pid") and exe and pname and exe.lower() == pname.lower():
                            record["pid"] = str(p.info.get("pid"))
                            if not record.get("process"):
                                record["process"] = pname
                            parent = p.parent()
                            if parent and not record.get("parent_process"):
                                record["parent_process"] = parent.name()
                            break
                    except Exception:
                        continue
            except Exception:
                pass

    def _parse_logger_entry(self, lines: List[str]) -> dict:
        raw_header = lines[0]
        log_record = {
            "timestamp": "",
            "level": "",
            "event_type": "",
            "file": "",
            "file_name": "",
            "process": "",
            "pid": "",
            "executable": "",
            "parent_process": "",
            "message": "",
            "raw_event": "",
        }

        header_match = re.match(
            r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<level>\w+) ?(?P<msg>.*)$",
            raw_header,
        )
        if header_match:
            log_record["timestamp"] = header_match.group("ts")
            log_record["level"] = header_match.group("level")
            log_record["message"] = header_match.group("msg").strip()

        body = "\n".join(lines[1:]).strip()
        if body:
            if body.startswith("EVENT:") or "EVENT:" in body:
                self._parse_event_block(body, log_record)
            elif not log_record["message"]:
                log_record["message"] = body
            else:
                log_record["message"] = f"{log_record['message']}\n{body}" if log_record["message"] else body

        return log_record

    def _parse_event_block(self, body: str, record: dict) -> None:
        lines = [line.strip() for line in body.splitlines() if line.strip()]
        current_key = None
        for line in lines:
            if line.startswith("EVENT:"):
                record["event_type"] = line.split("EVENT:", 1)[1].strip()
                continue
            if line.endswith(":"):
                current_key = line[:-1].lower().replace(" ", "_")
                continue
            if current_key and line:
                if current_key == "time":
                    record["timestamp"] = line
                elif current_key == "file":
                    record["file"] = line
                elif current_key == "file_name":
                    record["file_name"] = line
                elif current_key == "process":
                    record["process"] = line
                elif current_key == "pid":
                    record["pid"] = line
                elif current_key == "executable":
                    record["executable"] = line
                elif current_key == "parent_process":
                    record["parent_process"] = line
                else:
                    record["message"] += f"\n{line}"
                current_key = None

    def _text_color_for_event(self, event_type: str):
        event_type = (event_type or "").upper()
        if "CREAT" in event_type:
            return QColor("#007a00")
        if "DELET" in event_type:
            return QColor("#a00000")
        if "MODIF" in event_type or "MODIFIED" in event_type or "MODIFY" in event_type:
            return QColor("#003a9e")
        return None

    def _resolve_main_script(self) -> Path:
        if getattr(sys, "frozen", False):
            base_path = Path(sys._MEIPASS)
        else:
            base_path = Path(__file__).resolve().parent
        return base_path / "main.py"

    def _update_runtime_display(self):
        if not self.start_time:
            self.runtime_label.setText("Runtime: 00:00:00")
            return
        elapsed = int(time.time() - self.start_time)
        hours, rem = divmod(elapsed, 3600)
        mins, secs = divmod(rem, 60)
        self.runtime_label.setText(f"Runtime: {hours:02d}:{mins:02d}:{secs:02d}")

    def show_raw_output_window(self):
        if self.raw_output_window is None or not self.raw_output_window.isVisible():
            self.raw_output_window = RawOutputWindow()
            self.raw_output_window.show()
        else:
            self.raw_output_window.raise_()
            self.raw_output_window.activateWindow()


def main():
    app = QApplication(sys.argv)
    window = RdrsGui()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
