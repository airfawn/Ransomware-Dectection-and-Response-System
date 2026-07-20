#!/usr/bin/env python3
"""RDRS GUI Application.

This module provides the main graphical user interface for the Ransomware
Detection and Response System. It features:
- Real-time file monitoring display
- Process behavior tracking with detailed inspection
- Suspicious activity detection
- Process details panel with file activity timeline
- Thread-safe GUI updates from background monitoring

Thread Safety:
    All GUI updates are performed on the main Qt thread using signals.
"""

import re
import sys
import time
import logging
import threading
import queue
import shutil
import json
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set

try:
    import psutil
except ImportError:
    psutil = None

from PyQt5.QtCore import Qt, pyqtSignal, QObject, QTimer, QThread
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
    QSpinBox,
    QMessageBox,
    QDialog,
    QFileDialog,
    QStackedWidget,
    QSplitter,
    QComboBox,
    QFrame,
    QTreeWidget,
    QTreeWidgetItem,
    QAbstractItemView,
    QSizePolicy,
)

from monitor.session import MonitorSession
from entropy_loader import EntropyBuildWorker, EntropyRescanWorker
from splash_screen import EntropyRebuildDialog
from utils.paths import get_data_dir

try:
    from config import (
        get_config,
        save_rule_settings,
        save_entropy_rule_settings,
        save_startup_directories,
    )
    _CONFIG_AVAILABLE = True
except ImportError:
    _CONFIG_AVAILABLE = False

try:
    from database import get_logs_db, get_metadata_db, get_alerts_db
    _DATABASE_AVAILABLE = True
except ImportError:
    _DATABASE_AVAILABLE = False

# ---------------------------------------------------------------------------
# Entropy / database integration (gracefully optional so the GUI still starts
# even if new packages are not yet installed)
# ---------------------------------------------------------------------------
try:
    from entropy import EntropyMonitor, EntropyIncreaseDetected
    _ENTROPY_AVAILABLE = True
except ImportError:
    _ENTROPY_AVAILABLE = False
    EntropyMonitor = None  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)

APP_VERSION = "v1.0.5"


def _safe_export_name(value: str, fallback: str = "event") -> str:
    sanitized = re.sub(r"[^A-Za-z0-9._-]+", "_", value or "").strip("._")
    return sanitized or fallback


def _export_json_payload(parent: QWidget, payload: dict, suggested_name: str, title: str) -> Optional[Path]:
    default_path = str(Path.home() / suggested_name)
    target, _ = QFileDialog.getSaveFileName(parent, title, default_path, "JSON Files (*.json)")
    if not target:
        return None
    target_path = Path(target)
    if target_path.suffix.lower() != ".json":
        target_path = target_path.with_suffix(".json")
    with target_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False, default=str)
    return target_path


# Human-readable descriptions shown on the Active Rules page. Unknown/custom
# rule names fall back to a generic description rather than crashing.
_RULE_DESCRIPTIONS: Dict[str, str] = {
    "Rule1_FileBurst": "Triggers when a process performs more file operations than the configured threshold within 1 second.",
    "Rule2_MultipleDirectories": "Triggers when a process touches more distinct directories than the configured threshold within 1 second.",
    "Rule3_YoungProcessBurst": "Triggers when a recently started process (below the age threshold) generates high file activity.",
    "Rule4_ExtensionChangeBurst": "Triggers on a burst of genuine file-extension changes (e.g. .docx \u2192 .locked) from one process within the configured window \u2014 a strong ransomware signature.",
    "EntropyIncrease": "Triggers when a monitored file's Shannon entropy increases sharply between scans \u2014 a strong indicator that the file's contents were just encrypted.",
}

# Special sentinel used for the Entropy row in the Active Rules table, since
# its weight/enabled flag live in config.entropy (score/enabled) rather than
# config.detection.rule_weights/rule_enabled.
_ENTROPY_RULE_NAME = "EntropyIncrease"


class OutputBridge(QObject):
    new_raw_line = pyqtSignal(str)
    new_log_entry = pyqtSignal(dict)
    process_started = pyqtSignal()
    process_stopped = pyqtSignal()
    error_occurred = pyqtSignal(str)
    # Emitted when EntropyMonitor detects a suspicious entropy increase.
    # Payload: (file_path, process_name, previous_entropy, current_entropy, delta)
    entropy_alert = pyqtSignal(str, str, float, float, float)
    # Emitted periodically to refresh the Entropy Monitor page.
    entropy_data_updated = pyqtSignal()


class RawOutputWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RDRS Raw Output")
        self.setGeometry(100, 100, 800, 600)

        self.output_area = QPlainTextEdit()
        self.output_area.setReadOnly(True)
        self.output_area.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.output_area.setFont(QFont("Courier", 9))
        self.output_area.setStyleSheet(
            "QPlainTextEdit { background: #11151f; color: #f0f0f0; selection-background-color: #2f3f58; selection-color: #ffffff; }"
        )

        self.setCentralWidget(self.output_area)

    def append_line(self, line: str) -> None:
        self.output_area.appendPlainText(line)

    def clear_output(self) -> None:
        self.output_area.clear()


class EventDetailsDialog(QDialog):
    """Dialog for viewing detailed event information."""
    
    def __init__(self, parent: QWidget, entry: dict):
        """Initialize event details dialog.
        
        Args:
            parent: Parent widget.
            entry: Event dictionary.
        """
        super().__init__(parent)
        self.setWindowTitle("Event Details")
        self.setGeometry(200, 200, 700, 500)
        self.setModal(True)

        layout = QVBoxLayout()

        text_edit = QPlainTextEdit()
        text_edit.setReadOnly(True)
        text_edit.setFont(QFont("Courier", 11))
        text_edit.setLineWrapMode(QPlainTextEdit.NoWrap)
        text_edit.setStyleSheet(
            "QPlainTextEdit { background: #11151f; color: #f0f0f0; selection-background-color: #2f3f58; selection-color: #ffffff; }"
        )
        self._entry = dict(entry)

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

        actions_layout = QHBoxLayout()
        export_btn = QPushButton("Export JSON")
        export_btn.clicked.connect(self._export_json)
        actions_layout.addWidget(export_btn)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        actions_layout.addWidget(close_btn)
        layout.addLayout(actions_layout)
        self.setLayout(layout)

    def _export_json(self) -> None:
        payload = {
            "exported_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "event": self._entry,
        }
        event_type = _safe_export_name(self._entry.get("event_type", "event"), "event")
        timestamp = _safe_export_name(self._entry.get("timestamp", ""), "time")
        try:
            exported_path = _export_json_payload(
                self,
                payload,
                f"rdrs_{event_type.lower()}_{timestamp}.json",
                "Export Event As JSON",
            )
        except Exception as exc:
            QMessageBox.warning(self, "Export Failed", f"Could not export JSON: {exc}")
            return
        if exported_path is not None:
            QMessageBox.information(self, "Export Complete", f"Saved JSON report to:\n{exported_path}")


class ProcessDetailsDialog(QDialog):
    """Detailed process investigation panel.
    
    Displays comprehensive information about a process including:
    - General process information
    - Activity summary counters
    - File activity timeline
    - Search and filtering capabilities
    """
    
    def __init__(self, parent: QWidget, process_data: dict, process_key: Tuple):
        """Initialize process details dialog.
        
        Args:
            parent: Parent widget.
            process_data: Process state dictionary.
            process_key: Tuple identifying the process (pid, executable).
        """
        super().__init__(parent)
        self.process_data = process_data
        self.process_key = process_key
        self.parent_gui = parent
        self.file_events: List[Tuple[float, str, str, str]] = []
        
        self.setWindowTitle(f"Process Details - {process_data.get('process', 'Unknown')}")
        self.setGeometry(150, 150, 1200, 800)
        self.setModal(False)
        
        # Load config for styling
        if _CONFIG_AVAILABLE:
            config = get_config().gui
            self.classification_colors = config.classification_colors
            self.max_events = config.process_details_max_events
        else:
            self.classification_colors = {
                "Normal": "#4CAF50",
                "Suspicious": "#ff9800",
                "Alert": "#f44336",
                "Inactive": "#808080",
            }
            self.max_events = 1000
        
        self._build_ui()
        self._populate_data()
        
        # Auto-refresh timer for live updates
        self.refresh_timer = QTimer()
        self.refresh_timer.setInterval(1000)  # Update every second
        self.refresh_timer.timeout.connect(self._refresh_data)
        self.refresh_timer.start()
    
    def _build_ui(self) -> None:
        """Build the dialog UI."""
        main_layout = QVBoxLayout()
        main_layout.setSpacing(16)
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        # Header with process name and classification badge
        header_layout = QHBoxLayout()
        
        process_name = self.process_data.get("process", "Unknown")
        self.title_label = QLabel(f"Process: {process_name}")
        self.title_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #ffffff;")
        header_layout.addWidget(self.title_label)
        
        header_layout.addStretch()

        self.classification_badge = QLabel(self.process_data.get("classification", "Normal"))
        self._update_classification_badge()
        header_layout.addWidget(self.classification_badge)

        self.details_button_row = QHBoxLayout()
        self.details_button_row.setSpacing(10)

        self.btn_quarantine = QPushButton("Quarantine")
        self.btn_quarantine.setStyleSheet(
            "background: #b36b00; color: white; font-weight: bold; padding: 8px 14px; border-radius: 6px;"
        )
        self.btn_quarantine.clicked.connect(self._on_quarantine_clicked)
        self.details_button_row.addWidget(self.btn_quarantine)

        self.btn_ignore = QPushButton("Ignore")
        self.btn_ignore.setStyleSheet(
            "background: #5a1a1a; color: white; font-weight: bold; padding: 8px 14px; border-radius: 6px;"
        )
        self.btn_ignore.clicked.connect(self._on_ignore_clicked)
        self.details_button_row.addWidget(self.btn_ignore)

        self.btn_terminate = QPushButton("Remove / Terminate")
        self.btn_terminate.setStyleSheet(
            "background: #a00000; color: white; font-weight: bold; padding: 8px 14px; border-radius: 6px;"
        )
        self.btn_terminate.clicked.connect(self._on_delete_clicked)
        self.details_button_row.addWidget(self.btn_terminate)

        header_layout.addLayout(self.details_button_row)

        main_layout.addLayout(header_layout)
        
        # Splitter for sections
        splitter = QSplitter(Qt.Vertical)
        
        # === General Information Section ===
        info_frame = QFrame()
        info_frame.setStyleSheet("QFrame { background: #1f2430; border: 1px solid #2d3547; border-radius: 8px; padding: 12px; }")
        info_layout = QVBoxLayout()
        
        info_title = QLabel("General Information")
        info_title.setStyleSheet("font-size: 16pt; font-weight: bold; color: #ffffff; margin-bottom: 8px;")
        info_layout.addWidget(info_title)
        
        # Grid layout for info fields
        info_grid = QVBoxLayout()
        info_grid.setSpacing(4)
        
        self.info_labels = {}
        info_fields = [
            ("PID", "pid"),
            ("Executable Path", "executable"),
            ("Parent Process", "parent_process"),
            ("Process Creation Time", "process_start_time"),
            ("Process Age", "process_age"),
            ("First Activity", "first_activity"),
            ("Last Activity", "last_activity"),
            ("Current Score", "score"),
        ]
        
        for label_text, data_key in info_fields:
            row_layout = QHBoxLayout()
            label = QLabel(f"{label_text}:")
            label.setStyleSheet("color: #d9d9d9; font-weight: bold; min-width: 180px;")
            value_label = QLabel(self.process_data.get(data_key, "Unknown"))
            value_label.setStyleSheet("color: #f0f0f0;")
            value_label.setWordWrap(True)
            self.info_labels[data_key] = value_label
            row_layout.addWidget(label)
            row_layout.addWidget(value_label, 1)
            info_grid.addLayout(row_layout)
        
        info_layout.addLayout(info_grid)
        info_frame.setLayout(info_layout)
        splitter.addWidget(info_frame)
        
        # === Activity Summary Section ===
        activity_frame = QFrame()
        activity_frame.setStyleSheet("QFrame { background: #1f2430; border: 1px solid #2d3547; border-radius: 8px; padding: 12px; }")
        activity_layout = QVBoxLayout()
        
        activity_title = QLabel("Activity Summary")
        activity_title.setStyleSheet("font-size: 16pt; font-weight: bold; color: #ffffff; margin-bottom: 8px;")
        activity_layout.addWidget(activity_title)
        
        # Counter grid
        counter_grid = QHBoxLayout()
        counter_grid.setSpacing(20)
        
        self.counter_labels = {}
        counters = [
            ("Files Created", "files_created", "#007a00"),
            ("Files Modified", "files_modified", "#003a9e"),
            ("Files Deleted", "files_deleted", "#a00000"),
            ("Total Events", "total_events", "#ffffff"),
            ("Unique Files", "unique_files", "#ffffff"),
            ("Events/sec", "events_sec", "#ff9800"),
            ("Events/min", "events_min", "#ff9800"),
        ]
        
        for label_text, data_key, color in counters:
            counter_widget = QWidget()
            counter_layout = QVBoxLayout()
            counter_layout.setContentsMargins(8, 8, 8, 8)
            counter_layout.setSpacing(4)
            
            value_label = QLabel(self.process_data.get(data_key, "0"))
            value_label.setAlignment(Qt.AlignCenter)
            value_label.setStyleSheet(f"font-size: 24px; font-weight: bold; color: {color};")
            self.counter_labels[data_key] = value_label
            
            desc_label = QLabel(label_text)
            desc_label.setAlignment(Qt.AlignCenter)
            desc_label.setStyleSheet("font-size: 10px; color: #d9d9d9;")
            
            counter_layout.addWidget(value_label)
            counter_layout.addWidget(desc_label)
            counter_widget.setLayout(counter_layout)
            counter_grid.addWidget(counter_widget)
        
        counter_grid.addStretch()
        activity_layout.addLayout(counter_grid)
        activity_frame.setLayout(activity_layout)
        splitter.addWidget(activity_frame)

        breakdown_frame = QFrame()
        breakdown_frame.setStyleSheet("QFrame { background: #1f2430; border: 1px solid #2d3547; border-radius: 8px; padding: 12px; }")
        breakdown_layout = QVBoxLayout()
        breakdown_layout.setSpacing(8)

        breakdown_title = QLabel("Behavior Breakdown")
        breakdown_title.setStyleSheet("font-size: 16pt; font-weight: bold; color: #ffffff; margin-bottom: 8px;")
        breakdown_layout.addWidget(breakdown_title)

        self.behavior_summary_label = QLabel("The selected process is evaluated across behavioral rules, entropy changes, and file activity patterns.")
        self.behavior_summary_label.setWordWrap(True)
        self.behavior_summary_label.setStyleSheet("color: #d1d1d1; font-size: 11pt;")
        breakdown_layout.addWidget(self.behavior_summary_label)

        self.behavior_details_label = QLabel("Rule triggers and scoring are shown here when available.")
        self.behavior_details_label.setWordWrap(True)
        self.behavior_details_label.setStyleSheet("color: #f0f0f0; font-size: 11pt;")
        breakdown_layout.addWidget(self.behavior_details_label)

        breakdown_frame.setLayout(breakdown_layout)
        splitter.addWidget(breakdown_frame)

        # === File Activity Timeline Section ===
        timeline_frame = QFrame()
        timeline_frame.setStyleSheet("QFrame { background: #1f2430; border: 1px solid #2d3547; border-radius: 8px; padding: 12px; }")
        timeline_layout = QVBoxLayout()
        
        timeline_header_layout = QHBoxLayout()
        timeline_title = QLabel("File Activity Timeline")
        timeline_title.setStyleSheet("font-size: 16pt; font-weight: bold; color: #ffffff;")
        timeline_header_layout.addWidget(timeline_title)
        timeline_header_layout.addStretch()
        
        # Search and filter controls
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search file name, path, or extension...")
        self.search_input.setStyleSheet("background: #222938; color: white; border: 1px solid #2f3a59; padding: 6px; border-radius: 4px;")
        self.search_input.textChanged.connect(self._apply_filters)
        timeline_header_layout.addWidget(self.search_input)
        
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All Events", "Created Only", "Modified Only", "Deleted Only"])
        self.filter_combo.setStyleSheet("background: #222938; color: white; border: 1px solid #2f3a59; padding: 6px; border-radius: 4px;")
        self.filter_combo.currentIndexChanged.connect(self._apply_filters)
        timeline_header_layout.addWidget(self.filter_combo)
        
        timeline_layout.addLayout(timeline_header_layout)
        
        # Timeline table
        self.timeline_table = QTableWidget(0, 7)
        self.timeline_table.setHorizontalHeaderLabels([
            "Timestamp",
            "Event Type",
            "File Name",
            "Full Path",
            "Directory",
            "Extension",
            "Action",
        ])
        self.timeline_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.timeline_table.horizontalHeader().setStretchLastSection(False)
        self.timeline_table.setColumnWidth(0, 150)
        self.timeline_table.setColumnWidth(1, 120)
        self.timeline_table.setColumnWidth(2, 200)
        self.timeline_table.setColumnWidth(3, 300)
        self.timeline_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.timeline_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.timeline_table.setSelectionMode(QTableWidget.SingleSelection)
        self.timeline_table.setSortingEnabled(True)
        self.timeline_table.verticalHeader().setDefaultSectionSize(34)
        self.timeline_table.horizontalHeader().setFixedHeight(38)
        self.timeline_table.horizontalHeader().setFont(QFont("Segoe UI", 13, QFont.Bold))
        self.timeline_table.setFont(QFont("Segoe UI", 11))
        self.timeline_table.setStyleSheet(
            "QTableWidget { background: #171b25; font-size: 11pt; }"
            "QHeaderView::section { background: #242b3a; color: white; font-size: 13pt; font-weight: bold; padding: 8px; border: none; }"
            "QTableWidget::item { padding: 8px; }"
        )
        
        timeline_layout.addWidget(self.timeline_table)

        self.executive_summary_label = QLabel("Executive Summary: The incident summary is shown here once the selected process is reviewed.")
        self.executive_summary_label.setWordWrap(True)
        self.executive_summary_label.setStyleSheet("color: #d1d1d1; font-size: 11pt; margin-top: 10px;")
        timeline_layout.addWidget(self.executive_summary_label)

        timeline_frame.setLayout(timeline_layout)
        splitter.addWidget(timeline_frame)

        # Set splitter proportions
        splitter.setSizes([200, 150, 480])
        main_layout.addWidget(splitter)
        
        # Close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)
        close_btn.setStyleSheet("background: #2f3a59; color: white; font-weight: bold; padding: 10px; border-radius: 6px;")
        main_layout.addWidget(close_btn)
        
        self.setLayout(main_layout)
    
    def _update_classification_badge(self) -> None:
        """Update the classification badge color and text."""
        classification = self.process_data.get("classification", "Normal")
        color = self.classification_colors.get(classification, "#808080")
        self.classification_badge.setText(classification)
        self.classification_badge.setStyleSheet(
            f"background: {color}; color: white; font-weight: bold; "
            f"padding: 6px 16px; border-radius: 12px; font-size: 12px;"
        )
    
    def _populate_data(self) -> None:
        """Populate dialog with initial data."""
        self._refresh_data()
    
    def _refresh_data(self) -> None:
        """Refresh data from parent GUI."""
        # Get updated process data from parent
        if hasattr(self.parent_gui, 'process_state_cache'):
            updated_data = self.parent_gui.process_state_cache.get(self.process_key)
            if updated_data:
                self.process_data = updated_data
                self._update_info_fields()
                self._update_counters()
                self._update_classification_badge()
                self._update_timeline()
    
    def _update_info_fields(self) -> None:
        """Update general information fields."""
        for data_key, label in self.info_labels.items():
            value = self.process_data.get(data_key, "Unknown")
            label.setText(str(value))
    
    def _update_counters(self) -> None:
        """Update activity summary counters."""
        for data_key, label in self.counter_labels.items():
            value = self.process_data.get(data_key, "0")
            label.setText(str(value))
    
    def _update_timeline(self) -> None:
        """Update file activity timeline table."""
        self._extract_file_events()
        self._update_behavior_breakdown()
        self._update_executive_summary()
        self._apply_filters()

    def _update_behavior_breakdown(self) -> None:
        """Update the behavior breakdown summary section."""
        detection_entry = self.parent_gui.suspicious_process_entries.get(self.process_key, {})
        summary = detection_entry.get("reason") or self.process_data.get("reason") or "No detailed rule reasoning available."
        score = self.process_data.get("score", "0")
        classification = self.process_data.get("classification", "Unknown")
        process_name = self.process_data.get("process", "Unknown process")
        details = (
            f"Process {process_name} is currently classified as {classification} with a final suspicion score of {score}. "
            f"Primary detection reasoning: {summary}"
        )
        self.behavior_details_label.setText(details)

    def _update_executive_summary(self) -> None:
        """Generate a plain-language executive summary for the incident."""
        process_name = self.process_data.get("process", "Unknown process")
        pid = self.process_data.get("pid", "Unknown")
        severity = self.process_data.get("classification", "Unknown")
        score = self.process_data.get("score", "0")
        detection_entry = self.parent_gui.suspicious_process_entries.get(self.process_key, {})
        reason = detection_entry.get("reason") or self.process_data.get("reason") or "Suspicious file activity was detected."
        status = self.process_data.get("status", "Unknown")
        self.executive_summary_label.setText(
            f"Executive Summary: Process {process_name} (PID {pid}) is flagged as {severity} with a score of {score}. "
            f"The detection was triggered because {reason}. Current status: {status}."
        )

    def _on_quarantine_clicked(self) -> None:
        self.parent_gui._on_quarantine_alert_process()

    def _on_ignore_clicked(self) -> None:
        if hasattr(self.parent_gui, '_on_ignore_alert_process'):
            self.parent_gui._on_ignore_alert_process()

    def _on_delete_clicked(self) -> None:
        self.parent_gui._on_delete_alert_process()

    def _extract_file_events(self) -> None:
        """Extract file events from process data.
        
        Note: This is a workaround. In production, ProcessState should expose
        recent_events directly via a proper API.
        """
        # For now, we'll create mock events based on counters
        # In production, this should access ProcessState.recent_events directly
        self.file_events = []
        
        # Try to extract from parent's event logs
        if hasattr(self.parent_gui, 'event_rows'):
            pid = self.process_data.get('pid')
            executable = self.process_data.get('executable')
            
            for event in self.parent_gui.event_rows:
                if event.get('pid') == pid or event.get('executable') == executable:
                    timestamp_str = event.get('timestamp', '')
                    event_type = event.get('event_type', '')
                    file_path = event.get('file', '')
                    
                    if timestamp_str and file_path:
                        try:
                            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S").timestamp()
                            self.file_events.append((timestamp, event_type, '', file_path))
                        except Exception:
                            pass
        
        # Sort by timestamp (newest first) and limit
        self.file_events.sort(reverse=True, key=lambda x: x[0])
        self.file_events = self.file_events[:self.max_events]
    
    def _apply_filters(self) -> None:
        """Apply search and filter criteria to timeline table."""
        search_text = self.search_input.text().lower()
        filter_index = self.filter_combo.currentIndex()
        
        # Clear table
        self.timeline_table.setRowCount(0)
        self.timeline_table.setSortingEnabled(False)
        
        for timestamp, event_type, _, file_path in self.file_events:
            # Apply event type filter
            if filter_index == 1 and "CREATED" not in event_type.upper():
                continue
            elif filter_index == 2 and "MODIFIED" not in event_type.upper():
                continue
            elif filter_index == 3 and "DELETED" not in event_type.upper():
                continue
            
            # Apply search filter
            path_obj = Path(file_path)
            file_name = path_obj.name
            extension = path_obj.suffix
            directory = str(path_obj.parent)
            
            if search_text:
                if (search_text not in file_name.lower() and
                    search_text not in file_path.lower() and
                    search_text not in extension.lower()):
                    continue
            
            # Add row
            row = self.timeline_table.rowCount()
            self.timeline_table.insertRow(row)
            
            timestamp_str = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
            
            # Determine action badge
            if "CREATED" in event_type.upper():
                action = "Created"
                action_color = QColor("#007a00")
            elif "MODIFIED" in event_type.upper():
                action = "Modified"
                action_color = QColor("#003a9e")
            elif "DELETED" in event_type.upper():
                action = "Deleted"
                action_color = QColor("#a00000")
            else:
                action = "Unknown"
                action_color = QColor("#808080")
            
            items = [
                timestamp_str,
                event_type,
                file_name,
                file_path,
                directory,
                extension,
                action,
            ]
            
            for col, value in enumerate(items):
                item = QTableWidgetItem(value)
                if col == 6:  # Action column
                    item.setForeground(QBrush(action_color))
                    item.setFont(QFont("Arial", 10, QFont.Bold))
                self.timeline_table.setItem(row, col, item)
        
        self.timeline_table.setSortingEnabled(True)
    
    def closeEvent(self, event) -> None:
        """Handle dialog close event."""
        self.refresh_timer.stop()
        event.accept()


class RdrsGui(QWidget):
    def __init__(self):
        super().__init__()
        self.monitor_session: Optional[MonitorSession] = None
        self._pending_log_lines: List[str] = []
        self.event_rows: List[dict] = []
        self._displayed_event_rows: List[dict] = []
        self.suspicious_process_rows: Dict[Tuple[Optional[str], str], int] = {}
        self.suspicious_process_entries: Dict[Tuple[Optional[str], str], dict] = {}
        self._last_alert_process_key: Optional[Tuple[Optional[str], str]] = None
        self._auto_quarantine_attempted: Set[Tuple[Optional[str], str]] = set()
        self._selected_home_process_key: Optional[Tuple[Optional[str], str]] = None
        self.response_action_rows: List[dict] = []
        self.active_process_rows: Dict[Tuple[Optional[str], str], int] = {}
        self.inactive_process_rows: Dict[Tuple[Optional[str], str], int] = {}
        self.process_state_cache: Dict[Tuple[Optional[str], str], dict] = {}
        self.process_rows: Dict[Tuple[Optional[str], str], int] = {}
        self.raw_output_window = None
        self.event_count = 0
        self.start_time = None
        self.runtime_timer = QTimer()
        self.runtime_timer.setInterval(1000)
        self.runtime_timer.timeout.connect(self._update_runtime_display)
        self._ui_refresh_timer = QTimer(self)
        if _CONFIG_AVAILABLE:
            refresh_ms = int(get_config().monitoring.gui_refresh_interval_ms)
            refresh_ms = max(200, min(500, refresh_ms))
        else:
            refresh_ms = 300
        self._ui_refresh_timer.setInterval(refresh_ms)
        self._ui_refresh_timer.timeout.connect(self._flush_pending_gui_updates)
        self._pending_log_refresh = False
        self._pending_counter_refresh = False
        self._pending_process_state_refresh = False
        self._pending_suspicious_refresh = False
        self._pending_metrics_refresh = False
        self._pending_total_events_refresh = False
        self._filesystem_event_gui_queue: "queue.Queue[dict]" = queue.Queue(maxsize=10000)
        self._ui_refresh_timer.start()
        self.output_bridge = OutputBridge()
        self.output_bridge.new_raw_line.connect(self._handle_monitor_line)
        self.output_bridge.new_log_entry.connect(self.add_log_row)
        self.output_bridge.process_started.connect(self.on_process_started)
        self.output_bridge.process_stopped.connect(self.on_process_stopped)
        self.output_bridge.error_occurred.connect(self.show_error)
        self.output_bridge.entropy_alert.connect(self._on_entropy_alert_signal)
        self.output_bridge.entropy_data_updated.connect(self._refresh_entropy_table)

        # --- Entropy monitor (created lazily when monitor starts) ----------
        self._entropy_monitor: Optional[object] = None  # EntropyMonitor | None
        self._entropy_rebuild_dialog: Optional[QDialog] = None
        self._entropy_rebuild_thread: Optional[QThread] = None
        self._entropy_rebuild_worker: Optional[EntropyBuildWorker] = None
        self._entropy_rescan_thread: Optional[QThread] = None
        self._entropy_rescan_worker: Optional[EntropyRescanWorker] = None
        self._last_applied_entropy_root: Optional[str] = None

        self._log_db_event_queue: "queue.Queue[dict]" = queue.Queue(maxsize=5000)
        self._log_db_writer_running = False
        self._log_db_writer_thread: Optional[threading.Thread] = None
        self._log_db_writer_pool: Optional[ThreadPoolExecutor] = None

        # --- Alert banner state -------------------------------------------
        self._alert_banner_visible: bool = False
        # Timer to periodically refresh the entropy page data.
        self._entropy_refresh_timer = QTimer()
        self._entropy_refresh_timer.setInterval(5000)  # 5-second refresh
        self._entropy_refresh_timer.timeout.connect(self.output_bridge.entropy_data_updated.emit)
        self._entropy_refresh_in_progress = False

        # Persistent logs DB handle (available even when entropy module is not).
        self._logs_db = None
        self._alerts_db = None
        if _DATABASE_AVAILABLE:
            try:
                self._logs_db = get_logs_db()
            except Exception:
                self._logs_db = None
            try:
                self._alerts_db = get_alerts_db()
            except Exception:
                self._alerts_db = None

        self.setWindowTitle("RDRS GUI Monitor")
        self.setStyleSheet(
            "QWidget { background: #171b25; color: #f0f0f0; font-family: Segoe UI, Arial, sans-serif; }"
            "QPushButton { border: none; padding: 10px 12px; text-align: left; min-height: 40px; }"
            "QPushButton:hover { background: #2b3140; }"
            "QHeaderView::section { background: #242b3a; color: white; padding: 8px; border: none; font-size: 13pt; font-weight: bold; }"
            "QTableWidget { background: #1f2430; gridline-color: #2d3547; font-size: 11pt; }"
            "QTableWidget::item { padding: 8px; }"
        )
        self.build_ui()
        if hasattr(self, "entropy_dir_input"):
            self._last_applied_entropy_root = str(
                Path(self.entropy_dir_input.text().strip() or Path.home()).expanduser().resolve()
            )
        self._load_persisted_logs(limit=300)
        self._load_persisted_response_actions(limit=200)

    def build_ui(self):
        main_layout = QHBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        sidebar = QWidget()
        sidebar_layout = QVBoxLayout()
        sidebar_layout.setContentsMargins(16, 12, 16, 16)
        sidebar_layout.setSpacing(10)
        sidebar.setLayout(sidebar_layout)
        sidebar.setMinimumWidth(240)
        sidebar.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        sidebar.setStyleSheet("background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #171b25, stop:1 #20263a);")

        header = QLabel("RDRS Monitor")
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("font-size: 20px; font-weight: 900; margin-bottom: 18px; color: #ffffff;")
        sidebar_layout.addWidget(header)

        self.home_button = QPushButton("▶ Home")
        self.home_button.clicked.connect(lambda: self.select_page(0))
        self.home_button.setStyleSheet("font-weight: bold; color: white; background: transparent;")
        sidebar_layout.addWidget(self.home_button)

        self.incident_button = QPushButton("▶ Incident Details")
        self.incident_button.clicked.connect(lambda: self.select_page(5))
        self.incident_button.setEnabled(False)
        self.incident_button.setStyleSheet("font-weight: bold; color: white; background: transparent;")
        sidebar_layout.addWidget(self.incident_button)

        self.monitoring_button = QPushButton("▶ File Monitoring")
        self.monitoring_button.clicked.connect(lambda: self.select_page(1))
        self.monitoring_button.setStyleSheet("font-weight: bold; color: white; background: transparent;")
        sidebar_layout.addWidget(self.monitoring_button)

        self.processes_button = QPushButton("▶ Processes")
        self.processes_button.clicked.connect(lambda: self.select_page(2))
        self.processes_button.setStyleSheet("font-weight: bold; color: white; background: transparent;")
        sidebar_layout.addWidget(self.processes_button)

        self.entropy_button = QPushButton("▶ Entropy Monitor")
        self.entropy_button.clicked.connect(lambda: self.select_page(3))
        self.entropy_button.setStyleSheet("font-weight: bold; color: white; background: transparent;")
        sidebar_layout.addWidget(self.entropy_button)

        self.rules_button = QPushButton("▶ Active Rules")
        self.rules_button.clicked.connect(lambda: self.select_page(4))
        self.rules_button.setStyleSheet("font-weight: bold; color: white; background: transparent;")
        sidebar_layout.addWidget(self.rules_button)

        sidebar_layout.addSpacing(12)

        controls_label = QLabel("Monitor Settings")
        controls_label.setStyleSheet("font-size: 16pt; font-weight: bold; color: #d9d9d9; margin-top: 10px;")
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

        home_title = QLabel("Suspicious Processes")
        home_title.setStyleSheet("font-size: 17pt; font-weight: bold; color: #ffffff;")
        home_layout.addWidget(home_title)

        home_subtitle = QLabel("Review high-risk processes and open Incident Details for full forensic context.")
        home_subtitle.setStyleSheet("color: #d1d1d1; font-size: 11pt;")
        home_subtitle.setWordWrap(True)
        home_layout.addWidget(home_subtitle)

        dashboard_stats = QHBoxLayout()
        dashboard_stats.setSpacing(12)
        self.dashboard_metric_labels = {}
        for title, key in [
            ("Monitored", "monitored"),
            ("Suspicious", "suspicious"),
            ("Highest Score", "highest_score"),
            ("Current Alerts", "alerts"),
            ("Events/sec", "events_sec"),
        ]:
            card = QFrame()
            card.setStyleSheet("QFrame { background: #1f2430; border: 1px solid #2d3547; border-radius: 8px; }")
            card_layout = QVBoxLayout()
            card_layout.setContentsMargins(12, 10, 12, 10)
            card_layout.setSpacing(2)
            title_label = QLabel(title)
            title_label.setStyleSheet("color: #d1d1d1; font-size: 11px; font-weight: bold;")
            value_label = QLabel("0")
            value_label.setStyleSheet("color: #ffffff; font-size: 18px; font-weight: 900;")
            card_layout.addWidget(title_label)
            card_layout.addWidget(value_label)
            card.setLayout(card_layout)
            dashboard_stats.addWidget(card, 1)
            self.dashboard_metric_labels[key] = value_label
        home_layout.addLayout(dashboard_stats)

        # ---- Alert banner (hidden by default; shown when score >= threshold) ----
        self.alert_banner = QFrame()
        self.alert_banner.setStyleSheet(
            "QFrame { background: #8b0000; border: 2px solid #ff3333; border-radius: 8px; padding: 10px; }"
        )
        alert_banner_layout = QHBoxLayout()
        alert_banner_layout.setContentsMargins(12, 8, 12, 8)

        self._alert_icon = QLabel("🚨")
        self._alert_icon.setStyleSheet("font-size: 22px;")
        alert_banner_layout.addWidget(self._alert_icon)

        self._alert_text = QLabel("Suspicious process detected — score threshold exceeded!")
        self._alert_text.setStyleSheet("color: #ffffff; font-size: 13px; font-weight: bold;")
        self._alert_text.setWordWrap(True)
        alert_banner_layout.addWidget(self._alert_text, 1)

        # V1: Only Ignore is functional; others are visual stubs.
        _btn_style = (
            "QPushButton { background: #cc0000; color: white; font-weight: bold; "
            "padding: 6px 14px; border-radius: 5px; border: none; }"
            "QPushButton:hover { background: #e00000; }"
        )
        _stub_style = (
            "QPushButton { background: #5a1a1a; color: #aaaaaa; font-weight: bold; "
            "padding: 6px 14px; border-radius: 5px; border: 1px solid #7a2020; }"
        )

        btn_ignore = QPushButton("Ignore")
        btn_ignore.setStyleSheet(_btn_style)
        btn_ignore.clicked.connect(self._on_ignore_alert_process)
        alert_banner_layout.addWidget(btn_ignore)

        btn_quarantine = QPushButton("Quarantine")
        btn_quarantine.setStyleSheet(
            "QPushButton { background: #b36b00; color: white; font-weight: bold; "
            "padding: 6px 14px; border-radius: 5px; border: none; }"
            "QPushButton:hover { background: #cc7a00; }"
        )
        btn_quarantine.setToolTip("Terminate the detected process and move its executable to quarantine.")
        btn_quarantine.clicked.connect(self._on_quarantine_alert_process)
        alert_banner_layout.addWidget(btn_quarantine)

        btn_delete = QPushButton("Delete")
        btn_delete.setStyleSheet(
            "QPushButton { background: #a00000; color: white; font-weight: bold; "
            "padding: 6px 14px; border-radius: 5px; border: none; }"
            "QPushButton:hover { background: #c00000; }"
        )
        btn_delete.setToolTip("Terminate the detected process and delete its executable from disk.")
        btn_delete.clicked.connect(self._on_delete_alert_process)
        alert_banner_layout.addWidget(btn_delete)

        btn_more = QPushButton("More Information")
        btn_more.setStyleSheet(_stub_style)
        btn_more.setToolTip("Not yet implemented in v1.0")
        alert_banner_layout.addWidget(btn_more)

        self.alert_banner.setLayout(alert_banner_layout)
        self.alert_banner.setVisible(False)
        home_layout.addWidget(self.alert_banner)

        self.home_table = QTableWidget(0, 6)
        self.home_table.setHorizontalHeaderLabels([
            "Process Name",
            "PID",
            "Suspicion Score",
            "Severity",
            "Detection Time",
            "Current Status",
        ])
        self.home_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.home_table.horizontalHeader().setStretchLastSection(False)
        self.home_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.home_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.home_table.setSelectionMode(QTableWidget.SingleSelection)
        self.home_table.setAlternatingRowColors(True)
        self.home_table.setMinimumHeight(220)
        self.home_table.itemSelectionChanged.connect(self._on_home_selection_changed)
        self.home_table.doubleClicked.connect(lambda _: self._open_selected_incident_details())
        self.home_table.setSelectionMode(QTableWidget.SingleSelection)
        self.home_table.setSelectionBehavior(QTableWidget.SelectRows)

        self.home_details_button = QPushButton("View Incident Details")
        self.home_details_button.setStyleSheet(
            "background: #2f3a59; color: #ffffff; font-weight: bold; padding: 10px 14px; border-radius: 6px;"
        )
        self.home_details_button.setEnabled(False)
        self.home_details_button.clicked.connect(self._open_selected_incident_details)

        self.home_export_button = QPushButton("Export Incident JSON")
        self.home_export_button.setStyleSheet(
            "background: #2f3a59; color: #ffffff; font-weight: bold; padding: 10px 14px; border-radius: 6px;"
        )
        self.home_export_button.setEnabled(False)
        self.home_export_button.clicked.connect(self._export_selected_home_incident_json)

        self.home_action_buttons = QHBoxLayout()
        self.home_action_buttons.setSpacing(12)
        self.home_action_buttons.addStretch()
        self.home_action_buttons.addWidget(self.home_details_button)
        self.home_action_buttons.addWidget(self.home_export_button)

        self.home_selection_hint = QLabel(
            "Select a suspicious process and open Incident Details to review timeline, affected files, and response actions."
        )
        self.home_selection_hint.setWordWrap(True)
        self.home_selection_hint.setStyleSheet("color: #d1d1d1; font-size: 11pt;")

        home_layout.addWidget(self.home_selection_hint)
        home_layout.addWidget(self.home_table)
        home_layout.addLayout(self.home_action_buttons)
        self.page_stack.addWidget(self.home_page)

        self.file_monitoring_page = QWidget()
        file_layout = QVBoxLayout()
        file_layout.setContentsMargins(24, 24, 24, 24)
        file_layout.setSpacing(14)
        self.file_monitoring_page.setLayout(file_layout)

        file_title = QLabel("File Monitoring")
        file_title.setStyleSheet("font-size: 17pt; font-weight: bold; color: #ffffff;")
        file_layout.addWidget(file_title)

        file_toolbar = QHBoxLayout()
        file_toolbar.setSpacing(10)

        search_label = QLabel("Search:")
        search_label.setStyleSheet("color: #d9d9d9;")
        file_toolbar.addWidget(search_label)

        self.log_search_input = QLineEdit()
        self.log_search_input.setPlaceholderText("File, process, PID, or message")
        self.log_search_input.setStyleSheet("background: #222938; color: white; border: 1px solid #2f3a59; padding: 6px; border-radius: 4px;")
        self.log_search_input.textChanged.connect(self._refresh_log_table_view)
        file_toolbar.addWidget(self.log_search_input, 1)

        filter_label = QLabel("Type:")
        filter_label.setStyleSheet("color: #d9d9d9;")
        file_toolbar.addWidget(filter_label)

        self.log_filter_combo = QComboBox()
        self.log_filter_combo.addItems(["All Events", "FILE CREATED", "FILE MODIFIED", "FILE DELETED", "FILE MOVED", "EXTENSION_CHANGE", "DETECTION", "PROCESS_STATE"])
        self.log_filter_combo.currentIndexChanged.connect(self._refresh_log_table_view)
        self.log_filter_combo.setStyleSheet("background: #222938; color: white; border: 1px solid #2f3a59; padding: 6px; border-radius: 4px;")
        file_toolbar.addWidget(self.log_filter_combo)

        file_layout.addLayout(file_toolbar)

        file_stats_row = QHBoxLayout()
        file_stats_row.setSpacing(10)
        self.file_event_counter_labels = {}
        for label_text, key, color in [
            ("Created", "FILE CREATED", "#007a00"),
            ("Modified", "FILE MODIFIED", "#003a9e"),
            ("Moved", "FILE MOVED", "#ff9800"),
            ("Deleted", "FILE DELETED", "#a00000"),
            ("Ext. Changed", "EXTENSION_CHANGE", "#e91e63"),
        ]:
            counter = QLabel(f"{label_text}: 0")
            counter.setStyleSheet(
                f"background: #1f2430; border: 1px solid #2d3547; border-radius: 6px; "
                f"padding: 8px 12px; font-size: 11pt; font-weight: bold; color: {color};"
            )
            file_stats_row.addWidget(counter)
            self.file_event_counter_labels[key] = counter
        file_stats_row.addStretch()
        file_layout.addLayout(file_stats_row)

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
        self.log_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.log_table.horizontalHeader().setStretchLastSection(False)
        self.log_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.log_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.log_table.setSelectionMode(QTableWidget.SingleSelection)
        self.log_table.setColumnCount(10)
        self.log_table.setAlternatingRowColors(True)
        self.log_table.itemSelectionChanged.connect(self.on_table_selection_changed)
        file_layout.addWidget(self.log_table)

        raw_output_btn = QPushButton("View Raw Output")
        raw_output_btn.clicked.connect(self.show_raw_output_window)
        raw_output_btn.setStyleSheet("background: #2f3a59; color: #ffffff; font-weight: bold; margin-top: 8px; padding: 10px;")
        file_layout.addWidget(raw_output_btn)

        self.page_stack.addWidget(self.file_monitoring_page)

        self.processes_page = QWidget()
        processes_layout = QVBoxLayout()
        processes_layout.setContentsMargins(24, 24, 24, 24)
        processes_layout.setSpacing(14)
        self.processes_page.setLayout(processes_layout)

        processes_title = QLabel("Processes")
        processes_title.setStyleSheet("font-size: 17pt; font-weight: bold; color: #ffffff;")
        processes_layout.addWidget(processes_title)

        process_description = QLabel("Active and inactive process summaries are shown here. Each row reflects the current process state from the monitor.")
        process_description.setWordWrap(True)
        process_description.setStyleSheet("color: #d1d1d1; font-size: 12px; margin-bottom: 10px;")
        processes_layout.addWidget(process_description)

        processes_split_layout = QSplitter(Qt.Vertical)
        processes_split_layout.setChildrenCollapsible(False)
        processes_split_layout.setHandleWidth(8)

        active_container = QWidget()
        active_layout = QVBoxLayout()
        active_layout.setContentsMargins(0, 0, 0, 0)
        active_layout.setSpacing(8)
        active_container.setLayout(active_layout)

        active_label = QLabel("Active Processes")
        active_label.setStyleSheet("font-size: 16pt; font-weight: bold; color: #ffffff;")
        active_layout.addWidget(active_label)

        self.active_process_table = QTableWidget(0, 7)
        self.active_process_table.setHorizontalHeaderLabels([
            "Process Name",
            "PID",
            "Files Modified",
            "Events/sec",
            "Current Score",
            "Status",
            "Last Activity",
        ])
        self.active_process_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.active_process_table.horizontalHeader().setStretchLastSection(False)
        self.active_process_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.active_process_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.active_process_table.setSelectionMode(QTableWidget.SingleSelection)
        self.active_process_table.setAlternatingRowColors(True)
        self.active_process_table.doubleClicked.connect(self.on_process_double_click)
        active_layout.addWidget(self.active_process_table)

        inactive_container = QWidget()
        inactive_layout = QVBoxLayout()
        inactive_layout.setContentsMargins(0, 0, 0, 0)
        inactive_layout.setSpacing(8)
        inactive_container.setLayout(inactive_layout)

        inactive_label = QLabel("Inactive Processes")
        inactive_label.setStyleSheet("font-size: 16pt; font-weight: bold; color: #ffffff;")
        inactive_layout.addWidget(inactive_label)

        self.inactive_process_table = QTableWidget(0, 7)
        self.inactive_process_table.setHorizontalHeaderLabels([
            "Process Name",
            "PID",
            "Files Modified",
            "Events/sec",
            "Current Score",
            "Status",
            "Last Activity",
        ])
        self.inactive_process_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.inactive_process_table.horizontalHeader().setStretchLastSection(False)
        self.inactive_process_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.inactive_process_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.inactive_process_table.setSelectionMode(QTableWidget.SingleSelection)
        self.inactive_process_table.setAlternatingRowColors(True)
        self.inactive_process_table.doubleClicked.connect(self.on_process_double_click)
        inactive_layout.addWidget(self.inactive_process_table)

        processes_split_layout.addWidget(active_container)
        processes_split_layout.addWidget(inactive_container)
        processes_split_layout.setSizes([420, 420])
        processes_layout.addWidget(processes_split_layout, 1)
        self.page_stack.addWidget(self.processes_page)

        # ---- Entropy Monitor page ----------------------------------------
        self.entropy_page = QWidget()
        entropy_layout = QVBoxLayout()
        entropy_layout.setContentsMargins(20, 14, 20, 18)
        entropy_layout.setSpacing(10)
        self.entropy_page.setLayout(entropy_layout)

        entropy_title = QLabel("Entropy Monitor")
        entropy_title.setStyleSheet("font-size: 17pt; font-weight: bold; color: #ffffff;")
        entropy_layout.addWidget(entropy_title)

        entropy_desc = QLabel(
            "Displays entropy values for monitored files. "
            "High entropy increases may indicate encryption by ransomware."
        )
        entropy_desc.setWordWrap(True)
        entropy_desc.setStyleSheet("color: #d1d1d1; font-size: 11pt; margin-bottom: 2px;")
        entropy_layout.addWidget(entropy_desc)

        # Toolbar row (directory selector + refresh button)
        entropy_toolbar = QHBoxLayout()

        entropy_dir_label = QLabel("Directory:")
        entropy_dir_label.setStyleSheet("color: #d9d9d9;")
        entropy_toolbar.addWidget(entropy_dir_label)

        self.entropy_dir_input = QLineEdit(str(Path.home()))
        self.entropy_dir_input.setStyleSheet(
            "background: #222938; color: white; border: 1px solid #2f3a59; padding: 6px; border-radius: 4px;"
        )
        self.entropy_dir_input.setPlaceholderText("Entropy monitoring directory…")
        self.entropy_dir_input.editingFinished.connect(self._on_set_entropy_directory_clicked)
        entropy_toolbar.addWidget(self.entropy_dir_input, 1)

        btn_refresh_entropy = QPushButton("↻ Refresh")
        btn_refresh_entropy.clicked.connect(self._run_manual_entropy_refresh)
        btn_refresh_entropy.setStyleSheet(
            "background: #2f3a59; color: white; font-weight: bold; padding: 8px 16px; border-radius: 4px;"
        )
        entropy_toolbar.addWidget(btn_refresh_entropy)

        btn_apply_entropy_dir = QPushButton("Apply Entropy Directory")
        btn_apply_entropy_dir.clicked.connect(self._on_set_entropy_directory_clicked)
        btn_apply_entropy_dir.setStyleSheet(
            "background: #345f2f; color: white; font-weight: bold; padding: 8px 16px; border-radius: 4px;"
        )
        entropy_toolbar.addWidget(btn_apply_entropy_dir)

        entropy_layout.addLayout(entropy_toolbar)

        # Status label for entropy module state
        self.entropy_status_label = QLabel(
            "⚠ Entropy module not available — install the 'entropy' and 'database' packages."
            if not _ENTROPY_AVAILABLE else
            "Entropy module ready.  Start the monitor to begin tracking."
        )
        self.entropy_status_label.setStyleSheet("color: #ff9800; font-size: 11pt;")
        self.entropy_status_label.setWordWrap(True)
        entropy_layout.addWidget(self.entropy_status_label)

        entropy_content_split = QSplitter(Qt.Horizontal)
        entropy_content_split.setChildrenCollapsible(False)
        entropy_content_split.setHandleWidth(8)

        # SOC-style condensed table: critical fields only
        self.entropy_table = QTableWidget(0, 4)
        self.entropy_table.setHorizontalHeaderLabels([
            "File Name",
            "Current Entropy",
            "Δ Entropy",
            "Status",
        ])
        self.entropy_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.entropy_table.horizontalHeader().setStretchLastSection(False)
        self.entropy_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.entropy_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.entropy_table.setSelectionMode(QTableWidget.SingleSelection)
        self.entropy_table.setSortingEnabled(True)
        self.entropy_table.setAlternatingRowColors(True)
        self.entropy_table.itemSelectionChanged.connect(self._on_entropy_selection_changed)
        entropy_content_split.addWidget(self.entropy_table)

        self.entropy_details_panel = QFrame()
        self.entropy_details_panel.setStyleSheet(
            "QFrame { background: #1f2430; border: 1px solid #2d3547; border-radius: 8px; }"
        )
        details_layout = QVBoxLayout()
        details_layout.setContentsMargins(14, 14, 14, 14)
        details_layout.setSpacing(10)
        self.entropy_details_panel.setLayout(details_layout)

        details_title = QLabel("Selected File Details")
        details_title.setStyleSheet("font-size: 16pt; font-weight: bold; color: #ffffff;")
        details_layout.addWidget(details_title)

        self.entropy_details_hint = QLabel("Select a row to inspect previous entropy, scan time, and file size.")
        self.entropy_details_hint.setWordWrap(True)
        self.entropy_details_hint.setStyleSheet("color: #d1d1d1; font-size: 11pt;")
        details_layout.addWidget(self.entropy_details_hint)

        self.entropy_detail_labels = {}
        detail_fields = [
            ("File Name", "file_name"),
            ("Current Entropy", "current_entropy"),
            ("Previous Entropy", "previous_entropy"),
            ("Delta Entropy", "delta_entropy"),
            ("File Size", "file_size"),
            ("Last Scan", "last_scan"),
            ("Status", "status"),
        ]
        for title, key in detail_fields:
            label = QLabel(f"{title}: —")
            label.setWordWrap(True)
            label.setStyleSheet("color: #f0f0f0; font-size: 11pt;")
            details_layout.addWidget(label)
            self.entropy_detail_labels[key] = label
        details_layout.addStretch()

        entropy_content_split.addWidget(self.entropy_details_panel)
        entropy_content_split.setSizes([1000, 360])
        entropy_layout.addWidget(entropy_content_split, 1)

        self.page_stack.addWidget(self.entropy_page)

        # ---- Active Rules page --------------------------------------------
        self.rules_page = QWidget()
        rules_layout = QVBoxLayout()
        rules_layout.setContentsMargins(24, 24, 24, 24)
        rules_layout.setSpacing(16)
        self.rules_page.setLayout(rules_layout)

        rules_title = QLabel("Active Rules")
        rules_title.setStyleSheet("font-size: 17pt; font-weight: bold; color: #ffffff;")
        rules_layout.addWidget(rules_title)

        rules_desc = QLabel(
            "Behavioral detection rules that increase a process's suspicion score. "
            "Untick a rule to disable it entirely, or edit its score to change how "
            "much it contributes once triggered. Click a rule to see full details. "
            "Changes apply immediately and are saved to config.yaml."
        )
        rules_desc.setWordWrap(True)
        rules_desc.setStyleSheet("color: #d1d1d1; font-size: 11pt; margin-bottom: 2px;")
        rules_layout.addWidget(rules_desc)

        self.rules_save_status_label = QLabel("")
        self.rules_save_status_label.setStyleSheet("color: #4CAF50; font-size: 10pt;")
        self.rules_save_status_label.setWordWrap(True)
        rules_layout.addWidget(self.rules_save_status_label)

        rules_content_split = QSplitter(Qt.Horizontal)
        rules_content_split.setChildrenCollapsible(False)
        rules_content_split.setHandleWidth(8)

        self.rules_table = QTableWidget(0, 4)
        self.rules_table.setHorizontalHeaderLabels([
            "Rule",
            "Description",
            "Enabled",
            "Score",
        ])
        self.rules_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.rules_table.horizontalHeader().setStretchLastSection(True)
        self.rules_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.rules_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.rules_table.setSelectionMode(QTableWidget.SingleSelection)
        self.rules_table.setAlternatingRowColors(True)
        self.rules_table.setWordWrap(True)
        self.rules_table.verticalHeader().setVisible(False)
        self.rules_table.itemSelectionChanged.connect(self._on_rule_row_selected)
        rules_content_split.addWidget(self.rules_table)

        self.rule_details_panel = QFrame()
        self.rule_details_panel.setStyleSheet(
            "QFrame { background: #1f2430; border: 1px solid #2d3547; border-radius: 8px; }"
        )
        rule_details_layout = QVBoxLayout()
        rule_details_layout.setContentsMargins(18, 18, 18, 18)
        rule_details_layout.setSpacing(12)
        self.rule_details_panel.setLayout(rule_details_layout)

        self.rule_details_title = QLabel("Select a rule")
        self.rule_details_title.setWordWrap(True)
        self.rule_details_title.setStyleSheet("font-size: 16pt; font-weight: bold; color: #ffffff;")
        rule_details_layout.addWidget(self.rule_details_title)

        self.rule_details_hint = QLabel("Click a rule on the left to see its full description, trigger conditions, and current settings.")
        self.rule_details_hint.setWordWrap(True)
        self.rule_details_hint.setStyleSheet("color: #d1d1d1; font-size: 11pt;")
        rule_details_layout.addWidget(self.rule_details_hint)

        self.rule_details_labels = {}
        for title, key in [
            ("Status", "status"),
            ("Current Score", "score"),
            ("Trigger Condition", "trigger"),
        ]:
            field_label = QLabel(f"{title}:")
            field_label.setStyleSheet("color: #9aa4b8; font-size: 10pt; font-weight: bold; margin-top: 6px;")
            rule_details_layout.addWidget(field_label)

            value_label = QLabel("—")
            value_label.setWordWrap(True)
            value_label.setStyleSheet("color: #f0f0f0; font-size: 12pt;")
            rule_details_layout.addWidget(value_label)
            self.rule_details_labels[key] = value_label

        rule_details_layout.addStretch()

        rules_content_split.addWidget(self.rule_details_panel)
        rules_content_split.setSizes([900, 420])
        rules_layout.addWidget(rules_content_split, 1)

        if not _CONFIG_AVAILABLE:
            self.rules_save_status_label.setStyleSheet("color: #ff9800; font-size: 10pt;")
            self.rules_save_status_label.setText(
                "⚠ Config module not available — rule editing is disabled."
            )
            self.rules_table.setEnabled(False)

        self.page_stack.addWidget(self.rules_page)

        self.incident_page = QWidget()
        incident_layout = QVBoxLayout()
        incident_layout.setContentsMargins(24, 24, 24, 24)
        incident_layout.setSpacing(12)
        self.incident_page.setLayout(incident_layout)

        incident_header_row = QHBoxLayout()
        incident_header_row.setSpacing(10)

        self.incident_back_button = QPushButton("← Back To Home")
        self.incident_back_button.setStyleSheet(
            "background: #2f3a59; color: #ffffff; font-weight: bold; padding: 8px 12px; border-radius: 6px;"
        )
        self.incident_back_button.clicked.connect(lambda: self.select_page(0))
        incident_header_row.addWidget(self.incident_back_button)

        incident_title = QLabel("Incident Details")
        incident_title.setStyleSheet("font-size: 17pt; font-weight: bold; color: #ffffff;")
        incident_header_row.addWidget(incident_title)
        incident_header_row.addStretch()

        self.incident_quarantine_button = QPushButton("Quarantine Process")
        self.incident_quarantine_button.setStyleSheet(
            "QPushButton { background: #b36b00; color: white; font-weight: bold; padding: 8px 12px; border-radius: 6px; }"
            "QPushButton:hover { background: #cc7a00; }"
        )
        self.incident_quarantine_button.clicked.connect(self._on_quarantine_alert_process)
        incident_header_row.addWidget(self.incident_quarantine_button)

        self.incident_ignore_button = QPushButton("Ignore Detection")
        self.incident_ignore_button.setStyleSheet(
            "QPushButton { background: #5a1a1a; color: white; font-weight: bold; padding: 8px 12px; border-radius: 6px; }"
            "QPushButton:hover { background: #6f2222; }"
        )
        self.incident_ignore_button.clicked.connect(self._on_ignore_alert_process)
        incident_header_row.addWidget(self.incident_ignore_button)

        self.incident_terminate_button = QPushButton("Remove / Terminate Process")
        self.incident_terminate_button.setStyleSheet(
            "QPushButton { background: #a00000; color: white; font-weight: bold; padding: 8px 12px; border-radius: 6px; }"
            "QPushButton:hover { background: #c00000; }"
        )
        self.incident_terminate_button.clicked.connect(self._on_delete_alert_process)
        incident_header_row.addWidget(self.incident_terminate_button)

        incident_layout.addLayout(incident_header_row)

        self.incident_context_hint = QLabel("Select a suspicious process from Home to view this page.")
        self.incident_context_hint.setStyleSheet("color: #d1d1d1; font-size: 11pt;")
        self.incident_context_hint.setWordWrap(True)
        incident_layout.addWidget(self.incident_context_hint)

        summary_frame = QFrame()
        summary_frame.setStyleSheet("QFrame { background: #1f2430; border: 1px solid #2d3547; border-radius: 8px; }")
        summary_layout = QVBoxLayout()
        summary_layout.setContentsMargins(12, 12, 12, 12)
        summary_layout.setSpacing(6)
        summary_frame.setLayout(summary_layout)

        summary_title = QLabel("Incident Summary")
        summary_title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #ffffff;")
        summary_layout.addWidget(summary_title)

        self.incident_summary_labels = {}
        for title, key in [
            ("Process Name", "process"),
            ("PID", "pid"),
            ("Detection Time", "detection_time"),
            ("Severity", "severity"),
            ("Final Suspicion Score", "score"),
            ("Current Status", "status"),
        ]:
            label = QLabel(f"{title}: —")
            label.setStyleSheet("color: #f0f0f0; font-size: 11pt;")
            label.setWordWrap(True)
            self.incident_summary_labels[key] = label
            summary_layout.addWidget(label)

        incident_layout.addWidget(summary_frame)

        detail_split = QSplitter(Qt.Horizontal)
        detail_split.setChildrenCollapsible(False)
        detail_split.setHandleWidth(8)

        timeline_container = QFrame()
        timeline_container.setStyleSheet("QFrame { background: #1f2430; border: 1px solid #2d3547; border-radius: 8px; }")
        timeline_layout = QVBoxLayout()
        timeline_layout.setContentsMargins(12, 12, 12, 12)
        timeline_layout.setSpacing(8)
        timeline_container.setLayout(timeline_layout)
        timeline_title = QLabel("Detection Timeline")
        timeline_title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #ffffff;")
        timeline_layout.addWidget(timeline_title)

        self.incident_timeline_table = QTableWidget(0, 5)
        self.incident_timeline_table.setHorizontalHeaderLabels([
            "Time",
            "Event",
            "File",
            "Rule",
            "Details",
        ])
        self.incident_timeline_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.incident_timeline_table.horizontalHeader().setStretchLastSection(False)
        self.incident_timeline_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.incident_timeline_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.incident_timeline_table.setSelectionMode(QTableWidget.SingleSelection)
        self.incident_timeline_table.setAlternatingRowColors(True)
        timeline_layout.addWidget(self.incident_timeline_table)
        detail_split.addWidget(timeline_container)

        right_panel = QFrame()
        right_panel.setStyleSheet("QFrame { background: #1f2430; border: 1px solid #2d3547; border-radius: 8px; }")
        right_layout = QVBoxLayout()
        right_layout.setContentsMargins(12, 12, 12, 12)
        right_layout.setSpacing(10)
        right_panel.setLayout(right_layout)

        affected_title = QLabel("Affected Files")
        affected_title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #ffffff;")
        right_layout.addWidget(affected_title)

        self.incident_files_table = QTableWidget(0, 4)
        self.incident_files_table.setHorizontalHeaderLabels([
            "File Path",
            "Extension Change",
            "Entropy Change",
            "Last Event",
        ])
        self.incident_files_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.incident_files_table.horizontalHeader().setStretchLastSection(False)
        self.incident_files_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.incident_files_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.incident_files_table.setSelectionMode(QTableWidget.SingleSelection)
        self.incident_files_table.setAlternatingRowColors(True)
        right_layout.addWidget(self.incident_files_table)

        behavior_title = QLabel("Behavior Breakdown")
        behavior_title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #ffffff;")
        right_layout.addWidget(behavior_title)

        self.incident_behavior_table = QTableWidget(0, 3)
        self.incident_behavior_table.setHorizontalHeaderLabels([
            "Rule",
            "Score",
            "Reasoning",
        ])
        self.incident_behavior_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.incident_behavior_table.horizontalHeader().setStretchLastSection(False)
        self.incident_behavior_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.incident_behavior_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.incident_behavior_table.setSelectionMode(QTableWidget.SingleSelection)
        self.incident_behavior_table.setAlternatingRowColors(True)
        right_layout.addWidget(self.incident_behavior_table)

        self.incident_total_score_label = QLabel("Total Score: 0")
        self.incident_total_score_label.setStyleSheet("color: #ffffff; font-size: 11pt; font-weight: bold;")
        right_layout.addWidget(self.incident_total_score_label)

        executive_title = QLabel("Executive Summary")
        executive_title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #ffffff;")
        right_layout.addWidget(executive_title)

        self.incident_executive_summary = QLabel("No incident selected.")
        self.incident_executive_summary.setStyleSheet("color: #d1d1d1; font-size: 11pt;")
        self.incident_executive_summary.setWordWrap(True)
        right_layout.addWidget(self.incident_executive_summary)
        right_layout.addStretch()

        detail_split.addWidget(right_panel)
        detail_split.setSizes([900, 720])
        incident_layout.addWidget(detail_split, 1)

        self.page_stack.addWidget(self.incident_page)

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

        self.version_label = QLabel(APP_VERSION)
        self.version_label.setStyleSheet("color: #9fb3d1; font-weight: 600;")
        self.version_label.setAlignment(Qt.AlignRight | Qt.AlignBottom)
        self.version_label.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Minimum)
        bottom_layout.addWidget(self.version_label, 0, Qt.AlignRight | Qt.AlignBottom)
        self._update_version_label_font()

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
        self._apply_readability_to_tables()
        self._set_initial_column_widths()
        self._populate_rules_table()
        self.select_page(0)

        self.select_page(0)

    def _apply_readability_to_tables(self) -> None:
        """Apply consistent readability settings across all primary tables."""
        tables = [
            self.home_table,
            self.log_table,
            self.active_process_table,
            self.inactive_process_table,
            self.entropy_table,
            self.rules_table,
            self.incident_timeline_table,
            self.incident_files_table,
            self.incident_behavior_table,
        ]
        for table in tables:
            table.setFont(QFont("Segoe UI", 11))
            table.verticalHeader().setDefaultSectionSize(34)
            table.horizontalHeader().setFixedHeight(38)
            table.horizontalHeader().setFont(QFont("Segoe UI", 13, QFont.Bold))
            table.setStyleSheet(
                "QTableWidget { background: #1f2430; font-size: 11pt; color: #f0f0f0; }"
                "QTableWidget::item { padding: 8px; color: #f0f0f0; background: #1f2430; }"
                "QTableWidget::item:selected { background: #2f3f58; color: #ffffff; }"
                "QTableWidget::item:selected:!active { background: #27364d; color: #f0f0f0; }"
                "QHeaderView::section { background: #242b3a; color: white; font-size: 13pt; font-weight: bold; padding: 8px; border: none; }"
            )

        # The Active Rules table hosts wrapped descriptions plus embedded
        # checkboxes/spin boxes, so it needs noticeably more vertical
        # breathing room than the plain-text tables above (avoids the
        # cramped look of a fixed 34px row).
        self.rules_table.verticalHeader().setDefaultSectionSize(72)
        self.rules_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Interactive)
        self.rules_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.rules_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Fixed)
        self.rules_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Fixed)
        self.rules_table.horizontalHeader().setStretchLastSection(False)

    def _set_initial_column_widths(self) -> None:
        """Set non-uniform default column widths for readability."""
        self.home_table.setColumnWidth(0, 260)
        self.home_table.setColumnWidth(1, 90)
        self.home_table.setColumnWidth(2, 140)
        self.home_table.setColumnWidth(3, 120)
        self.home_table.setColumnWidth(4, 220)
        self.home_table.setColumnWidth(5, 170)
        if hasattr(self, "home_response_table"):
            self.home_response_table.setColumnWidth(0, 170)
            self.home_response_table.setColumnWidth(1, 120)
            self.home_response_table.setColumnWidth(2, 320)
            self.home_response_table.setColumnWidth(3, 120)
            self.home_response_table.setColumnWidth(4, 440)

        self.log_table.setColumnWidth(0, 180)
        self.log_table.setColumnWidth(1, 90)
        self.log_table.setColumnWidth(2, 140)
        self.log_table.setColumnWidth(3, 340)
        self.log_table.setColumnWidth(4, 230)
        self.log_table.setColumnWidth(5, 170)
        self.log_table.setColumnWidth(6, 90)
        self.log_table.setColumnWidth(7, 300)
        self.log_table.setColumnWidth(8, 190)
        self.log_table.setColumnWidth(9, 360)

        for table in (self.active_process_table, self.inactive_process_table):
            table.setColumnWidth(0, 260)
            table.setColumnWidth(1, 90)
            table.setColumnWidth(2, 140)
            table.setColumnWidth(3, 120)
            table.setColumnWidth(4, 130)
            table.setColumnWidth(5, 130)
            table.setColumnWidth(6, 190)

        self.rules_table.setColumnWidth(0, 240)
        self.rules_table.setColumnWidth(2, 90)
        self.rules_table.setColumnWidth(3, 100)

        self.incident_timeline_table.setColumnWidth(0, 170)
        self.incident_timeline_table.setColumnWidth(1, 180)
        self.incident_timeline_table.setColumnWidth(2, 330)
        self.incident_timeline_table.setColumnWidth(3, 190)
        self.incident_timeline_table.setColumnWidth(4, 450)

        self.incident_files_table.setColumnWidth(0, 420)
        self.incident_files_table.setColumnWidth(1, 170)
        self.incident_files_table.setColumnWidth(2, 150)
        self.incident_files_table.setColumnWidth(3, 220)

        self.incident_behavior_table.setColumnWidth(0, 220)
        self.incident_behavior_table.setColumnWidth(1, 90)
        self.incident_behavior_table.setColumnWidth(2, 450)

    def _resize_entropy_columns(self) -> None:
        """Keep File Name at ~45% while sizing other columns to content."""
        available = max(400, self.entropy_table.viewport().width())
        file_name_width = int(available * 0.45)

        self.entropy_table.setColumnWidth(1, max(180, self.entropy_table.sizeHintForColumn(1) + 20))
        self.entropy_table.setColumnWidth(2, max(150, self.entropy_table.sizeHintForColumn(2) + 20))
        self.entropy_table.setColumnWidth(3, max(120, self.entropy_table.sizeHintForColumn(3) + 20))
        self.entropy_table.setColumnWidth(0, file_name_width)

    def _update_version_label_font(self) -> None:
        """Keep the footer version text small while allowing gentle resize scaling."""
        if not hasattr(self, "version_label"):
            return

        width = max(0, self.width())
        point_size = 8.0
        if width >= 1200:
            point_size = 9.0
        if width >= 1600:
            point_size = 10.0
        if width >= 2000:
            point_size = 11.0

        font = self.version_label.font()
        font.setPointSizeF(point_size)
        self.version_label.setFont(font)

    def resizeEvent(self, event) -> None:
        """Keep responsive table proportions as the window size changes."""
        super().resizeEvent(event)
        if hasattr(self, "entropy_table"):
            self._resize_entropy_columns()
        self._update_version_label_font()

    def select_page(self, index: int):
        self.page_stack.setCurrentIndex(index)
        # Reset all buttons to inactive style
        _inactive = (
            "font-size: 12pt; font-weight: bold; color: #ffffff; background: transparent; "
            "min-height: 40px; padding: 8px 12px; text-align: left; border-radius: 8px;"
        )
        _active = (
            "font-size: 12pt; font-weight: bold; color: white; background: #2d3a5a; "
            "min-height: 40px; padding: 8px 12px; text-align: left; border-radius: 8px;"
        )

        self.home_button.setStyleSheet(_inactive)
        self.incident_button.setStyleSheet(_inactive)
        self.monitoring_button.setStyleSheet(_inactive)
        self.processes_button.setStyleSheet(_inactive)
        self.entropy_button.setStyleSheet(_inactive)
        self.rules_button.setStyleSheet(_inactive)

        self.home_button.setText("▶ Home")
        self.incident_button.setText("▶ Incident Details")
        self.monitoring_button.setText("▶ File Monitoring")
        self.processes_button.setText("▶ Processes")
        self.entropy_button.setText("▶ Entropy Monitor")
        self.rules_button.setText("▶ Active Rules")

        if index == 0:
            self.home_button.setText("▼ Home")
            self.home_button.setStyleSheet(_active)
        elif index == 5:
            self.incident_button.setText("▼ Incident Details")
            self.incident_button.setStyleSheet(_active)
        elif index == 1:
            self.monitoring_button.setText("▼ File Monitoring")
            self.monitoring_button.setStyleSheet(_active)
        elif index == 2:
            self.processes_button.setText("▼ Processes")
            self.processes_button.setStyleSheet(_active)
        elif index == 3:
            self.entropy_button.setText("▼ Entropy Monitor")
            self.entropy_button.setStyleSheet(_active)
            self._refresh_entropy_table()
        elif index == 4:
            self.rules_button.setText("▼ Active Rules")
            self.rules_button.setStyleSheet(_active)

    def _populate_rules_table(self) -> None:
        """Populate the Active Rules table from the current configuration.

        Each row represents one scoring rule (e.g. Rule1_FileBurst) with a
        checkbox (DetectionConfig.rule_enabled) and an editable score spin
        box (DetectionConfig.rule_weights). Edits are persisted immediately
        via config.save_rule_settings(), which updates both the live config
        and config.yaml on disk.
        """
        if not _CONFIG_AVAILABLE:
            return

        # Guard flag: suppresses save-on-change while widgets are being
        # populated programmatically (setChecked/setValue would otherwise
        # fire the same signals as a real user edit).
        self._rules_table_loading = True
        try:
            cfg = get_config().detection
            ecfg = get_config().entropy
            # Entropy is appended last: its weight/enabled flag live in
            # config.entropy rather than config.detection.rule_weights, but
            # it is displayed and edited identically to the other rules.
            rule_names = list(cfg.rule_weights.keys()) + [_ENTROPY_RULE_NAME]
            self.rules_table.setRowCount(len(rule_names))

            for row, rule_name in enumerate(rule_names):
                name_item = QTableWidgetItem(rule_name)
                name_item.setFlags(name_item.flags() & ~Qt.ItemIsEditable)
                self.rules_table.setItem(row, 0, name_item)

                description = _RULE_DESCRIPTIONS.get(rule_name, "Custom detection rule.")
                desc_item = QTableWidgetItem(description)
                desc_item.setFlags(desc_item.flags() & ~Qt.ItemIsEditable)
                desc_item.setToolTip(description)
                self.rules_table.setItem(row, 1, desc_item)

                if rule_name == _ENTROPY_RULE_NAME:
                    row_enabled = bool(ecfg.enabled)
                    row_score = int(ecfg.score)
                else:
                    row_enabled = bool(cfg.rule_enabled.get(rule_name, True))
                    row_score = int(cfg.rule_weights.get(rule_name, 0))

                checkbox = QCheckBox()
                checkbox.setChecked(row_enabled)
                checkbox.stateChanged.connect(
                    lambda state, rn=rule_name: self._on_rule_enabled_changed(rn, state)
                )
                checkbox_container = QWidget()
                checkbox_layout = QHBoxLayout()
                checkbox_layout.setContentsMargins(0, 0, 0, 0)
                checkbox_layout.setAlignment(Qt.AlignCenter)
                checkbox_layout.addWidget(checkbox)
                checkbox_container.setLayout(checkbox_layout)
                self.rules_table.setCellWidget(row, 2, checkbox_container)

                spin = QSpinBox()
                spin.setRange(0, 1000)
                spin.setValue(row_score)
                spin.setStyleSheet(
                    "background: #222938; color: white; border: 1px solid #2f3a59; "
                    "padding: 4px 6px; border-radius: 4px; min-height: 26px;"
                )
                spin.valueChanged.connect(
                    lambda value, rn=rule_name: self._on_rule_score_changed(rn, value)
                )
                self.rules_table.setCellWidget(row, 3, spin)
        finally:
            self._rules_table_loading = False

        if self.rules_table.rowCount() > 0:
            self.rules_table.selectRow(0)

    def _format_rule_trigger_info(self, rule_name: str) -> str:
        """Return a human-readable trigger-condition string using live config values."""
        if not _CONFIG_AVAILABLE:
            return "Unavailable — config module not loaded."

        if rule_name == _ENTROPY_RULE_NAME:
            ecfg = get_config().entropy
            sample_mb = ecfg.sample_size_bytes // (1024 * 1024)
            return (
                f"A monitored file's Shannon entropy increases by more than {ecfg.threshold:.2f} "
                f"bits/byte between two scans (sampling the first {sample_mb} MB of each file)."
            )

        dcfg = get_config().detection
        if rule_name == "Rule1_FileBurst":
            return f"The same process performs more than {dcfg.high_ops_threshold} file operations within 1 second."
        if rule_name == "Rule2_MultipleDirectories":
            return f"The same process touches more than {dcfg.multi_dir_threshold} distinct directories within 1 second."
        if rule_name == "Rule3_YoungProcessBurst":
            return (
                f"A process younger than {dcfg.young_process_age_threshold:.0f}s performs more than "
                f"{dcfg.young_process_ops_threshold} operations within 1 second."
            )
        if rule_name == "Rule4_ExtensionChangeBurst":
            return (
                f"{dcfg.extension_change_threshold}+ genuine file-extension changes "
                f"(e.g. .docx \u2192 .locked) by the same process within "
                f"{dcfg.extension_change_window_seconds:.0f} seconds."
            )
        return "Custom trigger condition."

    def _on_rule_row_selected(self) -> None:
        """Expand the selected rule into the details panel on the right.

        Shows the full description, current enabled/score state, and the
        precise trigger condition (formatted with live config values) so
        users can understand exactly when a rule fires without leaving
        the page.
        """
        selection_model = self.rules_table.selectionModel()
        selected_rows = selection_model.selectedRows() if selection_model else []
        if not selected_rows:
            return

        name_item = self.rules_table.item(selected_rows[0].row(), 0)
        if name_item is None:
            return
        rule_name = name_item.text()

        self.rule_details_title.setText(rule_name.replace("_", " "))
        self.rule_details_hint.setText(_RULE_DESCRIPTIONS.get(rule_name, "Custom detection rule."))

        if not _CONFIG_AVAILABLE:
            return

        if rule_name == _ENTROPY_RULE_NAME:
            enabled = bool(get_config().entropy.enabled)
            score = int(get_config().entropy.score)
        else:
            dcfg = get_config().detection
            enabled = bool(dcfg.rule_enabled.get(rule_name, True))
            score = int(dcfg.rule_weights.get(rule_name, 0))

        status_label = self.rule_details_labels["status"]
        status_label.setText("✅ Enabled" if enabled else "🚫 Disabled")
        status_label.setStyleSheet(
            f"font-size: 12pt; font-weight: bold; color: {'#4CAF50' if enabled else '#f44336'};"
        )
        self.rule_details_labels["score"].setText(f"+{score} points while active")
        self.rule_details_labels["trigger"].setText(self._format_rule_trigger_info(rule_name))

    def _on_rule_enabled_changed(self, rule_name: str, state: int) -> None:
        """Handle a user tick/untick of a rule's Enabled checkbox."""
        if getattr(self, "_rules_table_loading", False):
            return
        self._persist_rule_setting(rule_name, enabled=(state == Qt.Checked))

    def _on_rule_score_changed(self, rule_name: str, value: int) -> None:
        """Handle a user edit of a rule's Score spin box."""
        if getattr(self, "_rules_table_loading", False):
            return
        self._persist_rule_setting(rule_name, weight=value)

    def _persist_rule_setting(
        self,
        rule_name: str,
        *,
        weight: Optional[int] = None,
        enabled: Optional[bool] = None,
    ) -> None:
        """Persist a single rule's weight/enabled change to config.yaml.

        Updates take effect immediately in the running detection engines
        (they read rule_weights/rule_enabled, or entropy.score/enabled, live
        from the shared config object) and are written to config.yaml so
        they survive a restart. The Entropy row is routed to
        save_entropy_rule_settings() since its tunables live in a different
        config section than the other rules.
        """
        if not _CONFIG_AVAILABLE:
            return

        try:
            if rule_name == _ENTROPY_RULE_NAME:
                persisted = save_entropy_rule_settings(score=weight, enabled=enabled)
            else:
                weight_update = {rule_name: weight} if weight is not None else {}
                enabled_update = {rule_name: enabled} if enabled is not None else {}
                persisted = save_rule_settings(weight_update, enabled_update)
        except Exception as exc:
            self.rules_save_status_label.setStyleSheet("color: #f44336; font-size: 10pt;")
            self.rules_save_status_label.setText(f"Failed to save {rule_name}: {exc}")
            return

        if persisted:
            self.rules_save_status_label.setStyleSheet("color: #4CAF50; font-size: 10pt;")
            self.rules_save_status_label.setText(f"Saved — {rule_name} updated in config.yaml.")
        else:
            self.rules_save_status_label.setStyleSheet("color: #ff9800; font-size: 10pt;")
            self.rules_save_status_label.setText(
                f"{rule_name} updated for this session, but config.yaml could not be written."
            )

        # Refresh the details panel in case the edited row is the one on display.
        self._on_rule_row_selected()

    def start_monitor(self):
        if self.monitor_session is not None and self.monitor_session.is_running:
            return

        monitor_path_text = self.path_input.text().strip() or str(Path.home())
        monitor_path = Path(monitor_path_text).expanduser()
        if not monitor_path.exists():
            self.handle_error(f"Monitor path does not exist: {monitor_path}")
            return

        entropy_dir_text = self.entropy_dir_input.text().strip() if hasattr(self, "entropy_dir_input") else ""
        entropy_root = Path(entropy_dir_text).expanduser() if entropy_dir_text else monitor_path
        if not entropy_root.exists() or not entropy_root.is_dir():
            entropy_root = monitor_path
            if hasattr(self, "entropy_dir_input"):
                self.entropy_dir_input.setText(str(entropy_root))

        self._pending_log_lines.clear()
        self.append_raw_line(f"Starting monitor for: {monitor_path}")
        if self._logs_db is not None:
            self._start_log_db_writer()
        logger.info("[ENTROPY_TRACE][GUI] start_monitor path=%s entropy_available=%s", monitor_path, _ENTROPY_AVAILABLE)

        # --- Start entropy monitor first (if available) -------------------
        if _ENTROPY_AVAILABLE:
            try:
                cfg = get_config() if _CONFIG_AVAILABLE else None
                ent_cfg = cfg.entropy if cfg else None
                db_cfg  = cfg.database if cfg else None

                meta_db   = get_metadata_db()
                logs_db   = get_logs_db()
                alerts_db = get_alerts_db()

                allowed_ext = set(ent_cfg.file_extensions) if ent_cfg else set()
                sample_size = ent_cfg.sample_size_bytes if ent_cfg else 5 * 1024 * 1024
                threshold   = ent_cfg.threshold if ent_cfg else 1.4
                retention   = db_cfg.metadata_retention_days if db_cfg else 30

                entropy_enabled = bool(ent_cfg.enabled) if ent_cfg else True
                if entropy_enabled:
                    self._entropy_monitor = EntropyMonitor(
                        metadata_db=meta_db,
                        logs_db=logs_db,
                        alerts_db=alerts_db,
                        allowed_extensions=allowed_ext,
                        monitored_roots=[entropy_root],
                        sample_size_bytes=sample_size,
                        threshold=threshold,
                        on_entropy_alert=self._entropy_alert_callback,
                        retention_days=retention,
                        persist_events_to_logs=False,
                    )
                    self._entropy_monitor.start()
                    logger.info(
                        "[ENTROPY_TRACE][GUI] entropy_monitor_started threshold=%.3f sample_size=%s extensions=%s",
                        threshold,
                        sample_size,
                        sorted(list(allowed_ext))[:20],
                    )
                    self.entropy_status_label.setText(
                        f"Entropy module active  |  threshold: {threshold:.2f} bits  |  "
                        f"watching {len(allowed_ext)} extension(s)"
                    )
                    self.entropy_status_label.setStyleSheet("color: #4CAF50; font-size: 11px;")
                    self._entropy_refresh_timer.start()
                else:
                    self.entropy_status_label.setText("Entropy rule disabled from Active Rules. Module not started.")
                    self.entropy_status_label.setStyleSheet("color: #ff9800; font-size: 11px;")
            except Exception as exc:
                logger.exception("[ENTROPY_TRACE][GUI] entropy_monitor_start_failed: %s", exc)
                self.entropy_status_label.setText(f"Entropy module failed to start: {exc}")
                self.entropy_status_label.setStyleSheet("color: #ff9800; font-size: 11px;")

        self.monitor_session = MonitorSession(
            target_path=monitor_path,
            recursive=self.recursive_checkbox.isChecked(),
            emit_line=self.output_bridge.new_raw_line.emit,
            emit_error=self.output_bridge.error_occurred.emit,
            emit_started=self.output_bridge.process_started.emit,
            emit_stopped=self._on_monitor_stopped,
            event_callback=self._on_filesystem_event,
            high_score_callback=None,
        )

        if not self.monitor_session.start():
            self.monitor_session = None
            return

        self.start_time = time.time()
        self.event_count = 0
        self.total_events_label.setText("Total events: 0")
        self._update_runtime_display()
        self.runtime_timer.start()

    def _on_filesystem_event(
        self,
        event_type: str,
        file_path: str,
        process_name: str,
        pid: Optional[int],
        executable: str,
        parent: str,
        previous_path: Optional[str] = None,
        file_identifier: Optional[str] = None,
    ) -> None:
        """Handle raw filesystem events from the monitor callback.

        This callback runs on watchdog's observer thread. It must stay light:
        - persist event to logs.db (best effort)
        - forward event to EntropyMonitor (if active)
        - enqueue a lightweight GUI event for batched rendering
        """
        logger.info(
            "[ENTROPY_TRACE][GUI_CALLBACK] recv event=%s file=%s pid=%s proc=%s entropy_monitor=%s",
            event_type,
            file_path,
            pid,
            process_name,
            self._entropy_monitor is not None,
        )

        if self._logs_db is not None:
            try:
                self._log_db_event_queue.put_nowait(
                    {
                        "event_type": event_type,
                        "file_path": file_path,
                        "file_name": Path(file_path).name,
                        "process": process_name,
                        "pid": pid,
                        "executable": executable,
                        "parent": parent,
                        "file_identifier": file_identifier,
                        "timestamp": time.time(),
                    }
                )
            except queue.Full:
                logger.warning(
                    "[ENTROPY_TRACE][GUI_CALLBACK] logs_db queue full; dropping event=%s file=%s",
                    event_type,
                    file_path,
                )

        forward_to_entropy = event_type in {"FILE CREATED", "FILE MOVED", "FILE DELETED", "FILE RENAMED"}
        if self._entropy_monitor is not None and forward_to_entropy:
            try:
                self._entropy_monitor.on_file_event(
                    event_type,
                    file_path,
                    previous_path=previous_path,
                    file_identifier=file_identifier,
                    process_name=process_name,
                    pid=pid,
                    executable=executable,
                    parent=parent,
                )
                logger.info(
                    "[ENTROPY_TRACE][GUI_CALLBACK] forwarded_to_entropy event=%s file=%s",
                    event_type,
                    file_path,
                )
            except Exception:
                logger.exception(
                    "[ENTROPY_TRACE][GUI_CALLBACK] forward_error event=%s file=%s",
                    event_type,
                    file_path,
                )
        else:
            logger.debug(
                "[ENTROPY_TRACE][GUI_CALLBACK] entropy forwarding skipped event=%s file=%s monitor=%s",
                event_type,
                file_path,
                self._entropy_monitor is not None,
            )

        try:
            self._filesystem_event_gui_queue.put_nowait(
                {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "level": "INFO",
                    "event_type": event_type,
                    "file": file_path,
                    "file_name": Path(file_path).name,
                    "process": process_name or "",
                    "pid": str(pid) if pid is not None else "",
                    "executable": executable or "",
                    "parent_process": parent or "",
                    "file_identifier": file_identifier or "",
                    "message": (
                        f"Renamed from {previous_path}" if previous_path and "MOVE" in event_type.upper() else ""
                    ),
                    "raw_event": "",
                }
            )
        except queue.Full:
            logger.warning("GUI event queue full; dropped event=%s file=%s", event_type, file_path)

    def _on_set_entropy_directory_clicked(self) -> None:
        """Rebuild entropy database asynchronously when entropy root changes."""
        if not _CONFIG_AVAILABLE:
            self.show_error("Config module unavailable; cannot update entropy directory.")
            return
        if not _DATABASE_AVAILABLE:
            self.show_error("Database module unavailable; cannot rebuild entropy database.")
            return

        entropy_dir_text = self.entropy_dir_input.text().strip()
        if not entropy_dir_text:
            self.show_error("Please enter an entropy monitoring directory.")
            return

        entropy_root = Path(entropy_dir_text).expanduser()
        if not entropy_root.exists() or not entropy_root.is_dir():
            self.show_error(f"Invalid entropy directory: {entropy_root}")
            return

        try:
            normalized_entropy_root = str(entropy_root.resolve())
        except Exception:
            normalized_entropy_root = str(entropy_root)

        # Ignore no-op apply events (e.g., editingFinished focus changes).
        if self._last_applied_entropy_root == normalized_entropy_root:
            return

        if self._entropy_rebuild_thread is not None and self._entropy_rebuild_thread.isRunning():
            logger.info("Entropy rebuild request ignored: rebuild already running.")
            return

        cfg = get_config()
        monitor_root = self.path_input.text().strip() or cfg.monitoring.file_monitor_directory
        saved = save_startup_directories(str(entropy_root), str(Path(monitor_root).expanduser()))
        if not saved:
            self.show_error("Failed to save startup directories to config.yaml.")
            return

        self._last_applied_entropy_root = normalized_entropy_root

        self._entropy_rebuild_dialog = EntropyRebuildDialog(self)
        self._entropy_rebuild_dialog.show()

        metadata_db = get_metadata_db()
        self._entropy_rebuild_thread = QThread(self)
        self._entropy_rebuild_worker = EntropyBuildWorker(
            metadata_db=metadata_db,
            root=entropy_root,
            allowed_extensions=set(cfg.entropy.file_extensions),
            sample_size_bytes=cfg.entropy.sample_size_bytes,
        )
        self._entropy_rebuild_worker.moveToThread(self._entropy_rebuild_thread)

        self._entropy_rebuild_thread.started.connect(self._entropy_rebuild_worker.run)
        self._entropy_rebuild_worker.progress.connect(self._on_entropy_rebuild_progress)
        self._entropy_rebuild_worker.completed.connect(self._on_entropy_rebuild_finished)
        self._entropy_rebuild_worker.failed.connect(self._on_entropy_rebuild_failed)
        self._entropy_rebuild_worker.completed.connect(self._entropy_rebuild_thread.quit)
        self._entropy_rebuild_worker.failed.connect(self._entropy_rebuild_thread.quit)
        self._entropy_rebuild_thread.finished.connect(self._cleanup_entropy_rebuild_worker)

        self._entropy_rebuild_thread.start()

    def _on_entropy_rebuild_progress(self, current: int, total: int, file_name: str, percent: int) -> None:
        if self._entropy_rebuild_dialog is not None:
            self._entropy_rebuild_dialog.on_progress(current, total, file_name, percent)

    def _on_entropy_rebuild_finished(self, total: int, processed: int, added: int = 0, removed: int = 0, updated: int = 0) -> None:
        if self._entropy_rebuild_dialog is not None:
            self._entropy_rebuild_dialog.on_finished(total, processed)
            self._entropy_rebuild_dialog.close()
            self._entropy_rebuild_dialog.deleteLater()
            self._entropy_rebuild_dialog = None

        entropy_root = Path(self.entropy_dir_input.text().strip() or Path.home()).expanduser()
        self._restart_entropy_monitor_for_new_root(entropy_root)
        self.entropy_status_label.setText(
            f"Entropy database updated. Processed {processed} / {total} files from {entropy_root}."
        )
        self.entropy_status_label.setStyleSheet("color: #4CAF50; font-size: 11px;")
        self._refresh_entropy_table()

    def _on_entropy_rebuild_failed(self, message: str) -> None:
        self._entropy_refresh_in_progress = False
        if self._entropy_rebuild_dialog is not None:
            self._entropy_rebuild_dialog.on_failed(message)
        self.entropy_status_label.setText(f"Entropy refresh failed: {message}")
        self.entropy_status_label.setStyleSheet("color: #ff5252; font-size: 11px;")
        self.show_error(f"Entropy rebuild failed: {message}")

    def _cleanup_entropy_rebuild_worker(self) -> None:
        if self._entropy_rebuild_worker is not None:
            self._entropy_rebuild_worker.deleteLater()
        if self._entropy_rebuild_thread is not None:
            self._entropy_rebuild_thread.deleteLater()
        self._entropy_rebuild_worker = None
        self._entropy_rebuild_thread = None

    def _restart_entropy_monitor_for_new_root(self, entropy_root: Path) -> None:
        """Switch entropy monitor root without blocking the GUI thread."""
        if not _ENTROPY_AVAILABLE:
            return
        if not _DATABASE_AVAILABLE:
            return

        try:
            cfg = get_config() if _CONFIG_AVAILABLE else None
            ent_cfg = cfg.entropy if cfg else None
            db_cfg = cfg.database if cfg else None

            if ent_cfg is not None and not ent_cfg.enabled:
                self.entropy_status_label.setText("Entropy rule disabled from Active Rules. Module not started.")
                self.entropy_status_label.setStyleSheet("color: #ff9800; font-size: 11px;")
                return

            meta_db = get_metadata_db()
            logs_db = get_logs_db()
            alerts_db = get_alerts_db()

            allowed_ext = set(ent_cfg.file_extensions) if ent_cfg else set()
            sample_size = ent_cfg.sample_size_bytes if ent_cfg else 5 * 1024 * 1024
            threshold = ent_cfg.threshold if ent_cfg else 1.4
            retention = db_cfg.metadata_retention_days if db_cfg else 30

            old_monitor = self._entropy_monitor
            self._entropy_monitor = EntropyMonitor(
                metadata_db=meta_db,
                logs_db=logs_db,
                alerts_db=alerts_db,
                allowed_extensions=allowed_ext,
                monitored_roots=[entropy_root],
                sample_size_bytes=sample_size,
                threshold=threshold,
                on_entropy_alert=self._entropy_alert_callback,
                retention_days=retention,
                persist_events_to_logs=False,
            )
            self._entropy_monitor.start()
            self._entropy_refresh_timer.start()

            # Stop old monitor in the background to keep UI responsive.
            if old_monitor is not None:
                threading.Thread(target=old_monitor.stop, daemon=True).start()
        except Exception as exc:
            logger.exception("Failed to restart entropy monitor for new root: %s", exc)
            self.show_error(f"Failed to apply entropy root: {exc}")

    def stop_monitor(self):
        if self.monitor_session is None:
            return
        try:
            self.monitor_session.stop()
        except Exception as exc:
            self.handle_error(f"Failed to stop monitor: {exc}")
        self.monitor_session = None
        self._stop_log_db_writer()
        self.append_raw_line("Monitor stopped.")
        try:
            self.runtime_timer.stop()
        except Exception:
            pass
        # Stop entropy monitor
        if self._entropy_monitor is not None:
            try:
                self._entropy_monitor.stop()
            except Exception:
                pass
            self._entropy_monitor = None
        self._entropy_refresh_timer.stop()

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

    def _start_log_db_writer(self) -> None:
        if self._log_db_writer_thread is not None and self._log_db_writer_thread.is_alive():
            return
        self._log_db_writer_running = True
        pool_size = 2
        if _CONFIG_AVAILABLE:
            pool_size = max(1, int(get_config().database.log_writer_pool_size))
        self._log_db_writer_pool = ThreadPoolExecutor(
            max_workers=pool_size,
            thread_name_prefix="rdrs-log-db",
        )
        self._log_db_writer_thread = threading.Thread(
            target=self._log_db_writer_loop,
            name="rdrs-log-db-writer",
            daemon=True,
        )
        self._log_db_writer_thread.start()

    def _stop_log_db_writer(self) -> None:
        self._log_db_writer_running = False
        if self._log_db_writer_thread is not None and self._log_db_writer_thread.is_alive():
            self._log_db_event_queue.put(None)
            self._log_db_writer_thread.join(timeout=2.0)
            self._log_db_writer_thread = None
        if self._log_db_writer_pool is not None:
            self._log_db_writer_pool.shutdown(wait=True)
            self._log_db_writer_pool = None

    def _log_db_writer_loop(self) -> None:
        if self._logs_db is None:
            return

        batch = []
        in_flight = []
        while self._log_db_writer_running or not self._log_db_event_queue.empty():
            try:
                item = self._log_db_event_queue.get(timeout=0.25)
            except queue.Empty:
                item = None

            if item is None:
                if batch:
                    if self._log_db_writer_pool is not None:
                        in_flight.append(self._log_db_writer_pool.submit(self._flush_log_db_batch, list(batch)))
                    else:
                        self._flush_log_db_batch(batch)
                    batch = []
                if not self._log_db_writer_running:
                    break
                continue

            batch.append(item)
            if len(batch) >= 50:
                if self._log_db_writer_pool is not None:
                    in_flight.append(self._log_db_writer_pool.submit(self._flush_log_db_batch, list(batch)))
                else:
                    self._flush_log_db_batch(batch)
                batch = []

        if batch:
            if self._log_db_writer_pool is not None:
                in_flight.append(self._log_db_writer_pool.submit(self._flush_log_db_batch, list(batch)))
            else:
                self._flush_log_db_batch(batch)
        if in_flight:
            wait(in_flight)

    def _flush_log_db_batch(self, batch: List[dict]) -> None:
        if self._logs_db is None or not batch:
            return
        try:
            self._logs_db.log_events_batch(batch)
        except Exception:
            logger.exception("Failed to write batched log events to logs.db")

    def _on_high_score_rescan_requested(self, file_paths: List[str], context: Dict[str, object]) -> None:
        """Queue highest-priority filesystem-truth entropy rescans from monitor workers."""
        if self._entropy_monitor is None or not file_paths:
            return
        try:
            paths = [Path(path) for path in file_paths]
            self._entropy_monitor.queue_rescan_for_paths(paths)
            logger.info(
                "Queued high-score entropy rescan for %s files (pid=%s score=%s)",
                len(paths),
                context.get("pid"),
                context.get("score"),
            )
        except Exception:
            logger.exception("Failed to queue high-score entropy rescan.")

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
        if entry.get("event_type") == "PROCESS_STATE":
            self._update_process_state_table(entry)
            return

        if str(entry.get("event_type") or "").upper().startswith("FILE "):
            return

        if entry.get("event_type") == "EXTENSION_CHANGE":
            self._persist_extension_change(entry)

        self.event_rows.append(entry)
        self._trim_gui_event_cache()

        self.event_count += 1
        self._pending_total_events_refresh = True

        self._pending_log_refresh = True
        self._pending_counter_refresh = True
        self._update_suspicious_process_table(entry)
        self._pending_metrics_refresh = True

    def _persist_extension_change(self, entry: dict) -> None:
        """Persist a confirmed file-extension-change event to logs.db.

        The logs.db schema has no dedicated extension columns, so the
        transition is encoded into ``file_name`` (e.g. "report.docx
        (.docx -> .locked)") to avoid a breaking schema migration while
        still preserving the detail for later inspection.
        """
        if self._logs_db is None:
            return
        file_path = entry.get("file") or entry.get("previous_path") or ""
        original_ext = entry.get("original_extension") or "?"
        new_ext = entry.get("new_extension") or "?"
        base_name = Path(file_path).name if file_path else "?"
        pid_value = entry.get("pid")
        pid = int(pid_value) if str(pid_value or "").isdigit() else None
        try:
            self._logs_db.log_event(
                event_type="FILE EXTENSION CHANGED",
                file_path=file_path,
                file_name=f"{base_name} (.{original_ext} -> .{new_ext})",
                process=entry.get("process") or None,
                pid=pid,
                executable=entry.get("executable") or None,
                parent=entry.get("parent_process") or None,
            )
        except Exception:
            logger.exception("Failed to persist extension-change event to logs.db")

    def _load_persisted_logs(self, limit: int = 300) -> None:
        """Load recent persisted logs from logs.db into the File Monitoring page."""
        if self._logs_db is None:
            return
        try:
            rows = self._logs_db.get_recent(limit=limit)
        except Exception:
            return

        # rows are newest-first; render oldest-first for natural timeline.
        for row in reversed(rows):
            ts = row["timestamp"]
            try:
                ts_str = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                ts_str = ""

            entry = {
                "timestamp": ts_str,
                "level": "INFO",
                "event_type": row["event_type"] or "",
                "file": row["file_path"] or "",
                "file_name": row["file_name"] or "",
                "process": row["process"] or "",
                "pid": str(row["pid"]) if row["pid"] is not None else "",
                "executable": row["executable"] or "",
                "parent_process": row["parent"] or "",
                "message": "Loaded from logs.db",
                "raw_event": "",
            }
            self.add_log_row(entry)
        self._refresh_log_table_view()
        self._refresh_file_event_counters()

    def _load_persisted_response_actions(self, limit: int = 200) -> None:
        """Load persisted response-action history from alerts.db."""
        if self._alerts_db is None:
            return

        loaded_rows = []
        for action_type in ("QUARANTINE_ACTION", "DELETE_ACTION", "IGNORE_ACTION"):
            try:
                rows = self._alerts_db.get_by_type(action_type, limit=limit)
            except Exception:
                continue
            for row in rows:
                payload = {}
                notes = row["notes"] or ""
                if notes:
                    try:
                        parsed = json.loads(notes)
                        if isinstance(parsed, dict):
                            payload = parsed
                    except Exception:
                        payload = {}
                loaded_rows.append({
                    "timestamp": datetime.fromtimestamp(row["timestamp"]).strftime("%Y-%m-%d %H:%M:%S"),
                    "timestamp_epoch": row["timestamp"],
                    "action_type": row["alert_type"] or action_type,
                    "action_label": (
                        "Quarantine"
                        if (row["alert_type"] or action_type) == "QUARANTINE_ACTION"
                        else "Ignore"
                        if (row["alert_type"] or action_type) == "IGNORE_ACTION"
                        else "Remove / Terminate"
                    ),
                    "status": payload.get("status", "SUCCEEDED"),
                    "process": row["process_name"] or "",
                    "pid": str(row["pid"]) if row["pid"] is not None else "",
                    "executable": row["executable"] or "",
                    "source_path": payload.get("source_path") or row["file_path"] or row["executable"] or "",
                    "result_path": payload.get("result_path") or "",
                    "termination_status": payload.get("termination_status") or "",
                    "message": payload.get("message") or notes,
                })

        self.response_action_rows = sorted(loaded_rows, key=lambda item: item.get("timestamp_epoch", 0.0))

    def _selected_home_process_key_from_row(self, row: int) -> Optional[Tuple[Optional[str], str]]:
        item = self.home_table.item(row, 0)
        if item is not None:
            key = item.data(Qt.UserRole)
            if isinstance(key, tuple):
                return key
        for key, mapped_row in self.suspicious_process_rows.items():
            if mapped_row == row:
                return key
        return None

    def _response_actions_for_process(self, process_key: Tuple[Optional[str], str]) -> List[dict]:
        pid_value = str(process_key[0] or "")
        executable = str(process_key[1] or "")
        return [
            action
            for action in self.response_action_rows
            if str(action.get("pid") or "") == pid_value and str(action.get("executable") or "") == executable
        ]

    def _incident_status_for(self, process_entry: dict, action_rows: List[dict]) -> str:
        if action_rows:
            latest = action_rows[-1]
            if latest.get("action_type") == "IGNORE_ACTION" and latest.get("status") == "SUCCEEDED":
                return "Ignored"
            if latest.get("status") == "SUCCEEDED":
                return "Contained" if latest.get("action_type") == "QUARANTINE_ACTION" else "Removed"
            if latest.get("status") == "FAILED":
                return "Containment Failed"
        last_activity = process_entry.get("last_activity", "")
        return "Active" if self._process_is_active(last_activity) else "Inactive"

    def _build_selected_home_incident_payload(self, process_key: Tuple[Optional[str], str]) -> Optional[dict]:
        detection_entry = self.suspicious_process_entries.get(process_key, {}).copy()
        process_state = self.process_state_cache.get(process_key, {}).copy()
        if not detection_entry and not process_state:
            return None

        combined = process_state.copy()
        combined.update({k: v for k, v in detection_entry.items() if v not in (None, "")})

        score_text = str(combined.get("score") or "0")
        try:
            score_value = int(score_text)
        except Exception:
            score_value = 0

        try:
            threshold = get_config().alerts.process_alert_threshold if _CONFIG_AVAILABLE else 70
        except Exception:
            threshold = 70

        if score_value >= threshold:
            severity = "Critical"
        elif score_value >= 50:
            severity = "High"
        elif score_value > 0:
            severity = "Suspicious"
        else:
            severity = "Observed"

        actions = self._response_actions_for_process(process_key)
        latest_action = actions[-1] if actions else None
        response_taken = "None"
        if latest_action is not None:
            response_taken = f"{latest_action.get('action_label', 'Action')} ({latest_action.get('status', 'UNKNOWN').title()})"

        summary = {
            "severity": severity,
            "process": combined.get("process") or "Unknown process",
            "pid": combined.get("pid") or "Unknown",
            "executable": combined.get("executable") or "Unknown",
            "score": score_text,
            "reason": combined.get("reason") or "Behavioral thresholds exceeded.",
            "first_seen": combined.get("first_activity") or combined.get("process_start_time") or combined.get("start_time") or "Unknown",
            "last_seen": combined.get("last_activity") or combined.get("timestamp") or "Unknown",
            "status": self._incident_status_for(combined, actions),
            "response": response_taken,
        }

        return {
            "exported_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "incident_summary": summary,
            "detection_entry": detection_entry,
            "process_state": process_state,
            "containment_actions": actions,
        }

    def _on_home_selection_changed(self) -> None:
        selected_items = self.home_table.selectedItems()
        if not selected_items:
            self._selected_home_process_key = None
            self.home_details_button.setEnabled(False)
            self.home_export_button.setEnabled(False)
            self.incident_button.setEnabled(False)
            self.home_selection_hint.setText(
                "Select a suspicious process above and click View Incident Details to inspect the detection in depth."
            )
            return

        row = selected_items[0].row()
        process_key = self._selected_home_process_key_from_row(row)
        if process_key is None:
            self._selected_home_process_key = None
            self.home_details_button.setEnabled(False)
            self.home_export_button.setEnabled(False)
            self.incident_button.setEnabled(False)
            return

        self._selected_home_process_key = process_key
        self.home_details_button.setEnabled(True)
        self.home_export_button.setEnabled(True)
        self.incident_button.setEnabled(True)
        self.home_selection_hint.setText(
            "Click View Incident Details to open the dedicated incident report for the selected process."
        )

    def _open_selected_incident_details(self) -> None:
        if self._selected_home_process_key is None:
            self.show_error("Select a suspicious process before opening incident details.")
            return

        process_data = self.process_state_cache.get(self._selected_home_process_key)
        if process_data is None:
            self.show_error("Selected process no longer exists.")
            return
        self._populate_incident_page(self._selected_home_process_key)
        self.select_page(5)

    def _severity_for_score(self, score_value: int) -> str:
        if score_value >= 80:
            return "Critical"
        if score_value >= 50:
            return "High"
        if score_value > 0:
            return "Suspicious"
        return "Observed"

    def _populate_incident_page(self, process_key: Tuple[Optional[str], str]) -> None:
        process_entry = self.process_state_cache.get(process_key, {}).copy()
        detection_entry = self.suspicious_process_entries.get(process_key, {}).copy()
        if not process_entry and not detection_entry:
            return

        combined = process_entry.copy()
        combined.update({k: v for k, v in detection_entry.items() if v not in (None, "")})

        try:
            score_value = int(str(combined.get("score") or "0"))
        except Exception:
            score_value = 0

        timeline_rows: List[dict] = []
        pid = str(process_key[0] or "")
        executable = str(process_key[1] or "")
        process_name = str(combined.get("process") or "")
        for row in self.event_rows:
            row_pid = str(row.get("pid") or "")
            row_exe = str(row.get("executable") or "")
            row_process = str(row.get("process") or "")
            if (pid and row_pid == pid) or (executable and row_exe == executable) or (process_name and row_process == process_name):
                timeline_rows.append(row)

        timeline_rows.sort(key=lambda item: str(item.get("timestamp") or ""))

        status = self._incident_status_for(combined, self._response_actions_for_process(process_key))
        detection_time = (
            combined.get("timestamp")
            or combined.get("first_activity")
            or combined.get("last_activity")
            or "Unknown"
        )
        self.incident_summary_labels["process"].setText(f"Process Name: {combined.get('process') or 'Unknown process'}")
        self.incident_summary_labels["pid"].setText(f"PID: {combined.get('pid') or 'Unknown'}")
        self.incident_summary_labels["detection_time"].setText(f"Detection Time: {detection_time}")
        self.incident_summary_labels["severity"].setText(f"Severity: {self._severity_for_score(score_value)}")
        self.incident_summary_labels["score"].setText(f"Final Suspicion Score: {score_value}")
        self.incident_summary_labels["status"].setText(f"Current Status: {status}")

        self.incident_timeline_table.setSortingEnabled(False)
        self.incident_timeline_table.setRowCount(0)
        for row in timeline_rows:
            idx = self.incident_timeline_table.rowCount()
            self.incident_timeline_table.insertRow(idx)
            event_type = str(row.get("event_type") or "")
            message = str(row.get("message") or row.get("reason") or "")
            rule = ""
            rule_match = re.search(r"(Rule[0-9]+_[A-Za-z0-9_]+|EntropyIncrease)", message)
            if rule_match:
                rule = rule_match.group(1)
            items = [
                str(row.get("timestamp") or ""),
                event_type,
                str(row.get("file") or row.get("file_path") or row.get("file_name") or ""),
                rule,
                message,
            ]
            for col, value in enumerate(items):
                self.incident_timeline_table.setItem(idx, col, QTableWidgetItem(value))
        self.incident_timeline_table.setSortingEnabled(True)

        files: Dict[str, dict] = {}
        for row in timeline_rows:
            path = str(row.get("file") or row.get("file_path") or "").strip()
            if not path:
                continue
            item = files.setdefault(path, {"ext": "No", "entropy": "No", "last": ""})
            event_type = str(row.get("event_type") or "").upper()
            if event_type == "EXTENSION_CHANGE":
                item["ext"] = "Yes"
            if event_type == "ENTROPY_ALERT" or "ENTROPY" in str(row.get("message") or "").upper():
                item["entropy"] = "Yes"
            item["last"] = str(row.get("timestamp") or item["last"])

        self.incident_files_table.setSortingEnabled(False)
        self.incident_files_table.setRowCount(0)
        for path, payload in files.items():
            idx = self.incident_files_table.rowCount()
            self.incident_files_table.insertRow(idx)
            values = [path, payload["ext"], payload["entropy"], payload["last"]]
            for col, value in enumerate(values):
                self.incident_files_table.setItem(idx, col, QTableWidgetItem(value))
        self.incident_files_table.setSortingEnabled(True)

        reason = str(combined.get("reason") or "Behavioral thresholds exceeded.")
        self.incident_behavior_table.setRowCount(0)
        self.incident_behavior_table.insertRow(0)
        self.incident_behavior_table.setItem(0, 0, QTableWidgetItem("Detection Rules"))
        self.incident_behavior_table.setItem(0, 1, QTableWidgetItem(str(score_value)))
        self.incident_behavior_table.setItem(0, 2, QTableWidgetItem(reason))
        self.incident_total_score_label.setText(f"Total Score: {score_value}")

        self.incident_executive_summary.setText(
            f"Process {combined.get('process') or 'Unknown process'} (PID {combined.get('pid') or 'Unknown'}) "
            f"was classified as {self._severity_for_score(score_value)} with a final score of {score_value}. "
            f"The decision was driven by: {reason}. Current status is {status}."
        )

        self.incident_context_hint.setText(
            "Timeline includes extension changes, file activity bursts, entropy detections, and triggered rules in chronological order."
        )
        self.incident_button.setEnabled(True)

    def _export_selected_home_incident_json(self) -> None:
        if self._selected_home_process_key is None:
            self.show_error("Select a suspicious process before exporting.")
            return
        payload = self._build_selected_home_incident_payload(self._selected_home_process_key)
        if payload is None:
            self.show_error("No incident data is available for the selected process.")
            return

        summary = payload.get("incident_summary", {})
        process_name = _safe_export_name(str(summary.get("process") or "incident"), "incident")
        timestamp = _safe_export_name(str(summary.get("last_seen") or datetime.now().strftime("%Y-%m-%d_%H-%M-%S")), "time")
        try:
            exported_path = _export_json_payload(
                self,
                payload,
                f"rdrs_incident_{process_name}_{timestamp}.json",
                "Export Incident As JSON",
            )
        except Exception as exc:
            self.show_error(f"Could not export incident JSON: {exc}")
            return
        if exported_path is not None:
            QMessageBox.information(self, "Export Complete", f"Saved JSON report to:\n{exported_path}")

    def on_table_selection_changed(self):
        """Handle log table selection changes."""
        selected_items = self.log_table.selectedItems()
        if not selected_items:
            return
        row = selected_items[0].row()
        if 0 <= row < len(self._displayed_event_rows):
            entry = self._displayed_event_rows[row]
            dialog = EventDetailsDialog(self, entry)
            dialog.exec_()
    
    def on_process_double_click(self) -> None:
        """Handle double-click on process table to show details."""
        # Determine which table was clicked
        sender = self.sender()
        if sender == self.active_process_table:
            table = self.active_process_table
            row_map = self.active_process_rows
        elif sender == self.inactive_process_table:
            table = self.inactive_process_table
            row_map = self.inactive_process_rows
        else:
            return
        
        selected_items = table.selectedItems()
        if not selected_items:
            return
        
        row = selected_items[0].row()
        
        # Find process key for this row
        process_key = None
        for key, mapped_row in row_map.items():
            if mapped_row == row:
                process_key = key
                break
        
        if process_key is None:
            return
        
        # Get process data
        process_data = self.process_state_cache.get(process_key)
        if process_data is None:
            return
        
        # Open details dialog
        details_dialog = ProcessDetailsDialog(self, process_data, process_key)
        details_dialog.show()

    def _handle_monitor_line(self, line: str) -> None:
        """Receive one formatted log line from the background monitor."""
        self.append_raw_line(line)

        if self._is_timestamped_header(line):
            if self._pending_log_lines:
                self._emit_log_entry(self._pending_log_lines)
            self._pending_log_lines = [line]
            return

        self._pending_log_lines.append(line)

    def _on_monitor_stopped(self) -> None:
        """Flush any buffered log entry and update UI state."""
        if self._pending_log_lines:
            self._emit_log_entry(self._pending_log_lines)
            self._pending_log_lines = []
        self.output_bridge.process_stopped.emit()

    @staticmethod
    def _is_timestamped_header(line: str) -> bool:
        return bool(re.match(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} (INFO|ERROR|WARNING|DEBUG|CRITICAL)\b", line))

    def _emit_log_entry(self, lines: List[str]) -> None:
        raw_text = "\n".join(lines)
        if "EVENT:" in raw_text and "[Detection]" not in raw_text and "[ProcessState]" not in raw_text and "[ExtensionChange]" not in raw_text:
            return

        entry = self._parse_logger_entry(lines)
        entry["raw_event"] = "\n".join(lines)
        # Try to enrich the record (best-effort; never blocks the monitor).
        if not str(entry.get("event_type") or "").upper().startswith("FILE "):
            try:
                self._enrich_record(entry)
            except Exception:
                pass

        if str(entry.get("event_type") or "").upper().startswith("FILE "):
            return

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
            "score": "",
            "reason": "",
            "files_modified": "",
            "files_created": "",
            "files_deleted": "",
            "unique_directories": "",
            "unique_files": "",
            "last_activity": "",
            "process_age": "",
            "classification": "",
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
            is_detection_body = body.startswith("[Detection]") or "[Detection]" in body
            is_process_state = body.startswith("[ProcessState]") or "[ProcessState]" in body
            is_extension_change = body.startswith("[ExtensionChange]") or "[ExtensionChange]" in body
            if is_process_state:
                self._parse_process_state_block(body, log_record)
            elif is_extension_change:
                self._parse_extension_change_block(body, log_record)
            elif is_detection_body:
                self._parse_detection_block(body, log_record)
            else:
                is_event_body = body.startswith("EVENT:") or "EVENT:" in body
                if is_event_body:
                    self._parse_event_block(body, log_record)
                elif not log_record["message"]:
                    log_record["message"] = body
                else:
                    log_record["message"] = f"{log_record['message']}\n{body}" if log_record["message"] else body

            if not log_record["event_type"]:
                normalized_body = body.upper()
                if "FILE MODIFIED" in normalized_body:
                    log_record["event_type"] = "FILE MODIFIED"
                elif "FILE CREATED" in normalized_body:
                    log_record["event_type"] = "FILE CREATED"
                elif "FILE DELETED" in normalized_body:
                    log_record["event_type"] = "FILE DELETED"
                elif is_detection_body:
                    log_record["event_type"] = "DETECTION"
                elif is_process_state:
                    log_record["event_type"] = "PROCESS_STATE"
                elif is_extension_change:
                    log_record["event_type"] = "EXTENSION_CHANGE"

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

    def _parse_detection_block(self, body: str, record: dict) -> None:
        lines = [line.strip() for line in body.splitlines() if line.strip()]
        current_key = None
        for line in lines:
            if line.startswith("[Detection]"):
                record["event_type"] = "DETECTION"
                continue
            if line.endswith(":"):
                current_key = line[:-1].lower().replace(" ", "_")
                continue
            if current_key and line:
                if current_key == "process":
                    record["process"] = line
                elif current_key == "pid":
                    record["pid"] = line
                elif current_key == "executable":
                    record["executable"] = line
                elif current_key == "reason":
                    record["reason"] = line
                elif current_key == "score":
                    record["score"] = line
                elif current_key == "files_modified":
                    record["files_modified"] = line
                elif current_key == "files_created":
                    record["files_created"] = line
                elif current_key == "files_deleted":
                    record["files_deleted"] = line
                elif current_key == "unique_directories":
                    record["unique_directories"] = line
                elif current_key == "last_activity":
                    record["last_activity"] = line
                elif current_key == "start_time":
                    # Keep start time for future analysis, but no table column uses it yet.
                    record["start_time"] = line
                else:
                    record["message"] += f"\n{line}"
                current_key = None

    def _parse_extension_change_block(self, body: str, record: dict) -> None:
        """Parse a [ExtensionChange] block emitted by ProcessBehaviorTracker.

        Populates ``record`` with the fields the File Extension Monitor
        deliverable requires: timestamp, original/new path, original/new
        extension, process name and PID (see
        monitor.filesystem_monitor.ProcessBehaviorTracker._log_extension_change).
        """
        lines = [line.strip() for line in body.splitlines() if line.strip()]
        current_key = None
        for line in lines:
            if line.startswith("[ExtensionChange]"):
                record["event_type"] = "EXTENSION_CHANGE"
                continue
            if line.endswith(":"):
                current_key = line[:-1].lower().replace(" ", "_")
                continue
            if current_key and line:
                if current_key == "process":
                    record["process"] = line
                elif current_key == "pid":
                    record["pid"] = line
                elif current_key == "executable":
                    record["executable"] = line
                elif current_key == "original_path":
                    record["previous_path"] = line
                elif current_key == "new_path":
                    record["file"] = line
                    record["file_name"] = Path(line).name
                elif current_key == "original_extension":
                    record["original_extension"] = line
                elif current_key == "new_extension":
                    record["new_extension"] = line
                elif current_key == "timestamp":
                    record["timestamp"] = line
                else:
                    record["message"] += f"\n{line}"
                current_key = None

        original_ext = record.get("original_extension", "")
        new_ext = record.get("new_extension", "")
        if original_ext or new_ext:
            record["message"] = f".{original_ext or '?'}  →  .{new_ext or '?'}"

    def _parse_process_state_block(self, body: str, record: dict) -> None:
        lines = [line.rstrip() for line in body.splitlines()]
        current_key = None
        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("[ProcessState]"):
                record["event_type"] = "PROCESS_STATE"
                continue
            if line.endswith(":"):
                current_key = line[:-1].strip().lower().replace(" ", "_")
                continue
            if current_key is None and ":" in line:
                key, value = line.split(":", 1)
                current_key = key.strip().lower().replace(" ", "_")
                line = value.strip()
            if current_key:
                value = line
                if current_key == "process_name":
                    record["process"] = value
                elif current_key == "pid":
                    record["pid"] = value
                elif current_key == "executable":
                    record["executable"] = value
                elif current_key == "parent_pid":
                    record["parent_pid"] = value
                elif current_key == "parent_executable":
                    record["parent_executable"] = value
                elif current_key == "command_line":
                    record["command_line"] = value
                elif current_key == "working_directory":
                    record["working_directory"] = value
                elif current_key == "username":
                    record["username"] = value
                elif current_key == "process_age":
                    record["process_age"] = value
                elif current_key == "files_created":
                    record["files_created"] = value
                elif current_key == "files_modified":
                    record["files_modified"] = value
                elif current_key == "files_deleted":
                    record["files_deleted"] = value
                elif current_key == "unique_files":
                    record["unique_files"] = value
                elif current_key == "events_last_second":
                    record["events_sec"] = value
                elif current_key == "events_last_minute":
                    record["events_min"] = value
                elif current_key == "current_score":
                    record["score"] = value
                elif current_key == "classification":
                    record["classification"] = value
                elif current_key == "last_activity":
                    record["last_activity"] = value
                elif current_key == "process_start_time":
                    record["process_start_time"] = value
                elif current_key == "first_activity":
                    record["first_activity"] = value
                elif current_key == "total_events":
                    record["total_events"] = value
                else:
                    record["message"] += f"\n{value}"
                current_key = None

    def _update_suspicious_process_table(self, entry: dict) -> None:
        if entry.get("event_type") != "DETECTION":
            return
        try:
            score = int(entry.get("score", "0"))
        except ValueError:
            score = 0

        if "Extension Change Detection rule" in (entry.get("reason") or ""):
            self._log_extension_change_alert(entry, score)

        if score < 50:
            return

        key = (entry.get("pid"), entry.get("executable", ""))
        self.suspicious_process_entries[key] = entry.copy()

        try:
            threshold = get_config().alerts.process_alert_threshold if _CONFIG_AVAILABLE else 70
        except Exception:
            threshold = 70
        if score >= threshold:
            self._last_alert_process_key = key
        if score >= threshold and not self._alert_banner_visible:
            process = entry.get("process") or entry.get("executable") or "Unknown process"
            self._show_alert_banner(
                f"⚠  {process}  has reached a threat score of {score}."
            )

        self._pending_suspicious_refresh = True
        self._pending_metrics_refresh = True

    def _log_extension_change_alert(self, entry: dict, score: int) -> None:
        """Persist a mass-extension-change burst alert to alerts.db.

        Called exactly once per detection window: ``_apply_rules`` in
        ProcessBehaviorTracker only emits a [Detection] block the moment
        Rule4_ExtensionChangeBurst *newly* activates, so this never
        double-writes for the same burst (see detection_engine.ExtensionChangeEngine
        and monitor.filesystem_monitor.ProcessBehaviorTracker._apply_rules).
        """
        if self._alerts_db is None:
            return
        pid_value = entry.get("pid")
        pid = int(pid_value) if str(pid_value or "").isdigit() else None
        try:
            self._alerts_db.log_alert(
                alert_type="EXTENSION_CHANGE_BURST",
                process_name=entry.get("process") or None,
                pid=pid,
                executable=entry.get("executable") or None,
                process_score=score,
                triggered_rules=["Rule4_ExtensionChangeBurst"],
                notes=entry.get("reason"),
            )
        except Exception:
            logger.exception("Failed to persist extension-change burst alert to alerts.db")

    def _update_process_state_table(self, entry: dict) -> None:
        if entry.get("event_type") != "PROCESS_STATE":
            return
        key = (entry.get("pid"), entry.get("executable", ""))
        self.process_state_cache[key] = entry.copy()
        self._maybe_auto_quarantine_process(key, entry)
        self._pending_process_state_refresh = True
        self._pending_metrics_refresh = True
        if self._selected_home_process_key == key:
            self._on_home_selection_changed()

    def _maybe_auto_quarantine_process(self, process_key: Tuple[Optional[str], str], entry: dict) -> None:
        """Automatically quarantine processes that reach score threshold 50."""
        if process_key in self._auto_quarantine_attempted:
            return
        try:
            score_value = int(str(entry.get("score") or "0"))
        except Exception:
            score_value = 0
        if score_value < 50:
            return

        self._auto_quarantine_attempted.add(process_key)
        self._perform_quarantine_for_target(
            entry,
            automatic=True,
        )

    def _refresh_process_state_tables(self) -> None:
        self.active_process_table.setRowCount(0)
        self.inactive_process_table.setRowCount(0)
        self.active_process_rows.clear()
        self.inactive_process_rows.clear()

        def _score_for_sort(item: tuple) -> int:
            value = item[1].get("score", "0")
            try:
                return int(value)
            except Exception:
                return 0

        for key, entry in sorted(self.process_state_cache.items(), key=_score_for_sort, reverse=True):
            last_activity = entry.get("last_activity", "")
            is_active = self._process_is_active(last_activity)
            target_table = self.active_process_table if is_active else self.inactive_process_table
            row = target_table.rowCount()
            target_table.insertRow(row)
            if is_active:
                self.active_process_rows[key] = row
            else:
                self.inactive_process_rows[key] = row

            values = [
                entry.get("process", ""),
                entry.get("pid", ""),
                entry.get("files_modified", ""),
                entry.get("events_sec", ""),
                entry.get("score", ""),
                entry.get("classification", ""),
                entry.get("last_activity", ""),
            ]
            for col_index, value in enumerate(values):
                target_table.setItem(row, col_index, QTableWidgetItem(value))
        self._refresh_dashboard_metrics()

    def _refresh_suspicious_process_table(self) -> None:
        """Rebuild the suspicious process table from the latest detection model."""
        if not hasattr(self, "home_table"):
            return

        selected_key = None
        selected_items = self.home_table.selectedItems()
        if selected_items:
            selected_key = selected_items[0].data(Qt.UserRole)
            if not isinstance(selected_key, tuple):
                selected_key = self._selected_home_process_key_from_row(selected_items[0].row())

        self.home_table.setSortingEnabled(False)
        self.home_table.setRowCount(0)
        self.suspicious_process_rows.clear()

        def _score_for_sort(item: tuple) -> int:
            entry = item[1]
            try:
                return int(entry.get("score", "0") or 0)
            except Exception:
                return 0

        for row_index, (key, entry) in enumerate(
            sorted(self.suspicious_process_entries.items(), key=_score_for_sort, reverse=True)
        ):
            self.home_table.insertRow(row_index)
            self.suspicious_process_rows[key] = row_index
            score = entry.get("score", "0")
            try:
                score_int = int(score)
            except Exception:
                score_int = 0
            severity = self._severity_for_score(score_int)
            status = self._incident_status_for(entry, self._response_actions_for_process(key))
            detection_time = entry.get("timestamp") or entry.get("last_activity") or ""
            values = [
                entry.get("process", ""),
                entry.get("pid", ""),
                str(score),
                severity,
                detection_time,
                status,
            ]
            for col_index, value in enumerate(values):
                item = QTableWidgetItem(value)
                if col_index == 0:
                    item.setData(Qt.UserRole, key)
                self.home_table.setItem(row_index, col_index, item)

        if selected_key is not None:
            for row_index in range(self.home_table.rowCount()):
                item = self.home_table.item(row_index, 0)
                if item is not None and item.data(Qt.UserRole) == selected_key:
                    self.home_table.setCurrentCell(row_index, 0)
                    break

        self.home_table.setSortingEnabled(True)

    def _flush_pending_gui_updates(self) -> None:
        drained_events = 0
        while drained_events < 800:
            try:
                entry = self._filesystem_event_gui_queue.get_nowait()
            except queue.Empty:
                break
            self.event_rows.append(entry)
            self.event_count += 1
            drained_events += 1

        if drained_events:
            self._trim_gui_event_cache()
            self._pending_log_refresh = True
            self._pending_counter_refresh = True
            self._pending_total_events_refresh = True

        if self._pending_suspicious_refresh:
            self._refresh_suspicious_process_table()
            self._pending_suspicious_refresh = False

        if self._pending_process_state_refresh:
            self._refresh_process_state_tables()
            self._pending_process_state_refresh = False

        if self._pending_log_refresh:
            self._refresh_log_table_view()
            self._pending_log_refresh = False

        if self._pending_counter_refresh:
            self._refresh_file_event_counters()
            self._pending_counter_refresh = False

        if self._pending_metrics_refresh:
            self._refresh_dashboard_metrics()
            self._pending_metrics_refresh = False

        if self._pending_total_events_refresh:
            self.total_events_label.setText(f"Total events: {self.event_count}")
            self._pending_total_events_refresh = False

        if self.page_stack.currentIndex() == 5 and self._selected_home_process_key is not None:
            self._populate_incident_page(self._selected_home_process_key)

    def _refresh_dashboard_metrics(self) -> None:
        """Refresh the summary cards on the Home dashboard."""
        if not hasattr(self, "dashboard_metric_labels"):
            return

        monitored = len(self.process_state_cache)
        suspicious = len(self.suspicious_process_rows)
        highest_score = 0
        total_events_sec = 0
        for entry in self.process_state_cache.values():
            try:
                highest_score = max(highest_score, int(entry.get("score", "0") or 0))
            except Exception:
                pass
            try:
                total_events_sec += int(entry.get("events_sec", "0") or 0)
            except Exception:
                pass

        alerts = sum(1 for row in self.event_rows if row.get("event_type") == "DETECTION")
        metrics = {
            "monitored": str(monitored),
            "suspicious": str(suspicious),
            "highest_score": str(highest_score),
            "alerts": str(alerts),
            "events_sec": str(total_events_sec),
        }
        for key, value in metrics.items():
            label = self.dashboard_metric_labels.get(key)
            if label is not None:
                label.setText(value)

    def _trim_gui_event_cache(self) -> None:
        """Bound UI-side event cache size; full history stays in logs.db."""
        if _CONFIG_AVAILABLE:
            max_rows = max(500, int(get_config().monitoring.max_gui_events_displayed))
        else:
            max_rows = 5000
        if len(self.event_rows) <= max_rows:
            return
        overflow = len(self.event_rows) - max_rows
        del self.event_rows[:overflow]

    def _refresh_log_table_view(self) -> None:
        """Apply search and type filters to the File Monitoring table."""
        search_text = self.log_search_input.text().strip().lower() if hasattr(self, "log_search_input") else ""
        filter_text = self.log_filter_combo.currentText() if hasattr(self, "log_filter_combo") else "All Events"

        filtered_rows = []
        for entry in self.event_rows:
            event_type = (entry.get("event_type") or "").upper()
            if filter_text != "All Events" and event_type != filter_text:
                continue

            haystack = " ".join(
                str(entry.get(key, "") or "")
                for key in ("timestamp", "level", "event_type", "file", "file_name", "process", "pid", "executable", "parent_process", "message")
            ).lower()
            if search_text and search_text not in haystack:
                continue
            filtered_rows.append(entry)

        self._displayed_event_rows = filtered_rows
        self.log_table.setSortingEnabled(False)
        self.log_table.setRowCount(0)

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

        for entry in filtered_rows:
            row = self.log_table.rowCount()
            self.log_table.insertRow(row)
            text_color = self._text_color_for_event(entry.get("event_type", ""))
            for col_index, key in enumerate(columns):
                value = entry.get(key, "") or ""
                item = QTableWidgetItem(value)
                if col_index == 2 and text_color is not None:
                    item.setForeground(QBrush(text_color))
                self.log_table.setItem(row, col_index, item)

        self.log_table.setSortingEnabled(True)

    def _refresh_file_event_counters(self) -> None:
        """Update Created/Modified/Moved/Deleted counters from loaded events."""
        if not hasattr(self, "file_event_counter_labels"):
            return

        counts = {
            "FILE CREATED": 0,
            "FILE MODIFIED": 0,
            "FILE MOVED": 0,
            "FILE DELETED": 0,
            "EXTENSION_CHANGE": 0,
        }
        for row in self.event_rows:
            event_type = (row.get("event_type") or "").upper()
            if event_type in counts:
                counts[event_type] += 1

        self.file_event_counter_labels["FILE CREATED"].setText(f"Created: {counts['FILE CREATED']}")
        self.file_event_counter_labels["FILE MODIFIED"].setText(f"Modified: {counts['FILE MODIFIED']}")
        self.file_event_counter_labels["FILE MOVED"].setText(f"Moved: {counts['FILE MOVED']}")
        self.file_event_counter_labels["FILE DELETED"].setText(f"Deleted: {counts['FILE DELETED']}")
        self.file_event_counter_labels["EXTENSION_CHANGE"].setText(f"Ext. Changed: {counts['EXTENSION_CHANGE']}")

    def _process_is_active(self, last_activity: str) -> bool:
        if not last_activity:
            return False
        try:
            timestamp = time.strptime(last_activity, "%Y-%m-%d %H:%M:%S")
            last_ts = time.mktime(timestamp)
            return (time.time() - last_ts) <= 60.0
        except Exception:
            return False

    def _text_color_for_event(self, event_type: str):
        event_type = (event_type or "").upper()
        if "CREAT" in event_type:
            return QColor("#2e7d32")
        if "DELET" in event_type:
            return QColor("#d32f2f")
        if "MODIF" in event_type or "MODIFIED" in event_type or "MODIFY" in event_type:
            return QColor("#1976d2")
        if "EXTENSION" in event_type:
            return QColor("#ff7f7f")
        return None

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

    # ------------------------------------------------------------------
    # Entropy alert handling (called from the worker thread → Qt signal)
    # ------------------------------------------------------------------

    def _entropy_alert_callback(self, event) -> None:
        """Called by EntropyMonitor on the worker thread when an alert fires.

        Args:
            event: EntropyIncreaseDetected dataclass instance.
        """
        # Must cross to the Qt main thread via a signal.
        try:
            self.output_bridge.entropy_alert.emit(
                event.file_path,
                event.process_name or "",
                event.previous_entropy,
                event.current_entropy,
                event.delta,
            )
        except Exception:
            pass

    def _on_entropy_alert_signal(
        self,
        file_path: str,
        process_name: str,
        previous_entropy: float,
        current_entropy: float,
        delta: float,
    ) -> None:
        """Receives an entropy alert on the Qt main thread and shows the banner.

        The Engine score logic should be triggered here.  For now we display
        the alert banner and record a score delta via the existing detection
        infrastructure.
        """
        msg = (
            f"🔐  Entropy spike detected in  {Path(file_path).name}  "
            f"(+{delta:.2f} bits/byte)"
        )
        if process_name:
            msg += f"  ·  Process: {process_name}"
        self._show_alert_banner(msg)
        self.event_rows.append(
            {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "level": "WARNING",
                "event_type": "ENTROPY_ALERT",
                "file": file_path,
                "file_name": Path(file_path).name,
                "process": process_name,
                "pid": "",
                "executable": "",
                "parent_process": "",
                "message": f"Entropy increased from {previous_entropy:.3f} to {current_entropy:.3f} (delta {delta:.3f})",
                "raw_event": "",
            }
        )
        self._trim_gui_event_cache()
        self.event_count += 1
        self._pending_log_refresh = True
        self._pending_counter_refresh = True
        self._pending_total_events_refresh = True

    def _show_alert_banner(self, message: str) -> None:
        """Display the red alert banner on the Home page.

        Args:
            message: Text to show inside the banner.
        """
        self._alert_text.setText(message)
        self.alert_banner.setVisible(True)
        self._alert_banner_visible = True
        # Ensure the user can see the banner by switching to Home.
        # (only switch if not already on Home to avoid interrupting other tasks)
        # We intentionally do NOT force page navigation here to respect user flow.

    def _dismiss_alert_banner(self) -> None:
        """Hide the alert banner when the user clicks Ignore."""
        self.alert_banner.setVisible(False)
        self._alert_banner_visible = False

    def _get_response_target_process(self) -> Optional[dict]:
        """Resolve the process targeted by Quarantine/Delete actions.

        Priority:
        1. Selected row in the suspicious processes table (Home page).
        2. Most recent alert-triggering process.
        3. Highest-score process currently in cache.

        Returns:
            Process-state dict or None when no process is available.
        """
        state = self.__dict__
        selected_process_key = state.get("_selected_home_process_key")
        process_state_cache = state.get("process_state_cache", {})
        if selected_process_key is not None:
            selected_target = process_state_cache.get(selected_process_key)
            if selected_target is not None:
                return selected_target

        home_table = state.get("home_table")
        selected_items = home_table.selectedItems() if home_table is not None else []
        if selected_items:
            row = selected_items[0].row()
            for key, mapped_row in state.get("suspicious_process_rows", {}).items():
                if mapped_row == row:
                    return process_state_cache.get(key)

        last_alert_key = state.get("_last_alert_process_key")
        if last_alert_key is not None:
            target = process_state_cache.get(last_alert_key)
            if target is not None:
                return target

        if not process_state_cache:
            return None

        def _score(item: dict) -> int:
            try:
                return int(item.get("score", "0") or 0)
            except Exception:
                return 0

        return max(process_state_cache.values(), key=_score)

    def _suspend_process_if_running(self, pid_value: Optional[str]) -> str:
        """Suspend a running process, handling already-exited PIDs gracefully."""
        if not pid_value or not str(pid_value).isdigit():
            return "PID unavailable; suspension skipped"
        if psutil is None:
            return "psutil unavailable; suspension skipped"

        pid = int(str(pid_value))
        try:
            proc = psutil.Process(pid)
            if not proc.is_running():
                return "Process exited before quarantine could be performed."
            proc.suspend()
            return f"PID {pid} suspended"
        except psutil.NoSuchProcess:
            return "Process exited before quarantine could be performed."
        except Exception as exc:
            return f"PID {pid} suspension failed: {exc}"

    def _kill_process_if_running(self, pid_value: Optional[str]) -> str:
        """Kill a running process after quarantine succeeds."""
        if not pid_value or not str(pid_value).isdigit():
            return "PID unavailable; kill skipped"
        if psutil is None:
            return "psutil unavailable; kill skipped"

        pid = int(str(pid_value))
        try:
            proc = psutil.Process(pid)
            if not proc.is_running():
                return "Process exited before quarantine could be performed."
            proc.kill()
            return f"PID {pid} killed"
        except psutil.NoSuchProcess:
            return "Process exited before quarantine could be performed."
        except Exception as exc:
            return f"PID {pid} kill failed: {exc}"

    def _terminate_process_if_running(self, pid_value: Optional[str]) -> str:
        """Backward-compatible wrapper retained for existing callers/tests."""
        return self._kill_process_if_running(pid_value)

    def _log_response_action(
        self,
        action: str,
        process_data: dict,
        message: str,
        *,
        status: str,
        source_path: str,
        result_path: str = "",
        termination_status: str = "",
    ) -> None:
        """Persist and surface a user-triggered response action."""
        pid_value = process_data.get("pid")
        pid = int(pid_value) if str(pid_value or "").isdigit() else None
        action_row = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "timestamp_epoch": time.time(),
            "action_type": action,
            "action_label": (
                "Quarantine"
                if action == "QUARANTINE_ACTION"
                else "Ignore"
                if action == "IGNORE_ACTION"
                else "Remove / Terminate"
            ),
            "status": status,
            "process": process_data.get("process") or "",
            "pid": str(pid_value or ""),
            "executable": process_data.get("executable") or "",
            "source_path": source_path,
            "result_path": result_path,
            "termination_status": termination_status,
            "message": message,
        }
        self.response_action_rows.append(action_row)
        if self._selected_home_process_key is not None:
            self._on_home_selection_changed()
            self._populate_incident_page(self._selected_home_process_key)
        self._pending_suspicious_refresh = True
        self._pending_metrics_refresh = True

        if self._alerts_db is None:
            return
        try:
            self._alerts_db.log_alert(
                alert_type=action,
                process_name=process_data.get("process") or None,
                pid=pid,
                executable=process_data.get("executable") or None,
                process_score=int(process_data.get("score") or 0) if str(process_data.get("score") or "").isdigit() else None,
                file_path=source_path or None,
                notes=json.dumps({
                    "status": status,
                    "source_path": source_path,
                    "result_path": result_path,
                    "termination_status": termination_status,
                    "message": message,
                }),
            )
        except Exception:
            logger.exception("Failed to persist response action: %s", action)

    def _perform_quarantine_for_target(self, target: dict, *, automatic: bool) -> bool:
        """Suspend, quarantine executable, then kill process if quarantine succeeds."""
        executable = str(target.get("executable") or "").strip()
        if not executable:
            message = "Selected process had no executable path; quarantine aborted."
            self._log_response_action(
                "QUARANTINE_ACTION",
                target,
                message,
                status="FAILED",
                source_path="",
            )
            if not automatic:
                self.show_error(message)
            return False

        suspend_status = self._suspend_process_if_running(target.get("pid"))
        exe_path = Path(executable).expanduser()
        if not exe_path.exists() or not exe_path.is_file():
            message = f"Executable not found for quarantine: {exe_path}"
            if "Process exited before quarantine could be performed." in suspend_status:
                message = "Process exited before quarantine could be performed."
            self._log_response_action(
                "QUARANTINE_ACTION",
                target,
                message,
                status="FAILED",
                source_path=str(exe_path),
                termination_status=suspend_status,
            )
            if not automatic:
                self.show_error(message)
            return False

        quarantine_dir = get_data_dir() / "quarantine"
        quarantine_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        destination = quarantine_dir / f"{timestamp}_{exe_path.name}"

        try:
            moved_path = Path(shutil.move(str(exe_path), str(destination)))
        except Exception as exc:
            message = f"Failed to quarantine executable: {exc}"
            self._log_response_action(
                "QUARANTINE_ACTION",
                target,
                message,
                status="FAILED",
                source_path=str(exe_path),
                termination_status=suspend_status,
            )
            if not automatic:
                self.show_error(message)
            return False

        kill_status = self._kill_process_if_running(target.get("pid"))
        message = (
            f"Quarantined {target.get('process') or exe_path.name}. "
            f"{suspend_status}; {kill_status}.\nMoved to: {moved_path}"
        )
        self._show_alert_banner(message)
        self._log_response_action(
            "QUARANTINE_ACTION",
            target,
            message,
            status="SUCCEEDED",
            source_path=str(exe_path),
            result_path=str(moved_path),
            termination_status=kill_status,
        )
        if automatic:
            logger.warning("Automatic quarantine executed for PID=%s executable=%s", target.get("pid"), executable)
        return True

    def _on_quarantine_alert_process(self) -> None:
        """Manual quarantine action from GUI controls."""
        target = self._get_response_target_process()
        if target is None:
            self.show_error("No suspicious process available to quarantine.")
            return

        success = self._perform_quarantine_for_target(target, automatic=False)
        if success:
            QMessageBox.information(self, "Quarantine Complete", "Quarantine action completed.")

    def _on_delete_alert_process(self) -> None:
        """Terminate suspected process and delete executable file."""
        target = self._get_response_target_process()
        if target is None:
            self.show_error("No suspicious process available to delete.")
            return

        executable = str(target.get("executable") or "").strip()
        if not executable:
            self._log_response_action(
                "DELETE_ACTION",
                target,
                "Selected process had no executable path; delete aborted.",
                status="FAILED",
                source_path="",
            )
            self.show_error("Selected process has no executable path; cannot delete.")
            return

        exe_path = Path(executable).expanduser()
        if not exe_path.exists() or not exe_path.is_file():
            self._log_response_action(
                "DELETE_ACTION",
                target,
                f"Executable not found for deletion: {exe_path}",
                status="FAILED",
                source_path=str(exe_path),
            )
            self.show_error(f"Executable not found for deletion: {exe_path}")
            return

        confirm = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Delete suspected executable?\n{exe_path}",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return

        terminate_status = self._terminate_process_if_running(target.get("pid"))

        try:
            exe_path.unlink()
        except Exception as exc:
            self._log_response_action(
                "DELETE_ACTION",
                target,
                f"Failed to delete executable: {exc}",
                status="FAILED",
                source_path=str(exe_path),
                termination_status=terminate_status,
            )
            self.show_error(f"Failed to delete executable: {exc}")
            return

        msg = (
            f"Deleted executable for {target.get('process') or exe_path.name}. "
            f"{terminate_status}.\nRemoved: {exe_path}"
        )
        self._show_alert_banner(msg)
        self._log_response_action(
            "DELETE_ACTION",
            target,
            msg,
            status="SUCCEEDED",
            source_path=str(exe_path),
            result_path=str(exe_path),
            termination_status=terminate_status,
        )
        QMessageBox.information(self, "Delete Complete", msg)

    def _on_ignore_alert_process(self) -> None:
        target = self._get_response_target_process()
        if target is None:
            self.show_error("No suspicious process available to ignore.")
            return

        msg = f"Ignored suspicious process {target.get('process') or target.get('executable') or 'Unknown'} (PID {target.get('pid')})."
        self._log_response_action(
            "IGNORE_ACTION",
            target,
            msg,
            status="SUCCEEDED",
            source_path=str(target.get("executable") or ""),
            result_path="",
            termination_status="",
        )
        self._dismiss_alert_banner()
        QMessageBox.information(self, "Ignore Confirmed", msg)

    # ------------------------------------------------------------------
    # Entropy Monitor page refresh
    # ------------------------------------------------------------------

    def _refresh_entropy_table(self) -> None:
        """Populate the Entropy Monitor table with the latest metadata.db data."""
        if not _ENTROPY_AVAILABLE:
            return
        if self._entropy_monitor is None:
            self._refresh_entropy_table_from_db()
            return

        directory_filter = self.entropy_dir_input.text().strip()

        try:
            if directory_filter:
                rows = self._entropy_monitor.get_files_in_directory(directory_filter)
            else:
                rows = self._entropy_monitor.get_monitored_files()
        except Exception:
            return

        self.entropy_table.setSortingEnabled(False)
        self.entropy_table.setRowCount(0)

        for r in rows:
            row_idx = self.entropy_table.rowCount()
            self.entropy_table.insertRow(row_idx)

            file_name    = r["file_name"] or ""
            curr_ent     = r["current_entropy"]
            prev_ent     = r["previous_entropy"]
            file_size    = r["file_size"]
            last_scan    = r["last_scan_ts"]
            exists       = r["exists"]

            # Δ entropy
            if curr_ent is not None and prev_ent is not None:
                delta = curr_ent - prev_ent
                delta_str = f"{delta:+.4f}"
            else:
                delta = None
                delta_str = "—"

            curr_str    = f"{curr_ent:.4f}" if curr_ent is not None else "—"
            prev_str    = f"{prev_ent:.4f}" if prev_ent is not None else "—"
            size_str    = self._format_size(file_size) if file_size else "—"
            scan_str    = (
                datetime.fromtimestamp(last_scan).strftime("%Y-%m-%d %H:%M:%S")
                if last_scan else "—"
            )
            status_str  = "Exists" if exists else "Deleted"

            details_payload = {
                "file_name": file_name or "—",
                "current_entropy": curr_str,
                "previous_entropy": prev_str,
                "delta_entropy": delta_str,
                "file_size": size_str,
                "last_scan": scan_str,
                "status": status_str,
            }

            values = [file_name, curr_str, delta_str, status_str]
            for col, val in enumerate(values):
                item = QTableWidgetItem(val)
                if col == 0:
                    item.setData(Qt.UserRole, details_payload)

                # Colour delta column red if suspicious
                if col == 2 and delta is not None:
                    try:
                        cfg = get_config() if _CONFIG_AVAILABLE else None
                        threshold = cfg.entropy.threshold if cfg else 1.4
                    except Exception:
                        threshold = 1.4
                    if delta >= threshold:
                        item.setForeground(QBrush(QColor("#ff4444")))
                        item.setFont(QFont("Arial", 10, QFont.Bold))
                    elif delta > 0.5:
                        item.setForeground(QBrush(QColor("#ff9800")))
                if col == 3 and status_str == "Deleted":
                    item.setForeground(QBrush(QColor("#808080")))
                self.entropy_table.setItem(row_idx, col, item)

        self.entropy_table.setSortingEnabled(True)
        self._resize_entropy_columns()

    def _refresh_entropy_table_from_db(self) -> None:
        """Fallback path that reads the metadata database directly."""
        if not _DATABASE_AVAILABLE:
            return
        try:
            metadata_db = get_metadata_db()
            rows = metadata_db.get_all_existing()
        except Exception:
            return

        self.entropy_table.setSortingEnabled(False)
        self.entropy_table.setRowCount(0)
        for row in rows:
            row_idx = self.entropy_table.rowCount()
            self.entropy_table.insertRow(row_idx)
            values = [
                row["file_name"] or Path(row["file_path"]).name,
                f"{row['current_entropy']:.4f}" if row["current_entropy"] is not None else "—",
                f"{(row['current_entropy'] - row['previous_entropy']):+.4f}" if row["current_entropy"] is not None and row["previous_entropy"] is not None else "—",
                "Exists" if row["exists"] else "Deleted",
            ]
            for col_index, value in enumerate(values):
                item = QTableWidgetItem(value)
                self.entropy_table.setItem(row_idx, col_index, item)
        self.entropy_table.setSortingEnabled(True)
        self._resize_entropy_columns()

    def _run_manual_entropy_refresh(self) -> None:
        """Run a full filesystem-based entropy rebuild asynchronously."""
        if self._entropy_refresh_in_progress:
            return
        if not _DATABASE_AVAILABLE:
            self.show_error("Database module unavailable; cannot refresh entropy data.")
            return
        entropy_dir_text = self.entropy_dir_input.text().strip()
        if not entropy_dir_text:
            self.show_error("Please enter an entropy monitoring directory.")
            return
        entropy_root = Path(entropy_dir_text).expanduser()
        if not entropy_root.exists() or not entropy_root.is_dir():
            self.show_error(f"Invalid entropy directory: {entropy_root}")
            return

        self._entropy_refresh_in_progress = True
        self.entropy_status_label.setText("Scanning filesystem for entropy refresh…")
        self.entropy_status_label.setStyleSheet("color: #ff9800; font-size: 11px;")

        metadata_db = get_metadata_db()
        self._entropy_rebuild_thread = QThread(self)
        self._entropy_rebuild_worker = EntropyBuildWorker(
            metadata_db=metadata_db,
            root=entropy_root,
            allowed_extensions=set(get_config().entropy.file_extensions) if _CONFIG_AVAILABLE else set(),
            sample_size_bytes=get_config().entropy.sample_size_bytes if _CONFIG_AVAILABLE else 5 * 1024 * 1024,
        )
        self._entropy_rebuild_worker.moveToThread(self._entropy_rebuild_thread)
        self._entropy_rebuild_thread.started.connect(self._entropy_rebuild_worker.run)
        self._entropy_rebuild_worker.progress.connect(self._on_entropy_rebuild_progress)
        self._entropy_rebuild_worker.completed.connect(self._on_manual_entropy_refresh_finished)
        self._entropy_rebuild_worker.failed.connect(self._on_entropy_rebuild_failed)
        self._entropy_rebuild_worker.completed.connect(self._entropy_rebuild_thread.quit)
        self._entropy_rebuild_worker.failed.connect(self._entropy_rebuild_thread.quit)
        self._entropy_rebuild_thread.finished.connect(self._cleanup_entropy_rebuild_worker)
        self._entropy_rebuild_thread.start()

    def _on_manual_entropy_refresh_finished(self, total: int, processed: int, added: int, removed: int, updated: int) -> None:
        self._entropy_refresh_in_progress = False
        self.entropy_status_label.setText(
            f"Refresh complete — scanned {processed}/{total} files, added {added}, removed {removed}, updated {updated}."
        )
        self.entropy_status_label.setStyleSheet("color: #4CAF50; font-size: 11px;")
        self._refresh_entropy_table()

    def _on_entropy_selection_changed(self) -> None:
        """Update the details panel with data from the selected entropy row."""
        selected = self.entropy_table.selectedItems()
        if not selected:
            return

        row = selected[0].row()
        anchor_item = self.entropy_table.item(row, 0)
        if anchor_item is None:
            return

        payload = anchor_item.data(Qt.UserRole)
        if not isinstance(payload, dict):
            return

        self.entropy_details_hint.setVisible(False)
        self.entropy_detail_labels["file_name"].setText(f"File Name: {payload.get('file_name', '—')}")
        self.entropy_detail_labels["current_entropy"].setText(f"Current Entropy: {payload.get('current_entropy', '—')}")
        self.entropy_detail_labels["previous_entropy"].setText(f"Previous Entropy: {payload.get('previous_entropy', '—')}")
        self.entropy_detail_labels["delta_entropy"].setText(f"Delta Entropy: {payload.get('delta_entropy', '—')}")
        self.entropy_detail_labels["file_size"].setText(f"File Size: {payload.get('file_size', '—')}")
        self.entropy_detail_labels["last_scan"].setText(f"Last Scan: {payload.get('last_scan', '—')}")
        self.entropy_detail_labels["status"].setText(f"Status: {payload.get('status', '—')}")

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        """Convert a byte count to a human-readable string.

        Args:
            size_bytes: Number of bytes.

        Returns:
            String like '12.4 KB', '3.1 MB'.
        """
        for unit in ("B", "KB", "MB", "GB"):
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} TB"


def main():
    # Enable Windows-friendly HiDPI scaling so fonts/layout remain readable on scaled displays.
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    app = QApplication(sys.argv)

    from startup_dashboard import StartupDashboard
    from initialization_manager import InitializationManager

    startup = StartupDashboard()
    init_manager = InitializationManager(gui_factory=RdrsGui)

    def _on_desktop_mode_selected(entropy_dir: str, file_monitor_dir: str) -> None:
        init_manager.start(entropy_dir=entropy_dir, file_monitor_dir=file_monitor_dir)

    startup.desktop_mode_selected.connect(_on_desktop_mode_selected)
    startup.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
