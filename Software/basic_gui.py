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
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set

try:
    import psutil
except ImportError:
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
    QDialog,
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

try:
    from config import get_config
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
        
        main_layout.addLayout(header_layout)
        
        # Splitter for sections
        splitter = QSplitter(Qt.Vertical)
        
        # === General Information Section ===
        info_frame = QFrame()
        info_frame.setStyleSheet("QFrame { background: #1f2430; border: 1px solid #2d3547; border-radius: 8px; padding: 12px; }")
        info_layout = QVBoxLayout()
        
        info_title = QLabel("General Information")
        info_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #ffffff; margin-bottom: 8px;")
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
        activity_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #ffffff; margin-bottom: 8px;")
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
        
        # === File Activity Timeline Section ===
        timeline_frame = QFrame()
        timeline_frame.setStyleSheet("QFrame { background: #1f2430; border: 1px solid #2d3547; border-radius: 8px; padding: 12px; }")
        timeline_layout = QVBoxLayout()
        
        timeline_header_layout = QHBoxLayout()
        timeline_title = QLabel("File Activity Timeline")
        timeline_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #ffffff;")
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
        self.timeline_table.setStyleSheet("QTableWidget { background: #171b25; font-size: 11px; }")
        
        timeline_layout.addWidget(self.timeline_table)
        timeline_frame.setLayout(timeline_layout)
        splitter.addWidget(timeline_frame)
        
        # Set splitter proportions
        splitter.setSizes([200, 150, 450])
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
        # Extract file events from raw_event if available
        # This is a simplified version - in production, the monitor should expose events directly
        self._extract_file_events()
        
        # Apply current filters
        self._apply_filters()
    
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
        self.suspicious_process_rows: Dict[Tuple[Optional[str], str], int] = {}
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

        # --- Alert banner state -------------------------------------------
        self._alert_banner_visible: bool = False
        # Timer to periodically refresh the entropy page data.
        self._entropy_refresh_timer = QTimer()
        self._entropy_refresh_timer.setInterval(5000)  # 5-second refresh
        self._entropy_refresh_timer.timeout.connect(self.output_bridge.entropy_data_updated.emit)

        # Persistent logs DB handle (available even when entropy module is not).
        self._logs_db = None
        if _DATABASE_AVAILABLE:
            try:
                self._logs_db = get_logs_db()
            except Exception:
                self._logs_db = None

        self.setWindowTitle("RDRS GUI Monitor")
        self.setStyleSheet(
            "QWidget { background: #171b25; color: #f0f0f0; font-family: Segoe UI, Arial, sans-serif; }"
            "QPushButton { border: none; padding: 10px 12px; text-align: left; }"
            "QPushButton:hover { background: #2b3140; }"
            "QHeaderView::section { background: #242b3a; color: white; padding: 8px; border: none; }"
            "QTableWidget { background: #1f2430; gridline-color: #2d3547; }"
        )
        self.build_ui()
        self._load_persisted_logs(limit=300)

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

        self.processes_button = QPushButton("▶ Processes")
        self.processes_button.clicked.connect(lambda: self.select_page(2))
        self.processes_button.setStyleSheet("font-weight: bold; color: white; background: transparent;")
        sidebar_layout.addWidget(self.processes_button)

        self.entropy_button = QPushButton("▶ Entropy Monitor")
        self.entropy_button.clicked.connect(lambda: self.select_page(3))
        self.entropy_button.setStyleSheet("font-weight: bold; color: white; background: transparent;")
        sidebar_layout.addWidget(self.entropy_button)

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
        btn_ignore.clicked.connect(self._dismiss_alert_banner)
        alert_banner_layout.addWidget(btn_ignore)

        btn_quarantine = QPushButton("Quarantine")
        btn_quarantine.setStyleSheet(_stub_style)
        btn_quarantine.setToolTip("Not yet implemented in v1.0")
        alert_banner_layout.addWidget(btn_quarantine)

        btn_delete = QPushButton("Delete")
        btn_delete.setStyleSheet(_stub_style)
        btn_delete.setToolTip("Not yet implemented in v1.0")
        alert_banner_layout.addWidget(btn_delete)

        btn_more = QPushButton("More Information")
        btn_more.setStyleSheet(_stub_style)
        btn_more.setToolTip("Not yet implemented in v1.0")
        alert_banner_layout.addWidget(btn_more)

        self.alert_banner.setLayout(alert_banner_layout)
        self.alert_banner.setVisible(False)
        home_layout.addWidget(self.alert_banner)

        self.home_table = QTableWidget(0, 9)
        self.home_table.setHorizontalHeaderLabels([
            "Process Name",
            "PID",
            "Executable",
            "Score",
            "Modified",
            "Created",
            "Deleted",
            "Unique Directories",
            "Last Activity",
        ])
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

        self.processes_page = QWidget()
        processes_layout = QVBoxLayout()
        processes_layout.setContentsMargins(24, 24, 24, 24)
        processes_layout.setSpacing(14)
        self.processes_page.setLayout(processes_layout)

        processes_title = QLabel("Processes")
        processes_title.setStyleSheet("font-size: 20px; font-weight: bold; color: #ffffff;")
        processes_layout.addWidget(processes_title)

        process_description = QLabel("Active and inactive process summaries are shown here. Each row reflects the current process state from the monitor.")
        process_description.setWordWrap(True)
        process_description.setStyleSheet("color: #d1d1d1; font-size: 12px; margin-bottom: 10px;")
        processes_layout.addWidget(process_description)

        processes_split_layout = QHBoxLayout()
        processes_split_layout.setSpacing(16)

        active_container = QWidget()
        active_layout = QVBoxLayout()
        active_layout.setContentsMargins(0, 0, 0, 0)
        active_layout.setSpacing(8)
        active_container.setLayout(active_layout)

        active_label = QLabel("Active Processes")
        active_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #ffffff;")
        active_layout.addWidget(active_label)

        self.active_process_table = QTableWidget(0, 13)
        self.active_process_table.setHorizontalHeaderLabels([
            "Process Name",
            "PID",
            "Process Age",
            "Executable Path",
            "Files Created",
            "Files Modified",
            "Files Deleted",
            "Unique Files",
            "Events/sec",
            "Events/min",
            "Current Score",
            "Classification",
            "Last Activity",
        ])
        self.active_process_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.active_process_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.active_process_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.active_process_table.setSelectionMode(QTableWidget.SingleSelection)
        self.active_process_table.setStyleSheet(
            "QTableWidget { background: #1f2430; font-size: 12px; }"
            "QHeaderView::section { padding: 10px; }"
        )
        self.active_process_table.doubleClicked.connect(self.on_process_double_click)
        active_layout.addWidget(self.active_process_table)

        inactive_container = QWidget()
        inactive_layout = QVBoxLayout()
        inactive_layout.setContentsMargins(0, 0, 0, 0)
        inactive_layout.setSpacing(8)
        inactive_container.setLayout(inactive_layout)

        inactive_label = QLabel("Inactive Processes")
        inactive_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #ffffff;")
        inactive_layout.addWidget(inactive_label)

        self.inactive_process_table = QTableWidget(0, 13)
        self.inactive_process_table.setHorizontalHeaderLabels([
            "Process Name",
            "PID",
            "Process Age",
            "Executable Path",
            "Files Created",
            "Files Modified",
            "Files Deleted",
            "Unique Files",
            "Events/sec",
            "Events/min",
            "Current Score",
            "Classification",
            "Last Activity",
        ])
        self.inactive_process_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.inactive_process_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.inactive_process_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.inactive_process_table.setSelectionMode(QTableWidget.SingleSelection)
        self.inactive_process_table.setStyleSheet(
            "QTableWidget { background: #1f2430; font-size: 12px; }"
            "QHeaderView::section { padding: 10px; }"
        )
        self.inactive_process_table.doubleClicked.connect(self.on_process_double_click)
        inactive_layout.addWidget(self.inactive_process_table)

        processes_split_layout.addWidget(active_container, 1)
        processes_split_layout.addWidget(inactive_container, 1)
        processes_layout.addLayout(processes_split_layout)
        self.page_stack.addWidget(self.processes_page)

        # ---- Entropy Monitor page ----------------------------------------
        self.entropy_page = QWidget()
        entropy_layout = QVBoxLayout()
        entropy_layout.setContentsMargins(24, 24, 24, 24)
        entropy_layout.setSpacing(14)
        self.entropy_page.setLayout(entropy_layout)

        entropy_title = QLabel("Entropy Monitor")
        entropy_title.setStyleSheet("font-size: 18px; font-weight: bold; color: #ffffff;")
        entropy_layout.addWidget(entropy_title)

        entropy_desc = QLabel(
            "Displays entropy values for monitored files. "
            "High entropy increases may indicate encryption by ransomware."
        )
        entropy_desc.setWordWrap(True)
        entropy_desc.setStyleSheet("color: #d1d1d1; font-size: 12px; margin-bottom: 6px;")
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
        self.entropy_dir_input.setPlaceholderText("Filter by directory prefix…")
        entropy_toolbar.addWidget(self.entropy_dir_input, 1)

        btn_refresh_entropy = QPushButton("↻ Refresh")
        btn_refresh_entropy.clicked.connect(self._refresh_entropy_table)
        btn_refresh_entropy.setStyleSheet(
            "background: #2f3a59; color: white; font-weight: bold; padding: 8px 16px; border-radius: 4px;"
        )
        entropy_toolbar.addWidget(btn_refresh_entropy)

        entropy_layout.addLayout(entropy_toolbar)

        # Status label for entropy module state
        self.entropy_status_label = QLabel(
            "⚠ Entropy module not available — install the 'entropy' and 'database' packages."
            if not _ENTROPY_AVAILABLE else
            "Entropy module ready.  Start the monitor to begin tracking."
        )
        self.entropy_status_label.setStyleSheet("color: #ff9800; font-size: 11px;")
        self.entropy_status_label.setWordWrap(True)
        entropy_layout.addWidget(self.entropy_status_label)

        # File explorer-style table
        self.entropy_table = QTableWidget(0, 7)
        self.entropy_table.setHorizontalHeaderLabels([
            "File Name",
            "Current Entropy",
            "Previous Entropy",
            "Δ Entropy",
            "File Size",
            "Last Scan",
            "Status",
        ])
        self.entropy_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.entropy_table.horizontalHeader().setStretchLastSection(True)
        self.entropy_table.setColumnWidth(0, 240)
        self.entropy_table.setColumnWidth(1, 120)
        self.entropy_table.setColumnWidth(2, 120)
        self.entropy_table.setColumnWidth(3, 100)
        self.entropy_table.setColumnWidth(4, 90)
        self.entropy_table.setColumnWidth(5, 160)
        self.entropy_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.entropy_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.entropy_table.setSelectionMode(QTableWidget.SingleSelection)
        self.entropy_table.setSortingEnabled(True)
        self.entropy_table.setStyleSheet(
            "QTableWidget { background: #1f2430; font-size: 12px; }"
            "QHeaderView::section { padding: 8px; }"
        )
        entropy_layout.addWidget(self.entropy_table)

        self.page_stack.addWidget(self.entropy_page)

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
        # Reset all buttons to inactive style
        _inactive = "font-weight: bold; color: #ffffff; background: transparent;"
        _active   = "font-weight: bold; color: white; background: #2d3a5a; border-radius: 8px;"

        self.home_button.setStyleSheet(_inactive)
        self.monitoring_button.setStyleSheet(_inactive)
        self.processes_button.setStyleSheet(_inactive)
        self.entropy_button.setStyleSheet(_inactive)

        self.home_button.setText("▶ Home")
        self.monitoring_button.setText("▶ File Monitoring")
        self.processes_button.setText("▶ Processes")
        self.entropy_button.setText("▶ Entropy Monitor")

        if index == 0:
            self.home_button.setText("▼ Home")
            self.home_button.setStyleSheet(_active)
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

    def start_monitor(self):
        if self.monitor_session is not None and self.monitor_session.is_running:
            return

        monitor_path_text = self.path_input.text().strip() or str(Path.home())
        monitor_path = Path(monitor_path_text).expanduser()
        if not monitor_path.exists():
            self.handle_error(f"Monitor path does not exist: {monitor_path}")
            return

        # Keep the Entropy Monitor page aligned with the active monitored
        # directory so its table queries the same tree the file monitor is
        # watching. Without this, the entropy table can stay empty even though
        # metadata.db contains rows for the active directory.
        if hasattr(self, "entropy_dir_input"):
            self.entropy_dir_input.setText(str(monitor_path))

        self._pending_log_lines.clear()
        self.append_raw_line(f"Starting monitor for: {monitor_path}")
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

                self._entropy_monitor = EntropyMonitor(
                    metadata_db=meta_db,
                    logs_db=logs_db,
                    alerts_db=alerts_db,
                    allowed_extensions=allowed_ext,
                    sample_size_bytes=sample_size,
                    threshold=threshold,
                    on_entropy_alert=self._entropy_alert_callback,
                    retention_days=retention,
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
    ) -> None:
        """Handle raw filesystem events from the monitor callback.

        This callback runs on watchdog's observer thread. It must stay light:
        - persist event to logs.db (best effort)
        - forward event to EntropyMonitor (if active)
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
                self._logs_db.log_event(
                    event_type=event_type,
                    file_path=file_path,
                    file_name=Path(file_path).name,
                    process=process_name,
                    pid=pid,
                    executable=executable,
                    parent=parent,
                )
                logger.info(
                    "[ENTROPY_TRACE][GUI_CALLBACK] logs_db_write_ok event=%s file=%s",
                    event_type,
                    file_path,
                )
            except Exception:
                logger.exception(
                    "[ENTROPY_TRACE][GUI_CALLBACK] logs_db_write_error event=%s file=%s",
                    event_type,
                    file_path,
                )

        if self._entropy_monitor is not None:
            try:
                self._entropy_monitor.on_file_event(
                    event_type,
                    file_path,
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
            logger.warning(
                "[ENTROPY_TRACE][GUI_CALLBACK] entropy monitor is None; skip forward event=%s file=%s",
                event_type,
                file_path,
            )

    def stop_monitor(self):
        if self.monitor_session is None:
            return
        try:
            self.monitor_session.stop()
        except Exception as exc:
            self.handle_error(f"Failed to stop monitor: {exc}")
        self.monitor_session = None
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
        self._update_suspicious_process_table(entry)
        self._update_process_state_table(entry)

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

    def on_table_selection_changed(self):
        """Handle log table selection changes."""
        selected_items = self.log_table.selectedItems()
        if not selected_items:
            return
        row = selected_items[0].row()
        if 0 <= row < len(self.event_rows):
            entry = self.event_rows[row]
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
        entry = self._parse_logger_entry(lines)
        entry["raw_event"] = "\n".join(lines)
        # Try to enrich the record (best-effort; never blocks the monitor).
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
            if is_process_state:
                self._parse_process_state_block(body, log_record)
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
        if score < 50:
            return

        key = (entry.get("pid"), entry.get("executable", ""))
        row = self.suspicious_process_rows.get(key)
        values = [
            entry.get("process", ""),
            entry.get("pid", ""),
            entry.get("executable", ""),
            str(score),
            entry.get("files_modified", ""),
            entry.get("files_created", ""),
            entry.get("files_deleted", ""),
            entry.get("unique_directories", ""),
            entry.get("last_activity", ""),
        ]
        if row is None:
            row = self.home_table.rowCount()
            self.home_table.insertRow(row)
            self.suspicious_process_rows[key] = row
        for col_index, value in enumerate(values):
            item = QTableWidgetItem(value)
            self.home_table.setItem(row, col_index, item)

        # Show alert banner if score meets or exceeds configured threshold.
        try:
            threshold = get_config().alerts.process_alert_threshold if _CONFIG_AVAILABLE else 70
        except Exception:
            threshold = 70
        if score >= threshold and not self._alert_banner_visible:
            process = entry.get("process") or entry.get("executable") or "Unknown process"
            self._show_alert_banner(
                f"⚠  {process}  has reached a threat score of {score}."
            )

    def _update_process_state_table(self, entry: dict) -> None:
        if entry.get("event_type") != "PROCESS_STATE":
            return
        key = (entry.get("pid"), entry.get("executable", ""))
        self.process_state_cache[key] = entry.copy()
        self._refresh_process_state_tables()

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
                entry.get("process_age", ""),
                entry.get("executable", ""),
                entry.get("files_created", ""),
                entry.get("files_modified", ""),
                entry.get("files_deleted", ""),
                entry.get("unique_files", ""),
                entry.get("events_sec", ""),
                entry.get("events_min", ""),
                entry.get("score", ""),
                entry.get("classification", ""),
                entry.get("last_activity", ""),
            ]
            for col_index, value in enumerate(values):
                target_table.setItem(row, col_index, QTableWidgetItem(value))

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
            return QColor("#007a00")
        if "DELET" in event_type:
            return QColor("#a00000")
        if "MODIF" in event_type or "MODIFIED" in event_type or "MODIFY" in event_type:
            return QColor("#003a9e")
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

    # ------------------------------------------------------------------
    # Entropy Monitor page refresh
    # ------------------------------------------------------------------

    def _refresh_entropy_table(self) -> None:
        """Populate the Entropy Monitor table with the latest metadata.db data."""
        if not _ENTROPY_AVAILABLE or self._entropy_monitor is None:
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

            values = [file_name, curr_str, prev_str, delta_str, size_str, scan_str, status_str]
            for col, val in enumerate(values):
                item = QTableWidgetItem(val)
                # Colour delta column red if suspicious
                if col == 3 and delta is not None:
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
                if col == 6 and status_str == "Deleted":
                    item.setForeground(QBrush(QColor("#808080")))
                self.entropy_table.setItem(row_idx, col, item)

        self.entropy_table.setSortingEnabled(True)

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
    app = QApplication(sys.argv)
    window = RdrsGui()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
