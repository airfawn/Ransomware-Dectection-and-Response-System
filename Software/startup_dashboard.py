"""Startup dashboard (mode selection) for RDRS."""

from __future__ import annotations

from pathlib import Path

from PyQt5.QtCore import pyqtSignal, Qt
from PyQt5.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QStackedWidget,
    QWidget,
    QLabel,
    QLineEdit,
    QPushButton,
    QFrame,
    QFileDialog,
    QMessageBox,
)

from config import get_config, save_startup_directories


class StartupDashboard(QDialog):
    """Stage-1 startup mode selector shown before main dashboard launch."""

    desktop_mode_selected = pyqtSignal(str, str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("RDRS Startup")
        self.setMinimumSize(760, 520)

        cfg = get_config()
        entropy_dirs = cfg.entropy.directories or [str(Path.home())]
        self._remembered_entropy_dir = str(Path(entropy_dirs[0]).expanduser())
        self._remembered_file_monitor_dir = str(
            Path(cfg.monitoring.file_monitor_directory or str(Path.home())).expanduser()
        )

        layout = QVBoxLayout()
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(14)
        self.setLayout(layout)

        self._stack = QStackedWidget()
        layout.addWidget(self._stack)

        self._mode_page = QWidget()
        mode_layout = QVBoxLayout()
        mode_layout.setContentsMargins(0, 0, 0, 0)
        mode_layout.setSpacing(14)
        self._mode_page.setLayout(mode_layout)

        title = QLabel("RDRS Startup")
        title.setStyleSheet("font-size: 28px; font-weight: 900; color: #ffffff;")
        mode_layout.addWidget(title)

        subtitle = QLabel(
            "Select how you would like to run the Ransomware Detection and Response System."
        )
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("color: #d9d9d9; font-size: 12pt;")
        mode_layout.addWidget(subtitle)

        remembered = QLabel(
            "Remembered paths for next launch:\n"
            f"• Entropy: {self._remembered_entropy_dir}\n"
            f"• File Monitor: {self._remembered_file_monitor_dir}"
        )
        remembered.setWordWrap(True)
        remembered.setStyleSheet("color: #9fb3d1; font-size: 10pt;")
        mode_layout.addWidget(remembered)

        mode_layout.addWidget(self._mode_card(
            title="Desktop Mode",
            status="Available",
            description="Runs the complete desktop application with the graphical interface and local monitoring.",
            button_text="Start Desktop Mode",
            callback=self._open_desktop_mode_page,
            enabled=True,
        ))

        mode_layout.addWidget(self._mode_card(
            title="REST API Mode",
            status="Coming Soon",
            description="Headless service mode for API-based integration.",
            button_text="Coming Soon",
            callback=None,
            enabled=False,
        ))

        mode_layout.addWidget(self._mode_card(
            title="Docker Mode",
            status="Coming Soon",
            description="Containerized deployment workflow for orchestrated environments.",
            button_text="Coming Soon",
            callback=None,
            enabled=False,
        ))

        mode_layout.addStretch()

        self._desktop_page = QWidget()
        desktop_layout = QVBoxLayout()
        desktop_layout.setContentsMargins(0, 0, 0, 0)
        desktop_layout.setSpacing(14)
        self._desktop_page.setLayout(desktop_layout)

        desktop_title = QLabel("Desktop Mode Setup")
        desktop_title.setStyleSheet("font-size: 24px; font-weight: 900; color: #ffffff;")
        desktop_layout.addWidget(desktop_title)

        desktop_subtitle = QLabel(
            "Select directories for entropy monitoring and file monitoring, then continue to initialization."
        )
        desktop_subtitle.setWordWrap(True)
        desktop_subtitle.setStyleSheet("color: #d9d9d9; font-size: 12pt;")
        desktop_layout.addWidget(desktop_subtitle)

        entropy_label = QLabel("Entropy Monitoring Directory")
        entropy_label.setStyleSheet("font-size: 11pt; font-weight: bold; color: #ffffff;")
        desktop_layout.addWidget(entropy_label)

        entropy_row = QHBoxLayout()
        entropy_row.setSpacing(10)
        self._entropy_path_input = QLineEdit(self._remembered_entropy_dir)
        self._entropy_path_input.setStyleSheet(
            "background: #222938; color: white; border: 1px solid #2f3a59; padding: 8px; border-radius: 6px;"
        )
        entropy_row.addWidget(self._entropy_path_input, 1)
        entropy_browse_btn = QPushButton("Browse")
        entropy_browse_btn.clicked.connect(self._browse_entropy_directory)
        entropy_row.addWidget(entropy_browse_btn)
        desktop_layout.addLayout(entropy_row)

        monitor_label = QLabel("File Monitoring Directory")
        monitor_label.setStyleSheet("font-size: 11pt; font-weight: bold; color: #ffffff;")
        desktop_layout.addWidget(monitor_label)

        monitor_row = QHBoxLayout()
        monitor_row.setSpacing(10)
        self._monitor_path_input = QLineEdit(self._remembered_file_monitor_dir)
        self._monitor_path_input.setStyleSheet(
            "background: #222938; color: white; border: 1px solid #2f3a59; padding: 8px; border-radius: 6px;"
        )
        monitor_row.addWidget(self._monitor_path_input, 1)
        monitor_browse_btn = QPushButton("Browse")
        monitor_browse_btn.clicked.connect(self._browse_file_monitor_directory)
        monitor_row.addWidget(monitor_browse_btn)
        desktop_layout.addLayout(monitor_row)

        actions_row = QHBoxLayout()
        actions_row.setSpacing(10)
        back_btn = QPushButton("Back")
        back_btn.clicked.connect(self._show_mode_page)
        actions_row.addWidget(back_btn)
        actions_row.addStretch()
        start_btn = QPushButton("Start Initialization")
        start_btn.clicked.connect(self._start_desktop_mode)
        actions_row.addWidget(start_btn)
        desktop_layout.addLayout(actions_row)
        desktop_layout.addStretch()

        self._stack.addWidget(self._mode_page)
        self._stack.addWidget(self._desktop_page)
        self._show_mode_page()

        self.setStyleSheet(
            "QDialog { background: #141a26; color: #f0f0f0; }"
            "QFrame { background: #1f2430; border: 1px solid #2d3547; border-radius: 10px; }"
            "QPushButton { background: #2f3a59; color: #ffffff; font-weight: bold; padding: 10px 16px; border-radius: 6px; }"
            "QPushButton:hover:!disabled { background: #3b4a73; }"
            "QPushButton:disabled { background: #4a4f60; color: #b0b0b0; }"
        )

    def _mode_card(self, *, title: str, status: str, description: str, button_text: str, callback, enabled: bool) -> QFrame:
        card = QFrame()
        card_layout = QVBoxLayout()
        card_layout.setContentsMargins(16, 14, 16, 14)
        card_layout.setSpacing(8)
        card.setLayout(card_layout)

        title_label = QLabel(f"{title}  ({status})")
        title_label.setStyleSheet("font-size: 15pt; font-weight: bold; color: #ffffff;")
        card_layout.addWidget(title_label)

        desc_label = QLabel(description)
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet("color: #d1d1d1; font-size: 11pt;")
        card_layout.addWidget(desc_label)

        button = QPushButton(button_text)
        button.setEnabled(enabled)
        if callback is not None:
            button.clicked.connect(callback)
        card_layout.addWidget(button, alignment=Qt.AlignLeft)

        return card

    def _open_desktop_mode_page(self) -> None:
        self._stack.setCurrentWidget(self._desktop_page)

    def _show_mode_page(self) -> None:
        self._stack.setCurrentWidget(self._mode_page)

    def _browse_entropy_directory(self) -> None:
        selected = QFileDialog.getExistingDirectory(
            self,
            "Select Entropy Monitoring Directory",
            self._entropy_path_input.text().strip() or self._remembered_entropy_dir,
        )
        if selected:
            self._entropy_path_input.setText(selected)

    def _browse_file_monitor_directory(self) -> None:
        selected = QFileDialog.getExistingDirectory(
            self,
            "Select File Monitoring Directory",
            self._monitor_path_input.text().strip() or self._remembered_file_monitor_dir,
        )
        if selected:
            self._monitor_path_input.setText(selected)

    def _start_desktop_mode(self) -> None:
        """Validate selected paths, persist config, and emit selection."""
        entropy_dir = self._entropy_path_input.text().strip()
        file_monitor_dir = self._monitor_path_input.text().strip()
        if not entropy_dir or not file_monitor_dir:
            QMessageBox.warning(
                self,
                "Missing Directory",
                "Please select both Entropy Monitoring and File Monitoring directories.",
            )
            return

        entropy_path = Path(entropy_dir).expanduser()
        file_path = Path(file_monitor_dir).expanduser()
        if not entropy_path.exists() or not entropy_path.is_dir():
            QMessageBox.warning(self, "Invalid Directory", "Entropy Monitoring Directory is invalid.")
            return
        if not file_path.exists() or not file_path.is_dir():
            QMessageBox.warning(self, "Invalid Directory", "File Monitoring Directory is invalid.")
            return

        saved = save_startup_directories(str(entropy_path), str(file_path))
        if not saved:
            QMessageBox.warning(
                self,
                "Config Save Failed",
                "Directories could not be written to config.yaml. Please verify permissions.",
            )
            return

        self.desktop_mode_selected.emit(str(entropy_path), str(file_path))
        self.accept()
