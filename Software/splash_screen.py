"""Startup and loading dialogs for RDRS."""

from __future__ import annotations

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QHBoxLayout,
    QPlainTextEdit,
)


class InitializationSplashScreen(QDialog):
    """Responsive splash screen showing startup task progress."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("RDRS Initialization")
        self.setMinimumSize(760, 520)
        self.setModal(False)

        layout = QVBoxLayout()
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)
        self.setLayout(layout)

        title = QLabel("RDRS Initializing")
        title.setStyleSheet("font-size: 24px; font-weight: 800; color: #ffffff;")
        layout.addWidget(title)

        subtitle = QLabel("Preparing modules and loading startup data. Please wait...")
        subtitle.setStyleSheet("color: #d9d9d9; font-size: 12pt;")
        layout.addWidget(subtitle)

        self.current_step_label = QLabel("Starting...")
        self.current_step_label.setStyleSheet("font-size: 15pt; font-weight: bold; color: #ffffff;")
        layout.addWidget(self.current_step_label)

        self.current_status_label = QLabel("Waiting")
        self.current_status_label.setStyleSheet("color: #b8c0d0; font-size: 11pt;")
        self.current_status_label.setWordWrap(True)
        layout.addWidget(self.current_status_label)

        self.overall_bar = QProgressBar()
        self.overall_bar.setRange(0, 100)
        self.overall_bar.setValue(0)
        self.overall_bar.setStyleSheet("QProgressBar { min-height: 20px; }")
        layout.addWidget(self.overall_bar)

        entropy_title = QLabel("Entropy Build Progress")
        entropy_title.setStyleSheet("color: #dfe7f2; font-size: 11pt; font-weight: bold;")
        layout.addWidget(entropy_title)

        self.entropy_status_label = QLabel("Pending")
        self.entropy_status_label.setStyleSheet("color: #d1d1d1; font-size: 10pt;")
        self.entropy_status_label.setWordWrap(True)
        layout.addWidget(self.entropy_status_label)

        self.entropy_bar = QProgressBar()
        self.entropy_bar.setRange(0, 100)
        self.entropy_bar.setValue(0)
        layout.addWidget(self.entropy_bar)

        history_label = QLabel("Completed Steps")
        history_label.setStyleSheet("color: #dfe7f2; font-size: 11pt; font-weight: bold;")
        layout.addWidget(history_label)

        self.history_box = QPlainTextEdit()
        self.history_box.setReadOnly(True)
        self.history_box.setPlaceholderText("No completed steps yet.")
        layout.addWidget(self.history_box, 1)

        btn_row = QHBoxLayout()
        btn_row.addStretch()

        self.close_button = QPushButton("Close")
        self.close_button.setEnabled(False)
        self.close_button.clicked.connect(self.close)
        btn_row.addWidget(self.close_button)

        layout.addLayout(btn_row)

        self.setStyleSheet(
            "QDialog { background: #141a26; color: #f0f0f0; }"
            "QPlainTextEdit { background: #1f2430; border: 1px solid #2d3547; border-radius: 6px; }"
            "QProgressBar { background: #1f2430; border: 1px solid #2d3547; border-radius: 6px; text-align: center; }"
            "QProgressBar::chunk { background: #2d72d9; border-radius: 6px; }"
            "QPushButton { background: #2f3a59; color: #ffffff; font-weight: bold; padding: 8px 16px; border-radius: 6px; }"
            "QPushButton:disabled { background: #4a4f60; color: #b0b0b0; }"
        )

    def on_step_started(self, index: int, total: int, title: str, status: str) -> None:
        self.current_step_label.setText(f"Step {index}/{total}: {title}")
        self.current_status_label.setText(status)

    def on_step_completed(self, title: str, message: str) -> None:
        self.history_box.appendPlainText(f"✔ {title} — {message}")

    def on_overall_progress(self, value: int) -> None:
        self.overall_bar.setValue(max(0, min(100, int(value))))

    def on_entropy_progress(self, current: int, total: int, file_name: str, percent: int) -> None:
        if total <= 0:
            self.entropy_status_label.setText("Scanning 0 / 0 files")
            self.entropy_bar.setValue(100)
            return
        self.entropy_status_label.setText(f"Scanning\n{current} / {total} files\n{file_name}")
        self.entropy_bar.setValue(max(0, min(100, int(percent))))

    def on_failed(self, step: str, message: str) -> None:
        self.current_step_label.setText(f"Failed: {step}")
        self.current_status_label.setText(message)
        self.history_box.appendPlainText(f"✖ {step} — {message}")
        self.close_button.setEnabled(True)


class EntropyRebuildDialog(QDialog):
    """Progress dialog shown when entropy root changes at runtime."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Rebuilding Entropy Database")
        self.setMinimumSize(560, 240)
        self.setModal(False)
        self.setWindowModality(Qt.NonModal)

        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)
        self.setLayout(layout)

        title = QLabel("Updating Entropy Database")
        title.setStyleSheet("font-size: 18px; font-weight: bold;")
        layout.addWidget(title)

        self.status_label = QLabel("Starting rebuild...")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        self.progress_label = QLabel("0 / 0 files")
        layout.addWidget(self.progress_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)

        self.close_button = QPushButton("Close")
        self.close_button.setEnabled(False)
        self.close_button.clicked.connect(self.close)
        layout.addWidget(self.close_button, alignment=Qt.AlignRight)

        self.setStyleSheet(
            "QDialog { background: #141a26; color: #f0f0f0; }"
            "QProgressBar { background: #1f2430; border: 1px solid #2d3547; border-radius: 6px; text-align: center; }"
            "QProgressBar::chunk { background: #2d72d9; border-radius: 6px; }"
            "QPushButton { background: #2f3a59; color: #ffffff; font-weight: bold; padding: 8px 16px; border-radius: 6px; }"
            "QPushButton:disabled { background: #4a4f60; color: #b0b0b0; }"
        )

    def on_progress(self, current: int, total: int, file_name: str, percent: int) -> None:
        self.status_label.setText(file_name or "Scanning...")
        self.progress_label.setText(f"{current} / {total} files")
        self.progress_bar.setValue(max(0, min(100, int(percent))))

    def on_finished(self, total: int, processed: int) -> None:
        self.status_label.setText(f"Completed. Processed {processed} / {total} files.")
        self.progress_bar.setValue(100)
        self.close_button.setEnabled(True)

    def on_failed(self, message: str) -> None:
        self.status_label.setText(f"Failed: {message}")
        self.close_button.setEnabled(True)
