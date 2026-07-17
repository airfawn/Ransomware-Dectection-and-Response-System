"""Coordinator for stage-2 startup initialization and dashboard launch."""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Optional

from PyQt5.QtCore import QObject, QThread, QTimer

from startup_worker import StartupWorker
from splash_screen import InitializationSplashScreen


class InitializationManager(QObject):
    """Owns splash screen + worker thread and launches the main dashboard."""

    def __init__(self, *, gui_factory: Callable[[], object]) -> None:
        super().__init__()
        self._gui_factory = gui_factory
        self._thread: Optional[QThread] = None
        self._worker: Optional[StartupWorker] = None
        self._splash: Optional[InitializationSplashScreen] = None
        self._main_window = None

    @property
    def main_window(self):
        return self._main_window

    def start(self, *, entropy_dir: str, file_monitor_dir: str) -> None:
        """Start threaded initialization and show splash screen."""
        self._splash = InitializationSplashScreen()
        self._splash.show()

        self._thread = QThread()
        self._worker = StartupWorker(
            entropy_dir=Path(entropy_dir),
            file_monitor_dir=Path(file_monitor_dir),
        )
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.run)

        self._worker.step_started.connect(self._splash.on_step_started)
        self._worker.step_completed.connect(self._splash.on_step_completed)
        self._worker.overall_progress.connect(self._splash.on_overall_progress)
        self._worker.entropy_progress.connect(self._splash.on_entropy_progress)
        self._worker.failed.connect(self._on_failed)
        self._worker.succeeded.connect(self._on_succeeded)
        self._worker.finished.connect(self._thread.quit)

        self._thread.finished.connect(self._thread.deleteLater)
        self._thread.finished.connect(self._on_thread_finished)
        self._thread.start()

    def _on_failed(self, step: str, message: str) -> None:
        if self._splash is not None:
            self._splash.on_failed(step, message)

    def _on_succeeded(self, payload: dict) -> None:
        """Launch the existing dashboard only after startup succeeds."""
        self._main_window = self._gui_factory()

        entropy_dir = payload.get("entropy_dir", "")
        file_monitor_dir = payload.get("file_monitor_dir", "")
        if hasattr(self._main_window, "path_input"):
            self._main_window.path_input.setText(file_monitor_dir)
        if hasattr(self._main_window, "entropy_dir_input"):
            self._main_window.entropy_dir_input.setText(entropy_dir)

        if hasattr(self._main_window, "status_label"):
            logs_loaded = payload.get("logs_loaded", 0)
            self._main_window.status_label.setText(
                f"Ready. Startup loaded {logs_loaded} log entries."
            )

        self._main_window.show()
        if hasattr(self._main_window, "raise_"):
            self._main_window.raise_()
        if hasattr(self._main_window, "activateWindow"):
            self._main_window.activateWindow()

        if self._splash is not None:
            splash = self._splash
            self._splash = None

            def _close_splash() -> None:
                splash.close()
                splash.deleteLater()

            QTimer.singleShot(0, _close_splash)

    def _on_thread_finished(self) -> None:
        """Release worker/thread references after initialization completes."""
        if self._worker is not None:
            self._worker.deleteLater()
        self._worker = None
        self._thread = None
