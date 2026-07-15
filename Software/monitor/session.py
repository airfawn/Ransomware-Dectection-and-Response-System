"""Runtime session helper for running the filesystem monitor in-process.

This module replaces filename-based subprocess launches with an importable,
cross-platform worker that can be used from the GUI or future automation
layers. It keeps the monitor in a background thread and streams structured log
output line-by-line to a caller-provided callback.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Callable, Optional

from monitor.filesystem_monitor import FileSystemMonitor


class _LineRelayHandler(logging.Handler):
    """Logging handler that forwards formatted lines to a callback."""

    def __init__(self, emit_line: Callable[[str], None]) -> None:
        super().__init__()
        self._emit_line = emit_line

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = self.format(record)
            for line in message.splitlines() or [""]:
                self._emit_line(line)
        except Exception:
            self.handleError(record)


class MonitorSession:
    """Run a `FileSystemMonitor` in a background thread.

    The monitor itself still performs its work using watchdog's internal
    threads, but this session keeps startup/shutdown out of the GUI thread and
    avoids launching a separate Python file.
    """

    def __init__(
        self,
        target_path: Path,
        recursive: bool,
        emit_line: Callable[[str], None],
        emit_error: Callable[[str], None],
        emit_started: Optional[Callable[[], None]] = None,
        emit_stopped: Optional[Callable[[], None]] = None,
        event_callback: Optional[Callable] = None,
    ) -> None:
        """Initialise the session.

        Args:
            target_path:    Directory to monitor.
            recursive:      Monitor subdirectories recursively.
            emit_line:      Callback for formatted log lines (GUI thread-safe via Qt signal).
            emit_error:     Callback for error strings.
            emit_started:   Called on the background thread when the monitor starts.
            emit_stopped:   Called on the background thread when the monitor stops.
            event_callback: Optional raw event callback forwarded to
                            :class:`~monitor.filesystem_monitor.FileSystemMonitor`.
                            Signature: ``(event_type, file_path, process_name,
                            pid, executable, parent) -> None``.
                            Must be non-blocking.  Pass ``EntropyMonitor.on_file_event``
                            here to wire entropy analysis.
        """
        self._target_path = target_path
        self._recursive = recursive
        self._emit_line = emit_line
        self._emit_error = emit_error
        self._emit_started = emit_started
        self._emit_stopped = emit_stopped
        self._event_callback = event_callback

        self._thread: Optional[threading.Thread] = None
        self._monitor: Optional[FileSystemMonitor] = None
        self._stop_lock = threading.Lock()

    @property
    def is_running(self) -> bool:
        """Return whether the session thread is still active."""
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> bool:
        """Start the monitor session.

        Returns:
            `True` when the session was started, `False` when it was already
            running or the target path is invalid.
        """
        if self.is_running:
            return False

        if not self._target_path.exists():
            self._emit_error(f"Monitor path does not exist: {self._target_path}")
            return False

        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return True

    def stop(self) -> None:
        """Stop the monitor session without blocking the GUI unnecessarily."""
        with self._stop_lock:
            monitor = self._monitor

        if monitor is not None:
            try:
                monitor.stop()
            except Exception as exc:
                self._emit_error(f"Failed to stop monitor: {exc}")

        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=2.0)

    def _run(self) -> None:
        """Execute the monitor session in a background thread."""
        logger = logging.getLogger(f"rdrs.monitor.session.{id(self)}")
        logger.handlers.clear()
        logger.setLevel(logging.INFO)
        logger.propagate = False

        relay_handler = _LineRelayHandler(self._emit_line)
        relay_handler.setLevel(logging.INFO)
        relay_handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s %(levelname)s %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        logger.addHandler(relay_handler)

        try:
            monitor = FileSystemMonitor(
                target_path=self._target_path,
                recursive=self._recursive,
                logger=logger,
                event_callback=self._event_callback,
            )
            with self._stop_lock:
                self._monitor = monitor

            if self._emit_started is not None:
                self._emit_started()

            monitor.start()
            monitor.join()
        except Exception as exc:
            self._emit_error(f"Failed to run monitor: {exc}")
        finally:
            with self._stop_lock:
                self._monitor = None
            if self._emit_stopped is not None:
                self._emit_stopped()
