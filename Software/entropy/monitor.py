"""Event-driven Shannon Entropy Monitor for RDRS.

Architecture
------------
The monitor does NOT scan the filesystem on its own.  Instead it receives
file-modification events from the File Monitor (via a queue) and processes
them asynchronously on a dedicated worker thread.

Event flow::

    FileSystemMonitorHandler._report_event()
            │  (non-blocking queue.put_nowait)
            ▼
    EntropyMonitor._queue            (thread-safe queue.Queue)
            │
            ▼
    EntropyMonitor._worker_loop()    (background thread)
            │
            ├─ check file extension against config.yaml allow-list
            ├─ calculate current entropy (calculator.py, first 5 MB)
            ├─ fetch previous entropy from metadata.db
            ├─ upsert metadata.db with current values
            ├─ log event to logs.db
            └─ if delta > threshold → call on_entropy_alert callback
                                       (the Engine handles scoring)

Isolation guarantees
--------------------
  - The entropy module NEVER modifies process scores.
  - The entropy module NEVER imports from basic_gui.
  - The GUI callback is injected at construction time, keeping this module
    decoupled from the presentation layer.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, Set

from entropy.calculator import calculate_entropy
from database.metadata_db import MetadataDatabase
from database.logs_db import LogsDatabase
from database.alerts_db import AlertsDatabase

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class EntropyIncreaseDetected:
    """Event object emitted when entropy increases beyond the threshold.

    This object is passed to the on_entropy_alert callback.  The Engine
    (or the GUI on behalf of the engine) is solely responsible for deciding
    what score delta to apply.

    Attributes:
        file_path:        Absolute path to the affected file.
        process_name:     Resolved process name (may be None if unknown).
        previous_entropy: Entropy before this modification event.
        current_entropy:  Entropy after this modification event.
        delta:            current_entropy - previous_entropy.
    """
    file_path: str
    process_name: Optional[str]
    previous_entropy: float
    current_entropy: float
    delta: float


class _FileEvent:
    """Internal event payload placed on the worker queue."""
    __slots__ = ("event_type", "file_path", "process_name", "pid", "executable", "parent")

    def __init__(
        self,
        event_type: str,
        file_path: str,
        process_name: Optional[str],
        pid: Optional[int],
        executable: Optional[str],
        parent: Optional[str],
    ) -> None:
        self.event_type = event_type
        self.file_path = file_path
        self.process_name = process_name
        self.pid = pid
        self.executable = executable
        self.parent = parent


class EntropyMonitor:
    """Asynchronous entropy monitor driven by filesystem events.

    Parameters
    ----------
    metadata_db:
        MetadataDatabase instance (one per application; caller owns it).
    logs_db:
        LogsDatabase instance.
    alerts_db:
        AlertsDatabase instance.
    allowed_extensions:
        Set of lowercase extensions (without leading dot) to process.
        Files with other extensions are silently ignored.
    sample_size_bytes:
        How many bytes to read for the entropy calculation.
    threshold:
        Minimum entropy increase (bits) to treat as suspicious.
    on_entropy_alert:
        Optional callback invoked on the worker thread when an
        ``EntropyIncreaseDetected`` event is generated.  The signature is
        ``callback(event: EntropyIncreaseDetected) -> None``.
        Keep the callback fast; heavy work should be dispatched to the GUI
        thread via Qt signals.
    retention_days:
        Deleted-file records older than this are purged on startup.
    """

    def __init__(
        self,
        *,
        metadata_db: MetadataDatabase,
        logs_db: LogsDatabase,
        alerts_db: AlertsDatabase,
        allowed_extensions: Set[str],
        sample_size_bytes: int = 5 * 1024 * 1024,
        threshold: float = 1.4,
        on_entropy_alert: Optional[Callable[[EntropyIncreaseDetected], None]] = None,
        retention_days: int = 30,
    ) -> None:
        self._metadata_db = metadata_db
        self._logs_db = logs_db
        self._alerts_db = alerts_db
        self._allowed_extensions: Set[str] = {e.lower().lstrip(".") for e in allowed_extensions}
        self._sample_size = sample_size_bytes
        self._threshold = threshold
        self._on_entropy_alert = on_entropy_alert
        self._retention_days = retention_days

        self._queue: queue.Queue[Optional[_FileEvent]] = queue.Queue(maxsize=2000)
        self._worker_thread: Optional[threading.Thread] = None
        self._running = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background worker thread."""
        if self._running:
            return
        self._running = True
        self._worker_thread = threading.Thread(
            target=self._worker_loop,
            name="rdrs-entropy-worker",
            daemon=True,
        )
        self._worker_thread.start()
        logger.info("EntropyMonitor started (threshold=%.2f bits, extensions=%s)",
                    self._threshold, sorted(self._allowed_extensions))
        # Run a cleanup pass for old deleted records.
        threading.Thread(
            target=self._cleanup_deleted_records,
            daemon=True,
            name="rdrs-entropy-cleanup",
        ).start()

    def stop(self) -> None:
        """Signal the worker to stop and wait for it to finish."""
        self._running = False
        # Unblock the worker thread with a sentinel None.
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass
        if self._worker_thread is not None:
            self._worker_thread.join(timeout=5.0)
        logger.info("EntropyMonitor stopped.")

    # ------------------------------------------------------------------
    # Public event ingestion (called from the file monitor thread)
    # ------------------------------------------------------------------

    def on_file_event(
        self,
        event_type: str,
        file_path: str,
        *,
        process_name: Optional[str] = None,
        pid: Optional[int] = None,
        executable: Optional[str] = None,
        parent: Optional[str] = None,
    ) -> None:
        """Receive a filesystem event from the file monitor.

        This method is called on the watchdog observer thread.  It only
        performs a non-blocking queue.put_nowait(); all I/O happens on the
        worker thread.

        Args:
            event_type:   FILE CREATED | FILE MODIFIED | FILE DELETED | FILE RENAMED.
            file_path:    Absolute path to the file.
            process_name: Process name if known.
            pid:          Process ID if known.
            executable:   Executable path if known.
            parent:       Parent process name if known.
        """
        if not self._running:
            logger.warning(
                "[ENTROPY_TRACE][ENTROPY.on_file_event] monitor_not_running event=%s file=%s",
                event_type,
                file_path,
            )
            return

        evt = _FileEvent(
            event_type=event_type,
            file_path=file_path,
            process_name=process_name,
            pid=pid,
            executable=executable,
            parent=parent,
        )
        try:
            self._queue.put_nowait(evt)
            logger.info(
                "[ENTROPY_TRACE][ENTROPY.on_file_event] enqueued event=%s file=%s qsize=%s",
                event_type,
                file_path,
                self._queue.qsize(),
            )
        except queue.Full:
            # Drop the event rather than block the file monitor thread.
            logger.error(
                "[ENTROPY_TRACE][ENTROPY.on_file_event] queue_full drop event=%s file=%s",
                event_type,
                file_path,
            )

    # ------------------------------------------------------------------
    # Worker loop (background thread)
    # ------------------------------------------------------------------

    def _worker_loop(self) -> None:
        """Process events from the queue until stopped."""
        while True:
            try:
                evt = self._queue.get(timeout=1.0)
            except queue.Empty:
                if not self._running:
                    break
                continue

            if evt is None:
                # Sentinel: stop requested.
                break

            try:
                self._process_event(evt)
            except Exception as exc:
                logger.error("EntropyMonitor worker error processing %s: %s",
                             evt.file_path, exc, exc_info=True)
            finally:
                self._queue.task_done()

    def _process_event(self, evt: _FileEvent) -> None:
        """Handle a single file event: entropy check, DB update, alert check.

        Args:
            evt: The file event to process.
        """
        file_path = evt.file_path
        path = Path(file_path)
        logger.info(
            "[ENTROPY_TRACE][ENTROPY.worker] processing event=%s file=%s suffix=%s",
            evt.event_type,
            file_path,
            path.suffix,
        )

        # -----------------------------------------------------------------
        # 1. Extension filter — only process allowed file types
        #
        # Note: filesystem event persistence to logs.db is handled by the
        # monitor callback chain in basic_gui.py so that *all* events are
        # stored, not only entropy-supported extensions.
        # -----------------------------------------------------------------
        extension = path.suffix.lower().lstrip(".")
        if extension not in self._allowed_extensions:
            logger.info(
                "[ENTROPY_TRACE][ENTROPY.worker] filtered_extension extension=%s allowed=%s file=%s",
                extension,
                extension in self._allowed_extensions,
                file_path,
            )
            return
        logger.info(
            "[ENTROPY_TRACE][ENTROPY.worker] extension_ok extension=%s file=%s",
            extension,
            file_path,
        )

        # -----------------------------------------------------------------
        # 2. Handle deletion — mark as deleted, log to events DB
        # -----------------------------------------------------------------
        if "DELETE" in evt.event_type.upper():
            try:
                self._metadata_db.mark_deleted(file_path)
                logger.info(
                    "[ENTROPY_TRACE][ENTROPY.worker] mark_deleted_ok file=%s",
                    file_path,
                )
            except Exception as exc:
                logger.warning("Failed to mark deleted: %s — %s", file_path, exc)
            return

        # -----------------------------------------------------------------
        # 3. Stat the file before reading (fast exit if gone)
        # -----------------------------------------------------------------
        try:
            stat = path.stat()
        except OSError:
            logger.warning(
                "[ENTROPY_TRACE][ENTROPY.worker] stat_failed file=%s (likely transient)",
                file_path,
            )
            return

        file_size = stat.st_size
        last_modified = stat.st_mtime

        # -----------------------------------------------------------------
        # 4. Fetch existing record to get previous entropy
        # -----------------------------------------------------------------
        existing = self._metadata_db.get_file(file_path)
        previous_entropy: Optional[float] = None
        if existing:
            previous_entropy = existing["current_entropy"]
        logger.info(
            "[ENTROPY_TRACE][ENTROPY.worker] metadata_lookup existing=%s prev_entropy=%s file=%s",
            existing is not None,
            previous_entropy,
            file_path,
        )

        # -----------------------------------------------------------------
        # 5. Calculate current entropy
        # -----------------------------------------------------------------
        current_entropy = calculate_entropy(file_path, self._sample_size)
        if current_entropy is None:
            # Unreadable file — skip entropy update.
            logger.warning(
                "[ENTROPY_TRACE][ENTROPY.worker] entropy_calc_failed file=%s sample_size=%s",
                file_path,
                self._sample_size,
            )
            return
        logger.info(
            "[ENTROPY_TRACE][ENTROPY.worker] entropy_calc_ok current=%.5f file=%s",
            current_entropy,
            file_path,
        )

        # -----------------------------------------------------------------
        # 6. Upsert metadata database
        # -----------------------------------------------------------------
        self._metadata_db.upsert_file(
            file_path=file_path,
            file_name=path.name,
            current_entropy=current_entropy,
            previous_entropy=previous_entropy,
            file_size=file_size,
            last_modified_ts=last_modified,
        )
        logger.info(
            "[ENTROPY_TRACE][ENTROPY.worker] metadata_upsert_ok file=%s prev=%s current=%.5f",
            file_path,
            previous_entropy,
            current_entropy,
        )

        # -----------------------------------------------------------------
        # 7. Alert check — only on modifications (not initial creation scans)
        # -----------------------------------------------------------------
        if (
            "MODIF" in evt.event_type.upper()
            and previous_entropy is not None
            and current_entropy is not None
        ):
            delta = current_entropy - previous_entropy
            if delta >= self._threshold:
                self._trigger_alert(evt, previous_entropy, current_entropy, delta)

    def _log_event(self, evt: _FileEvent) -> None:
        """Persist a filesystem event to logs_db.

        Args:
            evt: The event to log.
        """
        try:
            self._logs_db.log_event(
                event_type=evt.event_type,
                file_path=evt.file_path,
                file_name=Path(evt.file_path).name,
                process=evt.process_name,
                pid=evt.pid,
                executable=evt.executable,
                parent=evt.parent,
                timestamp=time.time(),
            )
        except Exception as exc:
            logger.warning("Failed to log event for %s: %s", evt.file_path, exc)

    def _trigger_alert(
        self,
        evt: _FileEvent,
        previous_entropy: float,
        current_entropy: float,
        delta: float,
    ) -> None:
        """Record the alert and call the engine callback.

        Args:
            evt:              The triggering file event.
            previous_entropy: Entropy before the modification.
            current_entropy:  Entropy after the modification.
            delta:            Entropy change.
        """
        logger.warning(
            "ENTROPY ALERT: %s  previous=%.3f  current=%.3f  delta=+%.3f",
            evt.file_path, previous_entropy, current_entropy, delta,
        )

        # Persist to alerts_db.
        try:
            self._alerts_db.log_alert(
                alert_type="ENTROPY_INCREASE",
                process_name=evt.process_name,
                pid=evt.pid,
                executable=evt.executable,
                file_path=evt.file_path,
                previous_entropy=previous_entropy,
                current_entropy=current_entropy,
                entropy_delta=delta,
                notes=f"Entropy increased by {delta:.3f} bits (threshold={self._threshold})",
            )
        except Exception as exc:
            logger.warning("Failed to write alert to DB: %s", exc)

        # Notify the Engine (or GUI bridge).
        if self._on_entropy_alert is not None:
            try:
                alert_event = EntropyIncreaseDetected(
                    file_path=evt.file_path,
                    process_name=evt.process_name,
                    previous_entropy=previous_entropy,
                    current_entropy=current_entropy,
                    delta=delta,
                )
                self._on_entropy_alert(alert_event)
            except Exception as exc:
                logger.error("on_entropy_alert callback failed: %s", exc, exc_info=True)

    def _cleanup_deleted_records(self) -> None:
        """Purge old deleted-file records on a background thread."""
        try:
            removed = self._metadata_db.cleanup_old_deleted(self._retention_days)
            if removed:
                logger.info("EntropyMonitor: purged %d stale deleted-file records.", removed)
        except Exception as exc:
            logger.warning("EntropyMonitor cleanup failed: %s", exc)

    # ------------------------------------------------------------------
    # Utility helpers for the GUI
    # ------------------------------------------------------------------

    def get_monitored_files(self) -> list:
        """Return all existing monitored file records for the GUI.

        Returns:
            List of sqlite3.Row from metadata.db.
        """
        try:
            return self._metadata_db.get_all_existing()
        except Exception:
            return []

    def get_files_in_directory(self, directory: str) -> list:
        """Return monitored files under a given directory prefix.

        Args:
            directory: Directory path string.

        Returns:
            List of sqlite3.Row.
        """
        try:
            return self._metadata_db.get_by_directory(directory)
        except Exception:
            return []
