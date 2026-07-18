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
  - The entropy module NEVER imports from ransomwaredetector.
  - The GUI callback is injected at construction time, keeping this module
    decoupled from the presentation layer.
"""

from __future__ import annotations

import logging
import os
import queue
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from entropy.calculator import calculate_entropy
from database.metadata_db import MetadataDatabase
from database.logs_db import LogsDatabase
from database.alerts_db import AlertsDatabase

try:
    from config import get_config
    _CONFIG_AVAILABLE = True
except ImportError:
    _CONFIG_AVAILABLE = False

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
    __slots__ = (
        "event_type",
        "file_path",
        "previous_path",
        "file_id",
        "process_name",
        "pid",
        "executable",
        "parent",
    )

    def __init__(
        self,
        event_type: str,
        file_path: str,
        previous_path: Optional[str],
        file_id: Optional[str],
        process_name: Optional[str],
        pid: Optional[int],
        executable: Optional[str],
        parent: Optional[str],
    ) -> None:
        self.event_type = event_type
        self.file_path = file_path
        self.previous_path = previous_path
        self.file_id = file_id
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
        monitored_roots: Optional[Sequence[Path]] = None,
        sample_size_bytes: int = 5 * 1024 * 1024,
        threshold: float = 1.4,
        on_entropy_alert: Optional[Callable[[EntropyIncreaseDetected], None]] = None,
        retention_days: int = 30,
        persist_events_to_logs: bool = False,
    ) -> None:
        self._metadata_db = metadata_db
        self._logs_db = logs_db
        self._alerts_db = alerts_db
        self._allowed_extensions: Set[str] = {e.lower().lstrip(".") for e in allowed_extensions}
        self._monitored_roots = [Path(root).expanduser() for root in (monitored_roots or [])]
        self._sample_size = sample_size_bytes
        self._threshold = threshold
        self._on_entropy_alert = on_entropy_alert
        self._retention_days = retention_days
        self._persist_events_to_logs = persist_events_to_logs

        if _CONFIG_AVAILABLE:
            cfg = get_config()
            self._queue_maxsize = max(500, int(cfg.entropy.queue_maxsize))
            self._worker_count = max(1, int(cfg.entropy.worker_count))
            mcfg = cfg.monitoring
            self._packet_normal_max = int(mcfg.packet_normal_max)
            self._packet_medium_max = int(mcfg.packet_medium_max)
            self._packet_large_max = int(mcfg.packet_large_max)
            self._packet_medium_size = int(mcfg.packet_medium_size)
            self._packet_large_size = int(mcfg.packet_large_size)
            self._packet_extreme_size = int(mcfg.packet_extreme_size)
        else:
            self._queue_maxsize = 4000
            self._worker_count = 3
            self._packet_normal_max = 50
            self._packet_medium_max = 200
            self._packet_large_max = 1000
            self._packet_medium_size = 20
            self._packet_large_size = 50
            self._packet_extreme_size = 100

        self._queue: "queue.PriorityQueue[Tuple[int, float, int, _FileEvent]]" = queue.PriorityQueue(
            maxsize=self._queue_maxsize
        )
        self._worker_thread: Optional[threading.Thread] = None
        self._baseline_thread: Optional[threading.Thread] = None
        self._db_writer_thread: Optional[threading.Thread] = None
        self._running = False
        self._sequence = 0
        self._queue_lock = threading.Lock()
        self._modified_event_index: Dict[str, _FileEvent] = {}
        self._inflight_paths: Set[str] = set()
        self._inflight_lock = threading.Lock()
        self._metadata_update_lock = threading.Lock()
        self._pending_metadata_updates: Dict[str, Tuple[float, str, Optional[float], int, float, Optional[str]]] = {}
        self._worker_pool: Optional[ThreadPoolExecutor] = None

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
        self._worker_pool = ThreadPoolExecutor(
            max_workers=self._worker_count,
            thread_name_prefix="rdrs-entropy-calc",
        )
        self._worker_thread.start()
        self._db_writer_thread = threading.Thread(
            target=self._metadata_writer_loop,
            name="rdrs-entropy-db-writer",
            daemon=True,
        )
        self._db_writer_thread.start()
        if self._monitored_roots:
            self._baseline_thread = threading.Thread(
                target=self._baseline_scan,
                name="rdrs-entropy-baseline",
                daemon=True,
            )
            self._baseline_thread.start()
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
            self._queue.put_nowait((99, time.time(), 0, _FileEvent("STOP", "", None, None, None, None, None, None)))
        except queue.Full:
            pass
        if self._worker_thread is not None:
            self._worker_thread.join(timeout=5.0)
        if self._baseline_thread is not None:
            self._baseline_thread.join(timeout=5.0)
        if self._db_writer_thread is not None:
            self._db_writer_thread.join(timeout=5.0)
        if self._worker_pool is not None:
            self._worker_pool.shutdown(wait=True)
            self._worker_pool = None
        self._flush_pending_metadata_updates()
        logger.info("EntropyMonitor stopped.")

    # ------------------------------------------------------------------
    # Public event ingestion (called from the file monitor thread)
    # ------------------------------------------------------------------

    def on_file_event(
        self,
        event_type: str,
        file_path: str,
        *,
        previous_path: Optional[str] = None,
        file_identifier: Optional[str] = None,
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
            logger.debug(
                "[ENTROPY_TRACE][ENTROPY.on_file_event] monitor_not_running event=%s file=%s",
                event_type,
                file_path,
            )
            return

        evt = _FileEvent(
            event_type=event_type,
            file_path=file_path,
            previous_path=previous_path,
            file_id=file_identifier,
            process_name=process_name,
            pid=pid,
            executable=executable,
            parent=parent,
        )
        try:
            self._enqueue_event(evt)
            logger.debug(
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

    @staticmethod
    def _event_priority(event_type: str) -> int:
        event = (event_type or "").upper()
        if event in {"ENTROPY_RESCAN", "HIGH_SCORE_RESCAN"}:
            return 0
        if "MOVE" in event or "RENAME" in event or "DELETE" in event:
            return 0
        if "MODIF" in event or "CREAT" in event:
            return 1
        return 2

    def _enqueue_event(self, evt: _FileEvent) -> None:
        event_type_upper = (evt.event_type or "").upper()
        normalized_path = str(Path(evt.file_path))
        is_modified = "MODIF" in event_type_upper

        with self._queue_lock:
            if is_modified and normalized_path in self._modified_event_index:
                existing = self._modified_event_index[normalized_path]
                existing.process_name = evt.process_name or existing.process_name
                existing.pid = evt.pid if evt.pid is not None else existing.pid
                existing.executable = evt.executable or existing.executable
                existing.parent = evt.parent or existing.parent
                existing.file_id = evt.file_id or existing.file_id
                return

            self._sequence += 1
            item = (self._event_priority(evt.event_type), time.time(), self._sequence, evt)
            try:
                self._queue.put_nowait(item)
                if is_modified:
                    self._modified_event_index[normalized_path] = evt
            except queue.Full:
                if is_modified:
                    return
                self._force_enqueue_critical(item)

    def _force_enqueue_critical(self, critical_item: Tuple[int, float, int, _FileEvent]) -> None:
        drained: List[Tuple[int, float, int, _FileEvent]] = []
        dropped = False
        while True:
            try:
                item = self._queue.get_nowait()
            except queue.Empty:
                break
            _, _, _, evt = item
            if not dropped and "MODIF" in (evt.event_type or "").upper():
                dropped = True
                self._modified_event_index.pop(str(Path(evt.file_path)), None)
                continue
            drained.append(item)
        try:
            self._queue.put_nowait(critical_item)
        except queue.Full:
            pass
        for item in drained:
            try:
                self._queue.put_nowait(item)
            except queue.Full:
                break

    def _baseline_scan(self) -> None:
        """Prime the entropy cache for all monitored roots without blocking the UI."""
        for root in self._monitored_roots:
            if not self._running:
                return
            if not root.exists():
                continue
            if root.is_file():
                self._scan_file_for_cache(root)
                continue
            for path in root.rglob("*"):
                if not self._running:
                    return
                if not path.is_file():
                    continue
                self._scan_file_for_cache(path)

    def _scan_file_for_cache(self, path: Path) -> None:
        """Populate persistent cache rows for a single file if it should be tracked."""
        if path.suffix.lower().lstrip(".") not in self._allowed_extensions:
            return
        try:
            stat = path.stat()
        except OSError:
            return

        existing_cache = self._metadata_db.get_entropy_record(str(path))
        existing_legacy = self._metadata_db.get_file(str(path))
        entropy = None
        if (
            existing_cache is not None
            and existing_cache["exists"] == 1
            and existing_cache["file_size"] == stat.st_size
            and existing_cache["modified_time"] == stat.st_mtime
            and existing_cache["entropy"] is not None
        ):
            entropy = existing_cache["entropy"]
        else:
            entropy = calculate_entropy(path, self._sample_size)

        if entropy is None:
            return

        self._metadata_db.upsert_entropy_cache(
            path=str(path),
            entropy=entropy,
            file_size=stat.st_size,
            modified_time=stat.st_mtime,
            exists=True,
        )
        file_id = self._build_file_identity(path, stat)
        if file_id:
            self._metadata_db.upsert_entropy_identity(file_id, str(path), exists=True)
        previous_entropy = existing_legacy["current_entropy"] if existing_legacy else None
        self._metadata_db.upsert_file(
            file_path=str(path),
            file_name=path.name,
            current_entropy=entropy,
            previous_entropy=previous_entropy,
            file_size=stat.st_size,
            last_modified_ts=stat.st_mtime,
        )

    # ------------------------------------------------------------------
    # Worker loop (background thread)
    # ------------------------------------------------------------------

    def _worker_loop(self) -> None:
        """Process events from the queue until stopped."""
        while True:
            packet = self._drain_packet(self._adaptive_packet_size())
            if not packet:
                if not self._running and self._queue.empty():
                    break
                time.sleep(0.02)
                continue

            futures = []
            for evt in packet:
                if evt.event_type == "STOP":
                    self._running = False
                    continue
                if self._worker_pool is None:
                    continue
                futures.append(self._worker_pool.submit(self._process_event, evt))

            if futures:
                wait(futures)

    def _adaptive_packet_size(self) -> int:
        qsize = self._queue.qsize()
        if qsize < self._packet_normal_max:
            return 1
        if qsize < self._packet_medium_max:
            return self._packet_medium_size
        if qsize < self._packet_large_max:
            return self._packet_large_size
        return self._packet_extreme_size

    def _drain_packet(self, packet_size: int) -> List[_FileEvent]:
        packet: List[_FileEvent] = []
        while len(packet) < packet_size:
            try:
                _, _, _, evt = self._queue.get_nowait()
            except queue.Empty:
                break
            if "MODIF" in (evt.event_type or "").upper():
                with self._queue_lock:
                    self._modified_event_index.pop(str(Path(evt.file_path)), None)
            packet.append(evt)
        return packet

    def _process_event(self, evt: _FileEvent) -> None:
        """Handle a single file event: entropy check, DB update, alert check.

        Args:
            evt: The file event to process.
        """
        file_path = evt.file_path
        path = Path(file_path)
        resolved_path = str(path.resolve()) if path.exists() else str(path)
        logger.debug(
            "[ENTROPY_TRACE][ENTROPY.worker] processing event=%s file=%s suffix=%s",
            evt.event_type,
            file_path,
            path.suffix,
        )

        # -----------------------------------------------------------------
        # 1. Handle move/rename and deletion events before extension filtering.
        # -----------------------------------------------------------------
        event_type_upper = evt.event_type.upper()
        if "MOVE" in event_type_upper or "RENAME" in event_type_upper:
            if evt.previous_path:
                try:
                    self._metadata_db.rename_entropy_path(evt.previous_path, file_path)
                except Exception as exc:
                    logger.warning("Failed to rename entropy cache %s -> %s: %s", evt.previous_path, file_path, exc)
                try:
                    self._metadata_db.mark_deleted(evt.previous_path)
                except Exception:
                    pass

                if evt.file_id:
                    try:
                        self._metadata_db.upsert_entropy_identity(evt.file_id, file_path, exists=True)
                    except Exception as exc:
                        logger.debug("Failed to update identity map for move %s: %s", evt.file_id, exc)

            # Continue processing destination path so extension changes remain tracked.

        if "DELETE" in event_type_upper:
            try:
                self._metadata_db.mark_deleted(file_path)
                logger.debug(
                    "[ENTROPY_TRACE][ENTROPY.worker] mark_deleted_ok file=%s",
                    file_path,
                )
            except Exception as exc:
                logger.warning("Failed to mark deleted: %s — %s", file_path, exc)
            if evt.file_id:
                try:
                    self._metadata_db.mark_entropy_identity_deleted(evt.file_id)
                except Exception as exc:
                    logger.debug("Failed to mark identity deleted for %s: %s", evt.file_id, exc)
            if self._persist_events_to_logs:
                self._log_event(evt)
            return

        # -----------------------------------------------------------------
        # 2. Resolve filesystem stat and stable identity.
        # -----------------------------------------------------------------
        try:
            stat = path.stat()
        except OSError:
            logger.warning(
                "[ENTROPY_TRACE][ENTROPY.worker] stat_failed file=%s (likely transient)",
                file_path,
            )
            return

        resolved_path = self._normalize_runtime_path(path)
        file_id = evt.file_id or self._build_file_identity(path, stat)

        if file_id:
            try:
                mapped_path = self._metadata_db.resolve_entropy_path(file_id)
            except Exception:
                mapped_path = None

            if mapped_path and mapped_path != resolved_path:
                try:
                    self._metadata_db.rename_entropy_path(mapped_path, resolved_path)
                except Exception as exc:
                    logger.debug(
                        "Identity remap failed for file_id=%s (%s -> %s): %s",
                        file_id,
                        mapped_path,
                        resolved_path,
                        exc,
                    )

            try:
                self._metadata_db.upsert_entropy_identity(file_id, resolved_path, exists=True)
            except Exception as exc:
                logger.debug("Failed to persist identity map for %s: %s", resolved_path, exc)

        existing_cache = self._metadata_db.get_entropy_record(resolved_path)
        tracked_by_history = bool(existing_cache and existing_cache["exists"] == 1)

        # -----------------------------------------------------------------
        # 3. Extension filter (allow already-tracked files after rename).
        # -----------------------------------------------------------------
        extension = path.suffix.lower().lstrip(".")
        if extension not in self._allowed_extensions and not tracked_by_history:
            logger.debug(
                "Filtered extension=%s file=%s",
                extension,
                file_path,
            )
            return

        file_size = stat.st_size
        last_modified = stat.st_mtime

        with self._inflight_lock:
            if resolved_path in self._inflight_paths:
                logger.debug("[ENTROPY_TRACE][ENTROPY.worker] duplicate_scan_ignored file=%s", resolved_path)
                return
            self._inflight_paths.add(resolved_path)

        try:
            # -----------------------------------------------------------------
            # 4. Fetch existing record to get previous entropy
            # -----------------------------------------------------------------
            existing = self._metadata_db.get_file(resolved_path)
            previous_entropy: Optional[float] = None
            if existing:
                previous_entropy = existing["current_entropy"]
            elif existing_cache is not None:
                previous_entropy = existing_cache["entropy"]
            logger.debug(
                "[ENTROPY_TRACE][ENTROPY.worker] metadata_lookup existing=%s prev_entropy=%s file=%s",
                existing is not None,
                previous_entropy,
                file_path,
            )

            # -----------------------------------------------------------------
            # 5. Calculate current entropy from the filesystem at scan time.
            # -----------------------------------------------------------------
            current_entropy = calculate_entropy(file_path, self._sample_size)
        finally:
            with self._inflight_lock:
                self._inflight_paths.discard(resolved_path)

        if current_entropy is None:
            # Unreadable file — skip entropy update.
            logger.warning(
                "[ENTROPY_TRACE][ENTROPY.worker] entropy_calc_failed file=%s sample_size=%s",
                file_path,
                self._sample_size,
            )
            return
        logger.debug(
            "[ENTROPY_TRACE][ENTROPY.worker] entropy_calc_ok current=%.5f file=%s",
            current_entropy,
            file_path,
        )

        # -----------------------------------------------------------------
        # 6. Upsert metadata database
        # -----------------------------------------------------------------
        self._queue_metadata_upsert(
            resolved_path=resolved_path,
            file_name=path.name,
            current_entropy=current_entropy,
            previous_entropy=previous_entropy,
            file_size=file_size,
            last_modified=last_modified,
            file_id=file_id,
        )
        logger.debug(
            "[ENTROPY_TRACE][ENTROPY.worker] metadata_upsert_ok file=%s prev=%s current=%.5f",
            file_path,
            previous_entropy,
            current_entropy,
        )

        # -----------------------------------------------------------------
        # 7. Alert check — only on modifications (not initial creation scans)
        # -----------------------------------------------------------------
        if (
            ("MODIF" in event_type_upper or "RESCAN" in event_type_upper)
            and previous_entropy is not None
            and current_entropy is not None
        ):
            delta = current_entropy - previous_entropy
            logger.debug(
                "[ENTROPY_TRACE][ENTROPY.recalculated] file=%s prev=%.5f current=%.5f delta=%.5f",
                resolved_path,
                previous_entropy,
                current_entropy,
                delta,
            )
            if delta >= self._threshold:
                self._trigger_alert(evt, previous_entropy, current_entropy, delta)

        if self._persist_events_to_logs:
            self._log_event(evt)

    def _queue_metadata_upsert(
        self,
        *,
        resolved_path: str,
        file_name: str,
        current_entropy: float,
        previous_entropy: Optional[float],
        file_size: int,
        last_modified: float,
        file_id: Optional[str],
    ) -> None:
        """Coalesce metadata updates by file path for periodic batch flushes."""
        with self._metadata_update_lock:
            self._pending_metadata_updates[resolved_path] = (
                current_entropy,
                file_name,
                previous_entropy,
                file_size,
                last_modified,
                file_id,
            )

    def _metadata_writer_loop(self) -> None:
        """Flush coalesced metadata updates in short periodic batches."""
        while self._running or self._pending_metadata_updates:
            self._flush_pending_metadata_updates()
            time.sleep(0.2)

    def _flush_pending_metadata_updates(self) -> None:
        with self._metadata_update_lock:
            if not self._pending_metadata_updates:
                return
            batch = list(self._pending_metadata_updates.items())
            self._pending_metadata_updates.clear()

        for resolved_path, payload in batch:
            current_entropy, file_name, previous_entropy, file_size, last_modified, file_id = payload
            self._metadata_db.upsert_entropy_cache(
                path=resolved_path,
                entropy=current_entropy,
                file_size=file_size,
                modified_time=last_modified,
                exists=True,
            )
            self._metadata_db.upsert_file(
                file_path=resolved_path,
                file_name=file_name,
                current_entropy=current_entropy,
                previous_entropy=previous_entropy,
                file_size=file_size,
                last_modified_ts=last_modified,
            )
            if file_id:
                self._metadata_db.upsert_entropy_identity(file_id, resolved_path, exists=True)

    @staticmethod
    def _normalize_runtime_path(path: Path) -> str:
        try:
            return os.path.realpath(os.path.abspath(str(path)))
        except Exception:
            return str(path)

    @staticmethod
    def _build_file_identity(path: Path, stat_result: os.stat_result) -> Optional[str]:
        """Return a stable identity for rename/extension-churn resilience."""
        try:
            inode = int(getattr(stat_result, "st_ino", 0) or 0)
            device = int(getattr(stat_result, "st_dev", 0) or 0)
            if inode > 0:
                return f"{device}:{inode}"
        except Exception:
            pass

        try:
            return f"path:{os.path.normcase(os.path.realpath(str(path)))}"
        except Exception:
            return None

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

    def queue_rescan_for_paths(self, paths: Sequence[Path]) -> None:
        """Queue a filesystem-based entropy rescan for the provided files."""
        for path in paths:
            if not path.exists() or not path.is_file():
                continue
            self.on_file_event("ENTROPY_RESCAN", str(path))

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
