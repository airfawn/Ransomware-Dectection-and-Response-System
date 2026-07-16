"""Filesystem monitor module for RDRS.

This module provides a class that watches a target directory for file creation,
deletion, and modification events and enriches them with process metadata and
behavioral analysis.

Key responsibilities:
- Monitor filesystem events with minimal latency
- Resolve process information for each event
- Track behavioral patterns and apply scoring rules
- Maintain memory-efficient event history
- Support extensible detection rules
- Automatically clean up stale processes

Thread Safety:
- ProcessBehaviorTracker uses a threading lock for all state mutations
- ProcessResolver cache uses a separate lock
- Safe for concurrent access from multiple threads
"""

import logging
import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Deque, Dict, List, Optional, Set, Tuple

import psutil
from watchdog.events import (
    FileSystemEventHandler,
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
)
from watchdog.observers import Observer

try:
    from config import get_config
    from detection_engine import DetectionOrchestrator, FileActivityEngine, ProcessContext
    _CONFIG_AVAILABLE = True
except ImportError:
    _CONFIG_AVAILABLE = False


@dataclass(frozen=True)
class ProcessMetadata:
    """Process metadata captured for an event."""

    pid: Optional[int]
    name: Optional[str]
    executable: Optional[str]
    parent_name: Optional[str]
    start_time: Optional[str]
    start_time_epoch: Optional[float] = None


class ProcessResolver:
    """Resolve process metadata for filesystem events with caching.
    
    The filesystem event itself does not carry a PID, so this class performs a
    best-effort lookup using psutil open file handles. Results are cached to
    avoid re-scanning process lists repeatedly.
    
    Thread Safety:
        All cache operations are protected by a threading lock.
    
    Attributes:
        _cache: LRU-style cache mapping normalized paths to ProcessMetadata.
        _max_cache_size: Maximum number of cached entries.
        _lock: Threading lock for cache access.
    """

    def __init__(self, max_cache_size: int = 1024):
        """Initialize the ProcessResolver with optional caching.
        
        Args:
            max_cache_size: Maximum number of path-to-process mappings to cache.
        """
        self._cache: Dict[str, ProcessMetadata] = {}
        self._directory_cache: Dict[str, ProcessMetadata] = {}
        self._max_cache_size = max_cache_size
        self._lock = threading.Lock()

    def resolve(
        self,
        path: Path,
        *,
        previous_path: Optional[Path] = None,
        event_type: Optional[str] = None,
    ) -> ProcessMetadata:
        """Return process metadata matching an open file handle for the path.
        
        Uses a simple cache to avoid repeated scans of the same file. If the file
        is not found in cache, performs a process scan and caches the result.
        
        Thread Safety:
            This method is thread-safe and can be called concurrently.
        
        Args:
            path: The filesystem path to resolve.
            previous_path: Optional original path for moved/renamed/deleted files.
            event_type: Optional event type hint used for Windows-specific fallbacks.
            
        Returns:
            ProcessMetadata with process information or None values if unknown.
        """
        normalized_target = self._normalize_path(path)
        normalized_previous = self._normalize_path(previous_path) if previous_path is not None else None
        directory_target = self._normalize_path(path.parent)
        
        # Check cache first (thread-safe)
        with self._lock:
            if normalized_target in self._cache:
                return self._cache[normalized_target]
            if normalized_previous and normalized_previous in self._cache:
                return self._cache[normalized_previous]
            if directory_target in self._directory_cache:
                return self._directory_cache[directory_target]
            if normalized_previous is not None:
                previous_directory = self._normalize_path(Path(previous_path).parent)
                if previous_directory in self._directory_cache:
                    return self._directory_cache[previous_directory]
        
        # Resolve without holding lock
        result = self._resolve_uncached(path, normalized_target, normalized_previous, event_type)
        
        # Update cache (thread-safe)
        with self._lock:
            if len(self._cache) >= self._max_cache_size:
                # Simple eviction: clear oldest half
                items = list(self._cache.items())
                self._cache = dict(items[len(items) // 2:])
            self._cache[normalized_target] = result
            self._directory_cache[directory_target] = result
            if normalized_previous is not None:
                self._cache[normalized_previous] = result
                self._directory_cache[self._normalize_path(Path(previous_path).parent)] = result
        
        return result

    def remember(self, path: Path, metadata: ProcessMetadata) -> None:
        """Record a successful mapping for exact-path and directory reuse."""
        normalized_target = self._normalize_path(path)
        directory_target = self._normalize_path(path.parent)
        with self._lock:
            self._cache[normalized_target] = metadata
            self._directory_cache[directory_target] = metadata

    def _resolve_uncached(
        self,
        path: Path,
        normalized_target: str,
        normalized_previous: Optional[str],
        event_type: Optional[str],
    ) -> ProcessMetadata:
        """Perform uncached process resolution by scanning process handles.
        
        Args:
            path: The filesystem path.
            normalized_target: Pre-normalized path string.
            
        Returns:
            ProcessMetadata or unknown metadata if process not found.
        """
        event_type_upper = (event_type or "").upper()

        # Deleted files are often already gone from open handle tables on Windows,
        # so a full scan adds latency and causes event backlog under heavy writes.
        if event_type_upper == "FILE DELETED":
            return ProcessMetadata(pid=None, name=None, executable=None, parent_name=None, start_time=None)

        # Keep process-resolution latency bounded so the watchdog queue remains healthy.
        deadline = time.perf_counter() + 0.35

        try:
            if os.name == "nt" and event_type_upper in {"FILE CREATED", "FILE MODIFIED", "FILE MOVED"}:
                parent_norm = self._normalize_path(path.parent)
                for process in psutil.process_iter(["pid", "name", "exe", "ppid"]):
                    if time.perf_counter() > deadline:
                        break
                    try:
                        cwd = process.cwd()
                        if cwd and self._normalize_path(Path(cwd)) == parent_norm:
                            return self._extract_process_metadata(process)
                    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                        continue
                    except Exception as exc:
                        logging.debug("Unexpected error checking process cwd: %s", exc)

            # Open-file scans are expensive, so only attempt them for modify events
            # and while within a strict time budget.
            if event_type_upper == "FILE MODIFIED":
                for process in psutil.process_iter(["pid", "name", "exe", "ppid"]):
                    if time.perf_counter() > deadline:
                        break
                    try:
                        for open_file in process.open_files():
                            open_norm = self._normalize_path(Path(open_file.path))
                            if open_norm == normalized_target or (
                                normalized_previous is not None and open_norm == normalized_previous
                            ):
                                return self._extract_process_metadata(process)
                    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                        continue
                    except Exception as exc:
                        logging.debug("Unexpected error checking process handles: %s", exc)
                        continue
        except Exception as exc:
            logging.debug("Error iterating processes: %s", exc)
        
        # No process owns the file
        return ProcessMetadata(pid=None, name=None, executable=None, parent_name=None, start_time=None)

    def _extract_process_metadata(self, process: psutil.Process) -> ProcessMetadata:
        """Extract metadata from a psutil Process object.
        
        Args:
            process: The psutil Process object.
            
        Returns:
            ProcessMetadata with safely extracted values.
        """
        try:
            name = process.name()
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            name = None
        
        try:
            executable = process.exe()
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            executable = None
        
        try:
            parent = process.parent()
            parent_name = parent.name() if parent else None
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            parent_name = None
        
        start_time_epoch = self._get_start_time_epoch(process)
        start_time = (
            datetime.fromtimestamp(start_time_epoch).strftime("%Y-%m-%d %H:%M:%S")
            if start_time_epoch is not None
            else None
        )
        
        return ProcessMetadata(
            pid=process.pid,
            name=name,
            executable=executable,
            parent_name=parent_name,
            start_time=start_time,
            start_time_epoch=start_time_epoch,
        )

    @staticmethod
    def _get_start_time_epoch(process: psutil.Process) -> Optional[float]:
        """Return the process creation timestamp if available.
        
        Args:
            process: The psutil Process object.
            
        Returns:
            Epoch timestamp or None if unavailable.
        """
        try:
            return process.create_time()
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            return None

    @staticmethod
    def _normalize_path(path: Path) -> str:
        """Normalize filesystem paths for comparison.
        
        Args:
            path: The path to normalize.
            
        Returns:
            Normalized path string suitable for comparison.
        """
        try:
            normalized = os.path.normcase(str(path.resolve()))
        except Exception:
            normalized = os.path.normcase(str(path.absolute()))
        return normalized


@dataclass(frozen=True)
class ProcessIdentity:
    """Unique identifier used to track process behaviour."""

    pid: Optional[int]
    executable: Optional[str]

    def __str__(self) -> str:
        if self.pid is None and not self.executable:
            return "unknown"
        executable = self.executable or "unknown"
        pid = str(self.pid) if self.pid is not None else "unknown"
        return f"{executable}:{pid}"


@dataclass
class ProcessState:
    """Represents a single process and its current behavioral state.
    
    This class maintains a rolling history of file operations performed by a process,
    applies detection rules, and computes behavioral scores. Event history is
    automatically limited to prevent unbounded memory growth.
    
    Thread Safety:
        Individual ProcessState instances are not thread-safe. The containing
        ProcessBehaviorTracker handles synchronization.
    
    Attributes:
        process_name: Name of the process.
        pid: Process ID.
        executable: Full path to the executable.
        parent_name: Parent process name.
        process_start_time: Human-readable process start time.
        process_start_time_epoch: Epoch timestamp of process start.
        first_activity: Timestamp of first recorded activity.
        last_activity: Timestamp of most recent activity.
        created: Count of file creation events.
        modified: Count of file modification events.
        deleted: Count of file deletion events.
        total_events: Total count of all events.
        unique_directories: Set of directories touched.
        unique_files_touched: Set of unique file paths.
        recent_events: Bounded deque of (timestamp, event_type, directory, file_path).
        active_rules: Set of currently active detection rules.
        max_event_history: Maximum number of events to retain per process.
        event_window_seconds: Time window for calculating rates.
        entropy_score: Future: file entropy analysis score.
        extension_change_count: Future: count of extension changes.
        rename_count: Future: count of file renames.
        bytes_written: Future: total bytes written.
        encryption_indicators: Future: encryption detection metadata.
    """

    process_name: Optional[str]
    pid: Optional[int]
    executable: Optional[str]
    parent_name: Optional[str] = None
    process_start_time: Optional[str] = None
    process_start_time_epoch: Optional[float] = None
    first_activity: Optional[str] = None
    last_activity: Optional[str] = None
    created: int = 0
    modified: int = 0
    deleted: int = 0
    total_events: int = 0
    unique_directories: Set[str] = field(default_factory=set)
    unique_files_touched: Set[str] = field(default_factory=set)
    active_rules: Set[str] = field(default_factory=set)
    entropy_score: Optional[float] = None
    extension_change_count: int = 0
    rename_count: int = 0
    bytes_written: int = 0
    encryption_indicators: Dict[str, Any] = field(default_factory=dict)
    max_event_history: int = 1000
    event_window_seconds: float = 60.0
    recent_events: Deque[Tuple[float, str, str, str]] = field(default_factory=deque)

    def record_event(self, event_type: str, src_path: str, timestamp: float) -> None:
        """Record a file system event for this process.
        
        Args:
            event_type: Type of event (FILE CREATED, FILE MODIFIED, FILE DELETED).
            src_path: Path to the file.
            timestamp: Epoch timestamp of the event.
        """
        file_path = self._normalize_file_path(src_path)
        directory = self._extract_directory(src_path)

        if self.first_activity is None:
            self.first_activity = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
        
        self.last_activity = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
        self.total_events += 1
        self.unique_directories.add(directory)
        self.unique_files_touched.add(file_path)

        if event_type == "FILE CREATED":
            self.created += 1
        elif event_type == "FILE MODIFIED":
            self.modified += 1
        elif event_type == "FILE DELETED":
            self.deleted += 1

        self.recent_events.append((timestamp, event_type, directory, file_path))
        
        # Enforce event history limit and time window simultaneously
        self._expire_old_events(timestamp)

    def _normalize_file_path(self, src_path: str) -> str:
        """Normalize a file path for consistent comparison.
        
        Args:
            src_path: The raw file path.
            
        Returns:
            Normalized absolute path string.
        """
        try:
            return str(Path(src_path).resolve())
        except Exception:
            return str(Path(src_path).absolute())

    def _extract_directory(self, src_path: str) -> str:
        """Extract the directory path from a file path.
        
        Args:
            src_path: The raw file path.
            
        Returns:
            Directory path string.
        """
        try:
            return str(Path(src_path).parent.resolve())
        except Exception:
            return str(Path(src_path).parent)

    def _expire_old_events(self, now: float) -> None:
        """Remove events older than the time window or exceeding max history.
        
        This method enforces two limits:
        1. Time-based: events older than event_window_seconds are removed.
        2. Count-based: if history exceeds max_event_history, oldest events removed.
        
        Args:
            now: Current timestamp.
        """
        window_start = now - self.event_window_seconds
        
        # Remove events outside the time window
        while self.recent_events and self.recent_events[0][0] < window_start:
            self.recent_events.popleft()
        
        # Remove oldest events if exceeding max history
        while len(self.recent_events) > self.max_event_history:
            self.recent_events.popleft()

    @property
    def events_last_second(self) -> int:
        """Return count of events in the last second.
        
        Returns:
            Number of events within the last 1 second.
        """
        now = datetime.now().timestamp()
        return sum(1 for timestamp, *_ in self.recent_events if timestamp >= now - 1.0)

    @property
    def events_last_minute(self) -> int:
        """Return count of events in the last minute.
        
        Returns:
            Number of events within the entire event window (typically 60s).
        """
        return len(self.recent_events)

    @property
    def recent_directories_last_second(self) -> Set[str]:
        """Return directories touched in the last second.
        
        Returns:
            Set of directory paths with recent activity.
        """
        now = datetime.now().timestamp()
        return {
            directory
            for timestamp, _, directory, _ in self.recent_events
            if timestamp >= now - 1.0
        }

    @property
    def unique_files(self) -> int:
        """Return total count of unique files touched.
        
        Returns:
            Count of unique file paths.
        """
        return len(self.unique_files_touched)

    @property
    def score(self) -> int:
        """Return the current behavioral score based on active rules.
        
        Returns:
            Sum of weights for all active rules.
        """
        # Load weights from config or use defaults
        if _CONFIG_AVAILABLE:
            weights = get_config().detection.rule_weights
        else:
            weights = {
                "Rule1_FileBurst": 20,
                "Rule2_MultipleDirectories": 30,
                "Rule3_YoungProcessBurst": 10,
            }
        return sum(weights.get(rule_name, 0) for rule_name in self.active_rules)

    @property
    def process_age_seconds(self) -> Optional[float]:
        """Return age of process in seconds.
        
        Returns:
            Seconds since process start, or None if unknown.
        """
        if self.process_start_time_epoch is None:
            return None
        return datetime.now().timestamp() - self.process_start_time_epoch

    @property
    def classification(self) -> str:
        """Return behavioral classification based on score.
        
        Returns:
            One of "Alert", "Suspicious", or "Normal".
        """
        # Load thresholds from config or use defaults
        if _CONFIG_AVAILABLE:
            config = get_config().detection
            alert_threshold = config.alert_threshold
            suspicious_threshold = config.suspicious_threshold
        else:
            alert_threshold = 50
            suspicious_threshold = 1
        
        if self.score >= alert_threshold:
            return "Alert"
        if self.score >= suspicious_threshold:
            return "Suspicious"
        return "Normal"

    @property
    def process_age(self) -> str:
        """Return human-readable process age.
        
        Returns:
            Formatted string like "1h 23m 45s" or "Unknown".
        """
        if self.process_age_seconds is None:
            return "Unknown"
        age = int(self.process_age_seconds)
        hours, remainder = divmod(age, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours}h {minutes}m {seconds}s"

    @property
    def recent_directories(self) -> Set[str]:
        """Return directories from all recent events.
        
        Returns:
            Set of directory paths in recent_events.
        """
        return {directory for _, _, directory, _ in self.recent_events}

    @property
    def recent_files(self) -> Set[str]:
        """Return file paths from all recent events.
        
        Returns:
            Set of file paths in recent_events.
        """
        return {file_path for _, _, _, file_path in self.recent_events}


# Legacy compatibility: Keep DetectionResult for backward compatibility
# New code should use detection_engine.DetectionResult
@dataclass
class DetectionResult:
    """Legacy detection result class.
    
    Deprecated: Use detection_engine.DetectionResult instead.
    """
    reason: str
    score_delta: int


class ProcessBehaviorTracker:
    """Maintains runtime behaviour statistics and applies scoring rules.
    
    This class manages all ProcessState objects and coordinates detection engines.
    It automatically removes stale processes to prevent memory leaks during
    long monitoring sessions.
    
    Thread Safety:
        All public methods are thread-safe and protected by internal locking.
    """

    def __init__(self, logger: logging.Logger):
        """Initialize the behavior tracker.
        
        Args:
            logger: Logger instance for output.
        """
        self.logger = logger
        self.records: Dict[ProcessIdentity, ProcessState] = {}
        self._lock = threading.RLock()  # Reentrant lock for nested calls
        
        # Load configuration
        if _CONFIG_AVAILABLE:
            config = get_config()
            self._inactivity_threshold = config.monitoring.process_inactivity_threshold
            self._cleanup_interval = config.monitoring.stale_process_cleanup_interval
            self._max_event_history = config.monitoring.max_event_history_per_process
            self._event_window = config.monitoring.event_window_seconds
            
            # Initialize detection orchestrator
            self._orchestrator = DetectionOrchestrator()
            file_engine = FileActivityEngine(config.detection.__dict__)
            self._orchestrator.register_engine(file_engine)
        else:
            # Fallback defaults
            self._inactivity_threshold = 300.0
            self._cleanup_interval = 120.0
            self._max_event_history = 1000
            self._event_window = 60.0
            self._orchestrator = None
        
        # Cleanup scheduling
        self._last_cleanup_time = datetime.now().timestamp()
        self._cleanup_enabled = True

    def record_event(
        self,
        event_type: str,
        src_path: str,
        process_metadata: ProcessMetadata,
    ) -> ProcessState:
        """Record a filesystem event and update process behavior state.
        
        Thread Safety:
            This method is thread-safe.
        
        Args:
            event_type: Type of event (FILE CREATED, FILE MODIFIED, FILE DELETED).
            src_path: Path to the affected file.
            process_metadata: Resolved process information.
        
        Returns:
            Updated ProcessState for the process.
        """
        with self._lock:
            now = datetime.now().timestamp()
            
            # Get or create process state
            identity = ProcessIdentity(
                pid=process_metadata.pid,
                executable=process_metadata.executable or process_metadata.name,
            )
            
            record = self._get_or_create_process_state(identity, process_metadata)
            
            # Update process metadata if new information is available
            self._enrich_process_metadata(record, process_metadata)
            
            # Record the event
            record.record_event(event_type, src_path, now)
            
            # Apply detection rules
            self._apply_rules(record, event_type, now, src_path)
            
            # Log process state
            self._log_process_state(record)
            
            # Periodic cleanup of stale processes
            self._maybe_cleanup_stale_processes(now)
            
            return record

    def _get_or_create_process_state(
        self,
        identity: ProcessIdentity,
        process_metadata: ProcessMetadata,
    ) -> ProcessState:
        """Get existing ProcessState or create a new one.
        
        Must be called with lock held.
        
        Args:
            identity: Process identity.
            process_metadata: Process metadata.
        
        Returns:
            ProcessState instance.
        """
        record = self.records.get(identity)
        
        if record is None:
            record = ProcessState(
                process_name=process_metadata.name,
                pid=process_metadata.pid,
                executable=process_metadata.executable,
                parent_name=process_metadata.parent_name,
                process_start_time=process_metadata.start_time,
                process_start_time_epoch=process_metadata.start_time_epoch,
                max_event_history=self._max_event_history,
                event_window_seconds=self._event_window,
            )
            self.records[identity] = record
        
        return record

    def _enrich_process_metadata(
        self,
        record: ProcessState,
        process_metadata: ProcessMetadata,
    ) -> None:
        """Update ProcessState with new metadata if available.
        
        Must be called with lock held.
        
        Args:
            record: ProcessState to update.
            process_metadata: New metadata.
        """
        if not record.process_name and process_metadata.name:
            record.process_name = process_metadata.name
        if not record.executable and process_metadata.executable:
            record.executable = process_metadata.executable
        if not record.parent_name and process_metadata.parent_name:
            record.parent_name = process_metadata.parent_name
        if not record.process_start_time and process_metadata.start_time:
            record.process_start_time = process_metadata.start_time
        if not record.process_start_time_epoch and process_metadata.start_time_epoch:
            record.process_start_time_epoch = process_metadata.start_time_epoch

    def _apply_rules(
        self,
        record: ProcessState,
        event_type: str,
        timestamp: float,
        file_path: str,
    ) -> None:
        """Apply detection rules and update active rules set.
        
        Must be called with lock held.
        
        Args:
            record: ProcessState to evaluate.
            event_type: Type of event.
            timestamp: Event timestamp.
            file_path: Affected file path.
        """
        if self._orchestrator is None:
            # Fallback to legacy behavior if orchestrator unavailable
            self._apply_legacy_rules(record, event_type, timestamp)
            return
        
        # Use detection orchestrator
        active_rules = self._orchestrator.get_active_rules(record)
        
        # Detect newly activated rules
        new_activations = active_rules - record.active_rules
        
        # Update active rules
        record.active_rules = active_rules
        
        # Log new detections
        if new_activations:
            # Evaluate engines to get detection results
            results = self._orchestrator.evaluate_all(record, event_type, timestamp, file_path)
            for result in results:
                if result.rule_name in new_activations:
                    self._log_detection(record, result)

    def _apply_legacy_rules(
        self,
        record: ProcessState,
        event_type: str,
        timestamp: float,
    ) -> None:
        """Fallback rule application if detection orchestrator unavailable.
        
        Must be called with lock held.
        """
        # This preserves the original behavior
        active_rules = set()
        
        # Rule 1: High operation rate
        if record.events_last_second > 10:
            active_rules.add("Rule1_FileBurst")
        
        # Rule 2: Multiple directories
        if len(record.recent_directories_last_second) > 1:
            active_rules.add("Rule2_MultipleDirectories")
        
        # Rule 3: Young process burst
        if (
            record.process_age_seconds is not None
            and record.process_age_seconds < 3600
            and record.events_last_second > 10
        ):
            active_rules.add("Rule3_YoungProcessBurst")
        
        # Detect new activations
        new_activations = active_rules - record.active_rules
        record.active_rules = active_rules
        
        # Log new detections
        if new_activations:
            for rule_name in new_activations:
                # Create legacy detection result
                reason = self._get_legacy_rule_reason(rule_name)
                score = record.score
                self._log_legacy_detection(record, rule_name, reason, score)

    def _get_legacy_rule_reason(self, rule_name: str) -> str:
        """Get reason message for legacy rules."""
        reasons = {
            "Rule1_FileBurst": "More than 10 file operations within 1 second",
            "Rule2_MultipleDirectories": "Touched multiple directories within 1 second",
            "Rule3_YoungProcessBurst": "Young process with high file activity",
        }
        return reasons.get(rule_name, "Unknown rule")

    def _maybe_cleanup_stale_processes(self, now: float) -> None:
        """Remove inactive processes if cleanup interval has passed.
        
        Must be called with lock held.
        
        Args:
            now: Current timestamp.
        """
        if not self._cleanup_enabled:
            return
        
        if (now - self._last_cleanup_time) < self._cleanup_interval:
            return
        
        self._last_cleanup_time = now
        self._cleanup_stale_processes(now)

    def _cleanup_stale_processes(self, now: float) -> None:
        """Remove processes that have been inactive beyond the threshold.
        
        Must be called with lock held.
        
        Args:
            now: Current timestamp.
        """
        stale_identities = []
        
        for identity, record in self.records.items():
            if record.last_activity is None:
                continue
            
            try:
                last_activity_time = datetime.strptime(
                    record.last_activity,
                    "%Y-%m-%d %H:%M:%S"
                ).timestamp()
                
                inactivity_duration = now - last_activity_time
                
                if inactivity_duration > self._inactivity_threshold:
                    stale_identities.append(identity)
            except Exception as exc:
                self.logger.debug(f"Error checking process staleness: {exc}")
        
        # Remove stale processes
        for identity in stale_identities:
            del self.records[identity]
            self.logger.debug(f"Removed stale process: {identity}")
        
        if stale_identities:
            self.logger.info(f"Cleaned up {len(stale_identities)} stale process(es)")

    def get_all_processes(self) -> Dict[ProcessIdentity, ProcessState]:
        """Return a copy of all tracked processes.
        
        Thread Safety:
            Returns a snapshot that is safe to iterate.
        
        Returns:
            Dictionary mapping process identities to states.
        """
        with self._lock:
            return self.records.copy()

    def get_process(self, identity: ProcessIdentity) -> Optional[ProcessState]:
        """Get a specific process state.
        
        Thread Safety:
            This method is thread-safe.
        
        Args:
            identity: Process identity.
        
        Returns:
            ProcessState if found, None otherwise.
        """
        with self._lock:
            return self.records.get(identity)

    def _log_detection(self, record: ProcessState, detection: Any) -> None:
        """Log a detection event with structured output.
        
        Args:
            record: ProcessState that triggered detection.
            detection: DetectionResult from detection engine.
        """
        lines = ["[Detection]", "", "Process:", record.process_name or "unknown"]
        if record.pid is not None:
            lines.extend(["", "PID:", str(record.pid)])
        if record.executable:
            lines.extend(["", "Executable:", record.executable])
        
        reason = getattr(detection, "reason", str(detection))
        lines.extend([
            "", "Reason:", reason,
            "", "Score:", str(record.score),
            "", "Files Modified:", str(record.modified),
            "Files Created:", str(record.created),
            "Files Deleted:", str(record.deleted),
            "Unique Directories:", str(len(record.unique_directories)),
        ])
        
        if record.last_activity:
            lines.extend(["", "Last Activity:", record.last_activity])
        if record.process_start_time:
            lines.extend(["", "Start Time:", record.process_start_time])
        
        lines.append("")
        lines.append("----------------------------")
        self.logger.info("\n" + "\n".join(lines))

    def _log_legacy_detection(
        self,
        record: ProcessState,
        rule_name: str,
        reason: str,
        score: int,
    ) -> None:
        """Log detection in legacy format."""
        lines = ["[Detection]", "", "Process:", record.process_name or "unknown"]
        if record.pid is not None:
            lines.extend(["", "PID:", str(record.pid)])
        if record.executable:
            lines.extend(["", "Executable:", record.executable])
        lines.extend([
            "", "Reason:", reason,
            "", "Score:", str(score),
            "", "Files Modified:", str(record.modified),
            "Files Created:", str(record.created),
            "Files Deleted:", str(record.deleted),
            "Unique Directories:", str(len(record.unique_directories)),
        ])
        if record.last_activity:
            lines.extend(["", "Last Activity:", record.last_activity])
        if record.process_start_time:
            lines.extend(["", "Start Time:", record.process_start_time])
        lines.append("")
        lines.append("----------------------------")
        self.logger.info("\n" + "\n".join(lines))

    def _log_process_state(self, record: ProcessState) -> None:
        """Log the current state of a process.
        
        Args:
            record: ProcessState to log.
        """
        lines = ["[ProcessState]", ""]
        lines.extend([
            "Process Name:", record.process_name or "unknown",
            "PID:", str(record.pid) if record.pid is not None else "unknown",
            "Executable:", record.executable or "unknown",
            "Process Age:", record.process_age,
            "Process Start Time:", record.process_start_time or "unknown",
            "First Activity:", record.first_activity or "unknown",
            "Last Activity:", record.last_activity or "unknown",
            "Files Created:", str(record.created),
            "Files Modified:", str(record.modified),
            "Files Deleted:", str(record.deleted),
            "Unique Files:", str(record.unique_files),
            "Events Last Second:", str(record.events_last_second),
            "Events Last Minute:", str(record.events_last_minute),
            "Total Events:", str(record.total_events),
            "Current Score:", str(record.score),
            "Classification:", record.classification,
            "Active Rules:", ", ".join(sorted(record.active_rules)) or "None",
        ])
        lines.append("")
        lines.append("----------------------------")
        self.logger.info("\n" + "\n".join(lines))


class FileSystemMonitorHandler(FileSystemEventHandler):
    """Watchdog event handler specialized for file creation, deletion, and modification.
    
    Thread Safety:
        Event handler methods are called by the watchdog observer thread.
        All calls to behavior_tracker are thread-safe.
    """

    def __init__(
        self,
        logger: logging.Logger,
        behavior_tracker: ProcessBehaviorTracker,
        event_callback: Optional[Callable] = None,
    ):
        """Initialize the handler.
        
        Args:
            logger: Logger instance.
            behavior_tracker: ProcessBehaviorTracker instance.
            event_callback: Optional callable invoked for every file event
                *after* the behavior tracker has been updated.  Signature::

                    callback(
                            event_type: str,
                            file_path: str,
                            process_name: Optional[str],
                            pid: Optional[int],
                            executable: Optional[str],
                            parent: Optional[str],
                            previous_path: Optional[str] = None,
                        ) -> None

                The callback is called on the watchdog observer thread; it
                MUST NOT block.  Pass work to a queue if non-trivial I/O is
                needed (see EntropyMonitor.on_file_event).
        """
        super().__init__()
        self.logger = logger
        self.behavior_tracker = behavior_tracker
        self._process_resolver = ProcessResolver()
        self._event_callback: Optional[Callable] = event_callback

    def on_created(self, event: FileCreatedEvent) -> None:
        """Handle file creation events.
        
        Args:
            event: File creation event.
        """
        if event.is_directory:
            return
        self._report_event("FILE CREATED", event.src_path)

    def on_deleted(self, event: FileDeletedEvent) -> None:
        """Handle file deletion events.
        
        Args:
            event: File deletion event.
        """
        if event.is_directory:
            return
        self._report_event("FILE DELETED", event.src_path)

    def on_modified(self, event: FileModifiedEvent) -> None:
        """Handle file modification events.
        
        Args:
            event: File modification event.
        """
        if event.is_directory:
            return
        self._report_event("FILE MODIFIED", event.src_path)

    def on_moved(self, event: FileMovedEvent) -> None:
        """Handle file moved/renamed events.

        Args:
            event: File moved event.
        """
        if event.is_directory:
            return
        self._report_event("FILE MOVED", event.dest_path, previous_path=event.src_path)

    def _report_event(self, event_type: str, src_path: str, previous_path: Optional[str] = None) -> None:
        """Format and log an event report.
        
        Args:
            event_type: Type of event.
            src_path: Path to the affected file.
        """
        try:
            path = Path(src_path)
            event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Resolve process metadata
            process_metadata = self._process_resolver.resolve(
                path,
                previous_path=Path(previous_path) if previous_path else None,
                event_type=event_type,
            )

            # Update behavioral tracker
            self.behavior_tracker.record_event(event_type, src_path, process_metadata)

            # Log structured event
            output = ["=" * 38]
            output.append(f"EVENT: {event_type}")
            output.append("")
            output.append("Time:")
            output.append(event_time)
            output.append("")
            output.append("File:")
            
            try:
                resolved_path = str(path.resolve() if path.exists() else path.absolute())
            except Exception:
                resolved_path = str(path.absolute())
            
            output.append(resolved_path)
            output.append("")
            output.append("File Name:")
            output.append(path.name)
            if previous_path:
                output.append("")
                output.append("Previous Path:")
                output.append(previous_path)
            output.append("")
            output.append("Process:")
            output.append(process_metadata.name or "Unknown")
            output.append("")
            output.append("PID:")
            output.append(str(process_metadata.pid) if process_metadata.pid else "Unknown")
            output.append("")
            output.append("Executable:")
            output.append(process_metadata.executable or "Unknown")
            output.append("")
            output.append("Parent Process:")
            output.append(process_metadata.parent_name or "Unknown")
            output.append("=" * 38)

            self.logger.info("\n" + "\n".join(output))

            self._process_resolver.remember(path, process_metadata)
            if previous_path:
                self._process_resolver.remember(Path(previous_path), process_metadata)

            # --- Notify external modules (e.g. EntropyMonitor) ----------
            # The callback receives lightweight primitives only; it must not
            # block.  Errors in the callback must not crash the monitor.
            if self._event_callback is not None:
                try:
                    self.logger.info(
                        "[ENTROPY_TRACE][FSM->CALLBACK] event=%s file=%s pid=%s proc=%s",
                        event_type,
                        str(resolved_path),
                        process_metadata.pid,
                        process_metadata.name,
                    )
                    self._event_callback(
                        event_type,
                        str(resolved_path),
                        process_metadata.name,
                        process_metadata.pid,
                        process_metadata.executable,
                        process_metadata.parent_name,
                        previous_path,
                    )
                    self.logger.info(
                        "[ENTROPY_TRACE][FSM->CALLBACK] dispatch_ok event=%s file=%s",
                        event_type,
                        str(resolved_path),
                    )
                except Exception as cb_exc:
                    self.logger.error(
                        "[ENTROPY_TRACE][FSM->CALLBACK] dispatch_error file=%s err=%s",
                        src_path,
                        cb_exc,
                    )
            else:
                self.logger.warning(
                    "[ENTROPY_TRACE][FSM->CALLBACK] event_callback is None; event dropped file=%s",
                    src_path,
                )

        except Exception as exc:
            self.logger.error(f"Failed to report filesystem event for {src_path}: {exc}", exc_info=True)


class FileSystemMonitor:
    """Main monitor class for watching filesystem changes.
    
    This class coordinates the watchdog observer, event handler, and
    behavioral tracking. It ensures clean startup and shutdown.
    
    Thread Safety:
        The observer runs in a separate thread. All components are thread-safe.
    """

    def __init__(
        self,
        target_path: Path,
        recursive: bool,
        logger: logging.Logger,
        event_callback: Optional[Callable] = None,
    ):
        """Initialize the filesystem monitor.
        
        Args:
            target_path:    Directory to monitor.
            recursive:      Whether to monitor recursively.
            logger:         Logger instance.
            event_callback: Optional callback forwarded to
                            :class:`FileSystemMonitorHandler`.  Called for
                            every file event with
                            (event_type, file_path, process_name, pid,
                             executable, parent) — all on the observer thread.
        """
        self.target_path = target_path
        self.recursive = recursive
        self.logger = logger
        self.behavior_tracker = ProcessBehaviorTracker(logger=self.logger)
        self.observer = Observer()
        self.handler = FileSystemMonitorHandler(
            logger=self.logger,
            behavior_tracker=self.behavior_tracker,
            event_callback=event_callback,
        )

    def start(self) -> None:
        """Start watching the configured path.
        
        Raises:
            FileNotFoundError: If target path does not exist.
        """
        if not self.target_path.exists():
            raise FileNotFoundError(f"Monitor path does not exist: {self.target_path}")

        self.observer.schedule(self.handler, str(self.target_path), recursive=self.recursive)
        self.observer.start()
        self.logger.info(f"Monitoring {self.target_path} (recursive={self.recursive})")

    def stop(self) -> None:
        """Stop the observer cleanly."""
        try:
            self.observer.stop()
            self.observer.join(timeout=5)
        except Exception as exc:
            self.logger.error(f"Error stopping monitor: {exc}")

    def join(self) -> None:
        """Wait for the monitor thread until stopped."""
        try:
            while self.observer.is_alive():
                self.observer.join(timeout=1)
        except KeyboardInterrupt:
            self.stop()
            raise

    def is_alive(self) -> bool:
        """Check if the monitor is running.
        
        Returns:
            True if observer is alive, False otherwise.
        """
        return self.observer.is_alive()
