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
import queue
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait
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

from entropy.calculator import calculate_entropy
from database import get_metadata_db

try:
    from config import get_config
    from detection_engine import (
        DetectionOrchestrator,
        FileActivityEngine,
        ExtensionChangeEngine,
        ProcessContext,
    )
    _CONFIG_AVAILABLE = True
except ImportError:
    _CONFIG_AVAILABLE = False

from monitor.extension_monitor import (
    DEFAULT_IGNORED_TARGET_EXTENSIONS,
    get_extension,
    is_genuine_extension_change,
)


@dataclass(frozen=True)
class ProcessMetadata:
    """Process metadata captured for an event."""

    pid: Optional[int]
    name: Optional[str]
    executable: Optional[str]
    parent_name: Optional[str]
    start_time: Optional[str]
    start_time_epoch: Optional[float] = None
    parent_pid: Optional[int] = None
    parent_executable: Optional[str] = None
    command_line: Optional[str] = None
    working_directory: Optional[str] = None
    username: Optional[str] = None


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

    def __init__(self, max_cache_size: int = 1024, resolve_timeout_seconds: float = 1.25):
        """Initialize the ProcessResolver with optional caching.
        
        Args:
            max_cache_size: Maximum number of path-to-process mappings to cache.
        """
        self._cache: Dict[str, ProcessMetadata] = {}
        self._directory_cache: Dict[str, ProcessMetadata] = {}
        self._max_cache_size = max_cache_size
        self._lock = threading.Lock()
        self._resolve_timeout_seconds = max(0.05, float(resolve_timeout_seconds))

    def resolve(
        self,
        path: Path,
        *,
        previous_path: Optional[Path] = None,
        event_type: Optional[str] = None,
        time_budget_seconds: Optional[float] = None,
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
        result = self._resolve_uncached(
            path,
            normalized_target,
            normalized_previous,
            event_type,
            time_budget_seconds=time_budget_seconds,
        )
        
        # Update cache (thread-safe) only when attribution is meaningful.
        if self._is_attributed(result):
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
        if not self._is_attributed(metadata):
            return
        normalized_target = self._normalize_path(path)
        directory_target = self._normalize_path(path.parent)
        with self._lock:
            self._cache[normalized_target] = metadata
            self._directory_cache[directory_target] = metadata

    @staticmethod
    def _is_attributed(metadata: ProcessMetadata) -> bool:
        """Return True if metadata has enough process information to be useful."""
        return metadata.pid is not None or bool(metadata.executable) or bool(metadata.name)

    def _resolve_uncached(
        self,
        path: Path,
        normalized_target: str,
        normalized_previous: Optional[str],
        event_type: Optional[str],
        *,
        time_budget_seconds: Optional[float],
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
        effective_budget = self._resolve_timeout_seconds if time_budget_seconds is None else max(0.05, float(time_budget_seconds))
        deadline = time.perf_counter() + effective_budget

        try:
            if os.name == "nt" and event_type_upper in {"FILE CREATED", "FILE MODIFIED", "FILE MOVED"}:
                parent_norm = self._normalize_path(path.parent)
                processes = self._prioritized_process_list()
                for index, process in enumerate(processes):
                    if index >= 32 and time.perf_counter() > deadline:
                        break
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

            # Open-file scans are expensive, so only attempt them for events that
            # are likely to have active write handles and while within the time budget.
            if event_type_upper in {"FILE CREATED", "FILE MODIFIED", "FILE MOVED"}:
                processes = self._prioritized_process_list()
                for index, process in enumerate(processes):
                    if index >= 32 and time.perf_counter() > deadline:
                        break
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

    @staticmethod
    def _process_priority(process: psutil.Process) -> int:
        """Prioritize likely script hosts and shells for quicker attribution."""
        name = ""
        try:
            name = (process.info.get("name") or "").lower()
        except Exception:
            name = ""
        if "python" in name:
            return 0
        if "powershell" in name or name in {"pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe"}:
            return 1
        return 2

    def _prioritized_process_list(self) -> List[psutil.Process]:
        """Return processes ordered by likelihood of owning scripted file writes."""
        processes = list(psutil.process_iter(["pid", "name", "exe", "ppid"]))
        processes.sort(key=self._process_priority)
        return processes

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

        try:
            parent = process.parent()
            parent_pid = parent.pid if parent else None
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            parent_pid = None

        try:
            parent = process.parent()
            parent_executable = parent.exe() if parent else None
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            parent_executable = None

        try:
            cmdline_parts = process.cmdline()
            command_line = " ".join(cmdline_parts) if cmdline_parts else None
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            command_line = None

        try:
            working_directory = process.cwd()
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            working_directory = None

        try:
            username = process.username()
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            username = None

        display_name = name
        if name and "powershell" in name.lower() and command_line:
            script_hint = None
            for token in command_line.split():
                if token.lower().endswith(".ps1"):
                    script_hint = Path(token.strip('"\'' )).name
                    break
            if script_hint:
                display_name = f"{name} -> {script_hint}"
        
        start_time_epoch = self._get_start_time_epoch(process)
        start_time = (
            datetime.fromtimestamp(start_time_epoch).strftime("%Y-%m-%d %H:%M:%S")
            if start_time_epoch is not None
            else None
        )
        
        return ProcessMetadata(
            pid=process.pid,
            name=display_name,
            executable=executable,
            parent_name=parent_name,
            start_time=start_time,
            start_time_epoch=start_time_epoch,
            parent_pid=parent_pid,
            parent_executable=parent_executable,
            command_line=command_line,
            working_directory=working_directory,
            username=username,
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
    parent_pid: Optional[int] = None
    parent_executable: Optional[str] = None
    command_line: Optional[str] = None
    working_directory: Optional[str] = None
    username: Optional[str] = None
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
    entropy_score_bonus: int = 0
    max_event_history: int = 1000
    event_window_seconds: float = 60.0
    recent_events: Deque[Tuple[float, str, str, str]] = field(default_factory=deque)
    extension_change_timestamps: Deque[float] = field(default_factory=lambda: deque(maxlen=500))
    """Bounded history of genuine extension-change event timestamps, used by
    ExtensionChangeEngine to detect mass-rename bursts (see
    monitor.extension_monitor and detection_engine.ExtensionChangeEngine)."""

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

    def record_extension_change(self, timestamp: float) -> None:
        """Record a genuine file-extension-change event for this process.

        Called by ProcessBehaviorTracker after confirming (via
        monitor.extension_monitor.is_genuine_extension_change) that a
        FILE MOVED event actually changed a file's extension. Feeds
        detection_engine.ExtensionChangeEngine's burst rule via
        count_extension_changes().

        Args:
            timestamp: Epoch time of the extension-change event.
        """
        self.extension_change_count += 1
        self.extension_change_timestamps.append(timestamp)

    def count_extension_changes(self, window_seconds: float) -> int:
        """Return the number of extension changes within a trailing time window.

        Implements the ProcessContext.count_extension_changes protocol
        method consumed by detection_engine.ExtensionChangeEngine.

        Args:
            window_seconds: Size of the trailing window, in seconds.

        Returns:
            Count of extension-change events within the window.
        """
        cutoff = datetime.now().timestamp() - window_seconds
        return sum(1 for ts in self.extension_change_timestamps if ts >= cutoff)

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
                "Rule4_ExtensionChangeBurst": 30,
            }
        behavioral = sum(weights.get(rule_name, 0) for rule_name in self.active_rules)
        return behavioral + int(self.entropy_score_bonus or 0)

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
            extension_engine = ExtensionChangeEngine(config.detection.__dict__)
            self._orchestrator.register_engine(extension_engine)

            self._entropy_enabled = bool(config.entropy.enabled)
            self._entropy_allowed_extensions = {e.lower().lstrip(".") for e in config.entropy.file_extensions}
            self._entropy_sample_size_bytes = int(config.entropy.sample_size_bytes)
            self._entropy_delta_threshold = float(config.entropy.threshold)
            self._entropy_score_delta = int(config.entropy.score)
            self._entropy_trigger_score = int(config.monitoring.high_score_rescan_threshold)
            self._entropy_eval_cooldown = float(config.monitoring.high_score_rescan_cooldown_seconds)
            self._entropy_stability_check_interval_ms = max(50, int(config.entropy.stability_check_interval_ms))
            self._entropy_stability_required_ms = max(100, int(config.entropy.stability_required_ms))
            self._entropy_stability_max_wait_ms = max(
                self._entropy_stability_required_ms,
                int(config.entropy.stability_max_wait_ms),
            )
            self._unknown_entropy_fallback_enabled = True
            self._unknown_fallback_window_seconds = 2.0
            self._unknown_fallback_modified_threshold = 10
            self._unknown_fallback_extension_threshold = 5
            self._unknown_fallback_move_threshold = 5

            # File Extension Change Monitor settings (detection, not scoring).
            ext_cfg = config.extension_monitor
            self._extension_monitor_enabled = ext_cfg.enabled
            self._ignored_extensions = {e.lower().lstrip(".") for e in ext_cfg.ignored_extensions}
        else:
            # Fallback defaults
            self._inactivity_threshold = 300.0
            self._cleanup_interval = 120.0
            self._max_event_history = 1000
            self._event_window = 60.0
            self._orchestrator = None
            self._extension_monitor_enabled = True
            self._ignored_extensions = set(DEFAULT_IGNORED_TARGET_EXTENSIONS)
            self._entropy_enabled = True
            self._entropy_allowed_extensions = set()
            self._entropy_sample_size_bytes = 5 * 1024 * 1024
            self._entropy_delta_threshold = 1.4
            self._entropy_score_delta = 30
            self._entropy_trigger_score = 30
            self._entropy_eval_cooldown = 5.0
            self._entropy_stability_check_interval_ms = 150
            self._entropy_stability_required_ms = 500
            self._entropy_stability_max_wait_ms = 3000
            self._unknown_entropy_fallback_enabled = True
            self._unknown_fallback_window_seconds = 2.0
            self._unknown_fallback_modified_threshold = 10
            self._unknown_fallback_extension_threshold = 5
            self._unknown_fallback_move_threshold = 5

        self._entropy_rule_name = "EntropyIncrease"
        self._entropy_last_eval: Dict[ProcessIdentity, float] = {}
        self._metadata_db = get_metadata_db()
        
        # Cleanup scheduling
        self._last_cleanup_time = datetime.now().timestamp()
        self._cleanup_enabled = True

    def get_process_state(self, process_metadata: ProcessMetadata) -> Optional[ProcessState]:
        """Return the current ProcessState for a process identity if it exists."""
        with self._lock:
            identity = ProcessIdentity(
                pid=process_metadata.pid,
                executable=process_metadata.executable or process_metadata.name,
            )
            return self.records.get(identity)

    def record_event(
        self,
        event_type: str,
        src_path: str,
        process_metadata: ProcessMetadata,
        previous_path: Optional[str] = None,
        runtime_status: Optional[Dict[str, Any]] = None,
    ) -> ProcessState:
        """Record a filesystem event and update process behavior state.
        
        Thread Safety:
            This method is thread-safe.
        
        Args:
            event_type: Type of event (FILE CREATED, FILE MODIFIED, FILE DELETED).
            src_path: Path to the affected file.
            process_metadata: Resolved process information.
            previous_path: Original path for moved/renamed events (used to
                detect genuine file-extension changes). None for other
                event types.
        
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

            if runtime_status:
                record.encryption_indicators.update(runtime_status)
            
            # Detect genuine file-extension changes (independent of scoring
            # rules, which are applied below via the detection orchestrator).
            if previous_path:
                self._handle_potential_extension_change(record, previous_path, src_path, now)
            
            # Apply detection rules
            self._apply_rules(record, event_type, now, src_path)
            
            # Log process state
            self._log_process_state(record)
            
            # Periodic cleanup of stale processes
            self._maybe_cleanup_stale_processes(now)
            
            return record

    def _handle_potential_extension_change(
        self,
        record: ProcessState,
        previous_path: str,
        new_path: str,
        timestamp: float,
    ) -> None:
        """Detect and record a genuine file-extension change, if any.

        Delegates the "is this a real extension change" decision to
        monitor.extension_monitor.is_genuine_extension_change (pure, no
        side effects), then updates the process's statistics and emits a
        structured log entry consumed by the GUI exactly like existing
        [Detection] / [ProcessState] blocks.

        Must be called with lock held.

        Args:
            record: ProcessState for the process that touched the file.
            previous_path: Original path before the rename/move.
            new_path: Path after the rename/move.
            timestamp: Epoch time of the event.
        """
        if not self._extension_monitor_enabled:
            return

        try:
            genuine = is_genuine_extension_change(
                previous_path,
                new_path,
                ignored_extensions=self._ignored_extensions,
            )
        except Exception as exc:
            self.logger.debug(f"Extension-change check failed for {new_path}: {exc}")
            return

        if not genuine:
            return

        old_ext = get_extension(previous_path)
        new_ext = get_extension(new_path)

        record.record_extension_change(timestamp)
        self._log_extension_change(record, previous_path, new_path, old_ext, new_ext)

    def _log_extension_change(
        self,
        record: ProcessState,
        previous_path: str,
        new_path: str,
        old_extension: str,
        new_extension: str,
    ) -> None:
        """Emit a structured [ExtensionChange] log entry for a genuine change.

        Parsed by the GUI (ransomwaredetector.py::_parse_extension_change_block)
        into an EXTENSION_CHANGE table row, persisted to logs.db, and shown
        using the existing File Monitoring log table — no bespoke GUI
        plumbing required beyond that single parser.

        Args:
            record: ProcessState for the process that renamed the file.
            previous_path: Original file path.
            new_path: New file path.
            old_extension: Extension before the change (no leading dot).
            new_extension: Extension after the change (no leading dot).
        """
        lines = ["[ExtensionChange]", "", "Process:", record.process_name or "unknown"]
        if record.pid is not None:
            lines.extend(["", "PID:", str(record.pid)])
        if record.executable:
            lines.extend(["", "Executable:", record.executable])
        lines.extend([
            "", "Original Path:", previous_path,
            "", "New Path:", new_path,
            "", "Original Extension:", old_extension or "(none)",
            "", "New Extension:", new_extension or "(none)",
            "", "Timestamp:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ])
        lines.append("")
        lines.append("----------------------------")
        self.logger.info("\n" + "\n".join(lines))

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
                parent_pid=process_metadata.parent_pid,
                parent_executable=process_metadata.parent_executable,
                command_line=process_metadata.command_line,
                working_directory=process_metadata.working_directory,
                username=process_metadata.username,
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
        if not record.parent_pid and process_metadata.parent_pid is not None:
            record.parent_pid = process_metadata.parent_pid
        if not record.parent_executable and process_metadata.parent_executable:
            record.parent_executable = process_metadata.parent_executable
        if not record.command_line and process_metadata.command_line:
            record.command_line = process_metadata.command_line
        if not record.working_directory and process_metadata.working_directory:
            record.working_directory = process_metadata.working_directory
        if not record.username and process_metadata.username:
            record.username = process_metadata.username
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
        if _CONFIG_AVAILABLE:
            weights = get_config().detection.rule_weights
        else:
            weights = {
                "Rule1_FileBurst": 20,
                "Rule2_MultipleDirectories": 30,
                "Rule3_YoungProcessBurst": 10,
                "Rule4_ExtensionChangeBurst": 30,
            }

        contributions = []
        for rule_name in sorted(active_rules):
            contributions.append(f"+{int(weights.get(rule_name, 0))} {rule_name}")
        if int(record.entropy_score_bonus or 0) > 0:
            contributions.append(f"+{int(record.entropy_score_bonus or 0)} {self._entropy_rule_name}")
        
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

        # Verification-based entropy scoring runs only after the behavior score
        # reaches the configured trigger and evaluates a bounded recent-file set.
        self._apply_entropy_verification_rule(record, timestamp)

        post_contributions = []
        for rule_name in sorted(record.active_rules):
            if rule_name == self._entropy_rule_name:
                continue
            post_contributions.append(f"+{int(weights.get(rule_name, 0))} {rule_name}")
        post_contributions.append(f"+{int(record.entropy_score_bonus or 0)} {self._entropy_rule_name}")

    def _apply_entropy_verification_rule(self, record: ProcessState, timestamp: float) -> None:
        """Apply entropy verification bonus based on average entropy increase."""
        if not self._entropy_enabled:
            record.entropy_score_bonus = 0
            record.active_rules.discard(self._entropy_rule_name)
            return

        identity = ProcessIdentity(pid=record.pid, executable=record.executable or record.process_name)
        last_eval = self._entropy_last_eval.get(identity)
        if last_eval is not None and (timestamp - last_eval) < self._entropy_eval_cooldown:
            if int(record.entropy_score_bonus or 0) > 0:
                record.active_rules.add(self._entropy_rule_name)
            return

        is_unattributed = self._is_unattributed_process(record)
        if is_unattributed:
            if not self._unknown_entropy_fallback_enabled:
                record.entropy_score_bonus = 0
                record.active_rules.discard(self._entropy_rule_name)
                return
            if not self._unknown_fallback_triggered(record, timestamp):
                record.entropy_score_bonus = 0
                record.active_rules.discard(self._entropy_rule_name)
                return
        else:
            behavioral_score = record.score - int(record.entropy_score_bonus or 0)
            if behavioral_score < self._entropy_trigger_score:
                record.entropy_score_bonus = 0
                record.active_rules.discard(self._entropy_rule_name)
                return

        candidate_paths: List[str] = []
        seen: Set[str] = set()
        for _, evt_type, _, evt_path in reversed(record.recent_events):
            if "MODIF" not in evt_type.upper():
                continue
            normalized = os.path.normcase(str(Path(evt_path)))
            if normalized in seen:
                continue
            seen.add(normalized)
            candidate_paths.append(evt_path)
            if len(candidate_paths) >= 10:
                break

        if not candidate_paths:
            record.entropy_score_bonus = 0
            record.active_rules.discard(self._entropy_rule_name)
            self._entropy_last_eval[identity] = timestamp
            return

        deltas: List[float] = []
        evaluation_completed = False
        for raw_path in candidate_paths:
            path = Path(raw_path)
            if not path.exists() or not path.is_file():
                continue

            stat = self._wait_for_file_stable(path)
            if stat is None:
                continue

            file_id = self._compute_file_identity(path)
            existing = self._metadata_db.get_file_by_identifier(file_id, str(path))
            baseline_entropy: Optional[float] = None
            previous_entropy: Optional[float] = None
            if existing is not None:
                baseline_entropy = existing["baseline_entropy"] if "baseline_entropy" in existing.keys() else None
                previous_entropy = existing["current_entropy"]
            if baseline_entropy is None and previous_entropy is not None:
                baseline_entropy = previous_entropy
            if baseline_entropy is None:
                cache_row = self._metadata_db.get_entropy_record(str(path))
                if cache_row is not None:
                    baseline_entropy = cache_row["entropy"]
            if baseline_entropy is None:
                continue

            current_entropy = calculate_entropy(path, self._entropy_sample_size_bytes)
            if current_entropy is None:
                continue
            evaluation_completed = True

            delta = float(current_entropy - baseline_entropy)
            deltas.append(delta)

        if evaluation_completed:
            self._entropy_last_eval[identity] = timestamp
        if not deltas:
            record.entropy_score_bonus = 0
            record.active_rules.discard(self._entropy_rule_name)
            return

        avg_entropy_increase = sum(deltas) / len(deltas)
        previously_active = self._entropy_rule_name in record.active_rules
        if avg_entropy_increase > self._entropy_delta_threshold:
            record.entropy_score_bonus = self._entropy_score_delta
            record.active_rules.add(self._entropy_rule_name)
            if not previously_active:
                reason = (
                    "Entropy verification rule triggered: average entropy increase "
                    f"{avg_entropy_increase:.3f} across {len(deltas)} recent files "
                    f"(threshold {self._entropy_delta_threshold:.3f})"
                )
                self._log_legacy_detection(
                    record,
                    self._entropy_rule_name,
                    reason,
                    record.score,
                )
        else:
            record.entropy_score_bonus = 0
            record.active_rules.discard(self._entropy_rule_name)

    def _wait_for_file_stable(self, path: Path) -> Optional[os.stat_result]:
        """Wait until file size and mtime stay unchanged for the required interval."""
        interval_s = self._entropy_stability_check_interval_ms / 1000.0
        required_s = self._entropy_stability_required_ms / 1000.0
        max_wait_s = self._entropy_stability_max_wait_ms / 1000.0

        started = time.monotonic()
        stable_since: Optional[float] = None
        last_signature: Optional[Tuple[int, float]] = None

        while (time.monotonic() - started) <= max_wait_s:
            try:
                stat = path.stat()
            except OSError:
                return None

            signature = (int(stat.st_size), float(stat.st_mtime))
            now = time.monotonic()
            if signature == last_signature:
                if stable_since is None:
                    stable_since = now
                if (now - stable_since) >= required_s:
                    return stat
            else:
                last_signature = signature
                stable_since = None

            time.sleep(interval_s)

        return None

    @staticmethod
    def _is_unattributed_process(record: ProcessState) -> bool:
        """Return True when process attribution is not reliable."""
        if record.pid is not None:
            return False
        if record.executable:
            return False
        process_name = (record.process_name or "").strip().lower()
        return process_name in {"", "unknown"}

    def _unknown_fallback_triggered(self, record: ProcessState, timestamp: float) -> bool:
        """Return True when unknown-attributed activity exceeds fallback thresholds."""
        window_start = timestamp - self._unknown_fallback_window_seconds
        modified_count = 0
        move_count = 0
        for ts, evt_type, _, _ in record.recent_events:
            if ts < window_start:
                continue
            evt_upper = evt_type.upper()
            if "MODIF" in evt_upper:
                modified_count += 1
            if "MOVE" in evt_upper or "RENAME" in evt_upper:
                move_count += 1

        extension_count = record.count_extension_changes(self._unknown_fallback_window_seconds)
        return (
            modified_count >= self._unknown_fallback_modified_threshold
            or extension_count >= self._unknown_fallback_extension_threshold
            or move_count >= self._unknown_fallback_move_threshold
        )

    @staticmethod
    def _compute_file_identity(path: Path) -> Optional[str]:
        """Build stable identity for DB lookups (inode/device, then path fallback)."""
        try:
            stat = path.stat()
            inode = int(getattr(stat, "st_ino", 0) or 0)
            device = int(getattr(stat, "st_dev", 0) or 0)
            if inode > 0:
                return f"{device}:{inode}"
        except Exception:
            pass
        try:
            return f"path:{os.path.normcase(os.path.realpath(str(path)))}"
        except Exception:
            return None

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
        
        # Rule 4: Mass extension-change burst
        if record.count_extension_changes(10.0) >= 5:
            active_rules.add("Rule4_ExtensionChangeBurst")
        
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
            "Rule4_ExtensionChangeBurst": (
                "Extension Change Detection rule triggered: more than 5 file "
                "extension changes within 10s — possible mass encryption"
            ),
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
            "Parent PID:", str(record.parent_pid) if record.parent_pid is not None else "unknown",
            "Executable:", record.executable or "unknown",
            "Parent Executable:", record.parent_executable or "unknown",
            "Command Line:", record.command_line or "unknown",
            "Working Directory:", record.working_directory or "unknown",
            "Username:", record.username or "unknown",
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
            "Process Alive:", str(record.encryption_indicators.get("process_alive", "unknown")),
            "Queue Pending:", str(record.encryption_indicators.get("queue_pending", 0)),
            "Queue Processed:", str(record.encryption_indicators.get("queue_processed", 0)),
            "Process Completed:", str(record.encryption_indicators.get("process_completed", False)),
        ])
        lines.append("")
        lines.append("----------------------------")
        self.logger.info("\n" + "\n".join(lines))


class _QueuedFileEvent:
    """Internal event payload for the burst processor."""

    __slots__ = (
        "event_type",
        "src_path",
        "previous_path",
        "process_metadata",
        "timestamp",
        "priority",
        "event_key",
        "payload",
    )

    def __init__(
        self,
        *,
        event_type: str,
        src_path: str,
        previous_path: Optional[str],
        process_metadata: Optional[ProcessMetadata] = None,
        timestamp: float,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.event_type = event_type
        self.src_path = src_path
        self.previous_path = previous_path
        self.process_metadata = process_metadata
        self.timestamp = timestamp
        self.payload = payload or {}
        self.priority = self._priority_for_event(event_type)
        self.event_key = self._build_event_key(event_type, src_path)

    @staticmethod
    def _priority_for_event(event_type: str) -> int:
        event_type_upper = (event_type or "").upper()
        if event_type_upper in {"HIGH_SCORE_RESCAN", "ENTROPY_RESCAN"}:
            return 0
        if event_type_upper in {"FILE CREATED", "FILE DELETED", "FILE MOVED"}:
            return 0
        if event_type_upper in {"FILE MODIFIED"}:
            return 1
        return 2

    @staticmethod
    def _build_event_key(event_type: str, src_path: str) -> Tuple[str, str]:
        return (
            (event_type or "").upper(),
            str(Path(src_path).resolve() if Path(src_path).exists() else Path(src_path).absolute()),
        )


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
        high_score_callback: Optional[Callable[[List[str], Dict[str, Any]], None]] = None,
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
                            file_identifier: Optional[str] = None,
                        ) -> None

                The callback is called on the watchdog observer thread; it
                MUST NOT block.  Pass work to a queue if non-trivial I/O is
                needed (see EntropyMonitor.on_file_event).
        """
        super().__init__()
        self.logger = logger
        self.behavior_tracker = behavior_tracker
        self._event_callback: Optional[Callable] = event_callback
        self._high_score_callback = high_score_callback

        if _CONFIG_AVAILABLE:
            cfg = get_config().monitoring
            queue_maxsize = max(500, int(cfg.filesystem_queue_maxsize))
            self._burst_window_seconds = float(cfg.burst_window_seconds)
            self._packet_normal_max = int(cfg.packet_normal_max)
            self._packet_medium_max = int(cfg.packet_medium_max)
            self._packet_large_max = int(cfg.packet_large_max)
            self._packet_medium_size = int(cfg.packet_medium_size)
            self._packet_large_size = int(cfg.packet_large_size)
            self._packet_extreme_size = int(cfg.packet_extreme_size)
            self._filesystem_worker_count = max(1, int(cfg.filesystem_worker_count))
            self._high_score_threshold = int(cfg.high_score_rescan_threshold)
            self._high_score_cooldown_seconds = float(cfg.high_score_rescan_cooldown_seconds)
            resolver_timeout_seconds = 1.25
        else:
            queue_maxsize = 8000
            self._burst_window_seconds = 2.0
            self._packet_normal_max = 50
            self._packet_medium_max = 200
            self._packet_large_max = 1000
            self._packet_medium_size = 20
            self._packet_large_size = 50
            self._packet_extreme_size = 100
            self._filesystem_worker_count = 4
            self._high_score_threshold = 30
            self._high_score_cooldown_seconds = 5.0
            resolver_timeout_seconds = 1.25

        self._process_resolver = ProcessResolver(resolve_timeout_seconds=resolver_timeout_seconds)

        self._event_queue: "queue.PriorityQueue[Tuple[int, float, int, _QueuedFileEvent]]" = queue.PriorityQueue(
            maxsize=queue_maxsize
        )
        self._event_lock = threading.Lock()
        self._sequence = 0
        self._queued_event_keys: Set[Tuple[str, str]] = set()
        self._processing_event_keys: Set[Tuple[str, str]] = set()
        self._modified_event_index: Dict[str, _QueuedFileEvent] = {}
        self._recent_modification_timestamps: Deque[float] = deque(maxlen=5000)
        self._high_score_rescan_state: Dict[Tuple[Optional[int], str], Tuple[int, float]] = {}

        self._burst_worker_running = True
        self._burst_packet_count = 0
        self._burst_event_count = 0
        self._merged_duplicate_events = 0
        self._deferred_low_priority_events = 0
        self._worker_pool = ThreadPoolExecutor(
            max_workers=self._filesystem_worker_count,
            thread_name_prefix="rdrs-fs-worker",
        )
        self._burst_worker_thread = threading.Thread(
            target=self._burst_worker_loop,
            name="rdrs-burst-worker",
            daemon=True,
        )
        self._burst_worker_thread.start()

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
        """Queue a filesystem event for burst-safe background processing."""
        try:
            self._enqueue_event(
                event_type=event_type,
                src_path=src_path,
                previous_path=previous_path,
                process_metadata=None,
                timestamp=time.time(),
            )
        except Exception as exc:
            self.logger.error(f"Failed to queue filesystem event for {src_path}: {exc}", exc_info=True)

    def _enqueue_event(
        self,
        *,
        event_type: str,
        src_path: str,
        previous_path: Optional[str],
        process_metadata: Optional[ProcessMetadata],
        timestamp: float,
        payload: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Queue an event without blocking the observer thread.

        Queue-full handling preserves forensic correctness by prioritizing
        create/delete/move events and collapsing duplicate modify events.
        """
        queued_event = _QueuedFileEvent(
            event_type=event_type,
            src_path=src_path,
            previous_path=previous_path,
            process_metadata=process_metadata,
            timestamp=timestamp,
            payload=payload,
        )
        event_type_upper = queued_event.event_type.upper()
        is_modification = event_type_upper == "FILE MODIFIED"
        is_forensic_critical = event_type_upper in {"FILE CREATED", "FILE DELETED", "FILE MOVED"}
        normalized_path = os.path.normcase(str(Path(src_path)))

        with self._event_lock:
            if is_modification and normalized_path in self._modified_event_index:
                existing = self._modified_event_index[normalized_path]
                if queued_event.timestamp > existing.timestamp:
                    existing.timestamp = queued_event.timestamp
                    existing.process_metadata = queued_event.process_metadata or existing.process_metadata
                    existing.payload.update(queued_event.payload)
                self._merged_duplicate_events += 1
                return False

            if is_modification:
                self._recent_modification_timestamps.append(timestamp)

            self._queued_event_keys.add(queued_event.event_key)
            self._sequence += 1
            queue_item = (queued_event.priority, queued_event.timestamp, self._sequence, queued_event)
            try:
                self._event_queue.put_nowait(queue_item)
                if is_modification:
                    self._modified_event_index[normalized_path] = queued_event
            except queue.Full:
                if is_modification:
                    self._queued_event_keys.discard(queued_event.event_key)
                    self._deferred_low_priority_events += 1
                    return False

                if is_forensic_critical:
                    self._force_enqueue_critical(queued_event)
                    return True

                self._queued_event_keys.discard(queued_event.event_key)
                self._deferred_low_priority_events += 1
                return False
        return True

    def _force_enqueue_critical(self, queued_event: _QueuedFileEvent) -> None:
        """Best-effort insertion for critical forensic events when queue is full."""
        drained: List[Tuple[int, float, int, _QueuedFileEvent]] = []
        dropped_one_low_priority = False
        while True:
            try:
                item = self._event_queue.get_nowait()
            except queue.Empty:
                break
            _, _, _, existing = item
            existing_type = existing.event_type.upper()
            if not dropped_one_low_priority and existing_type == "FILE MODIFIED":
                dropped_one_low_priority = True
                self._queued_event_keys.discard(existing.event_key)
                self._modified_event_index.pop(os.path.normcase(str(Path(existing.src_path))), None)
                continue
            drained.append(item)

        self._sequence += 1
        try:
            self._event_queue.put_nowait((queued_event.priority, queued_event.timestamp, self._sequence, queued_event))
        except queue.Full:
            self._queued_event_keys.discard(queued_event.event_key)

        for item in drained:
            try:
                self._event_queue.put_nowait(item)
            except queue.Full:
                _, _, _, existing = item
                self._queued_event_keys.discard(existing.event_key)
                if existing.event_type.upper() == "FILE MODIFIED":
                    self._modified_event_index.pop(os.path.normcase(str(Path(existing.src_path))), None)

    def _burst_worker_loop(self) -> None:
        """Process queued filesystem events with adaptive packet sizes."""
        while self._burst_worker_running or not self._event_queue.empty():
            try:
                packet_size = self._adaptive_packet_size()
                packet = self._drain_packet(packet_size)
                if not packet:
                    time.sleep(0.02)
                    continue

                self._burst_packet_count += 1
                self._burst_event_count += len(packet)
                futures = [self._worker_pool.submit(self._process_event, queued_event) for queued_event in packet]
                wait(futures)

                if packet_size > 1:
                    time.sleep(0.02)
            except Exception as exc:
                self.logger.exception("Burst worker loop failed: %s", exc)
                time.sleep(0.1)

    def _modification_volume(self) -> int:
        """Return modification volume within the active burst window."""
        cutoff = time.time() - self._burst_window_seconds
        with self._event_lock:
            while self._recent_modification_timestamps and self._recent_modification_timestamps[0] < cutoff:
                self._recent_modification_timestamps.popleft()
            return len(self._recent_modification_timestamps)

    def _adaptive_packet_size(self) -> int:
        """Select packet size based on modification-volume tiers."""
        volume = self._modification_volume()
        return self._adaptive_packet_size_for_volume(volume)

    def _adaptive_packet_size_for_volume(self, volume: int) -> int:
        """Return packet size for a known modification volume.

        Accepting the precomputed volume avoids re-entering _event_lock from
        status paths that already hold it.
        """
        if volume < self._packet_normal_max:
            return 1
        if volume < self._packet_medium_max:
            return self._packet_medium_size
        if volume < self._packet_large_max:
            return self._packet_large_size
        return self._packet_extreme_size

    def _drain_packet(self, packet_size: int) -> List[_QueuedFileEvent]:
        """Drain up to packet_size queued events, preserving priority order."""
        packet: List[_QueuedFileEvent] = []
        while len(packet) < packet_size:
            try:
                _, _, _, item = self._event_queue.get_nowait()
            except queue.Empty:
                break
            if item is None:
                continue
            packet.append(item)
        if len(packet) > 1:
            packet.sort(key=lambda item: (item.priority, item.timestamp))
        return packet

    def get_burst_status(self) -> Dict[str, Any]:
        """Return lightweight burst metrics for monitoring and UI status panels."""
        volume = self._modification_volume()
        adaptive_packet_size = self._adaptive_packet_size_for_volume(volume)
        with self._event_lock:
            queue_size = self._event_queue.qsize()
            pending_count = len(self._queued_event_keys)
            processing_count = len(self._processing_event_keys)
            return {
                "queue_size": queue_size,
                "pending_count": pending_count,
                "processing_count": processing_count,
                "packet_count": self._burst_packet_count,
                "processed_event_count": self._burst_event_count,
                "merged_duplicate_events": self._merged_duplicate_events,
                "deferred_low_priority_events": self._deferred_low_priority_events,
                "burst_active": volume >= self._packet_normal_max,
                "modification_volume": volume,
                "adaptive_packet_size": adaptive_packet_size,
            }

    def stop(self) -> None:
        """Stop the burst worker thread cleanly."""
        self._burst_worker_running = False
        burst_thread = getattr(self, "_burst_worker_thread", None)
        if burst_thread is not None and burst_thread.is_alive():
            burst_thread.join(timeout=5.0)

        if burst_thread is not None and burst_thread.is_alive():
            self.logger.warning(
                "Burst worker did not drain before timeout; forcing shutdown with %d queued event(s).",
                self._event_queue.qsize(),
            )
            self._worker_pool.shutdown(wait=False, cancel_futures=True)
            return

        self._worker_pool.shutdown(wait=True)

    def enqueue_high_priority_rescan(self, file_paths: List[str], reason: str = "manual") -> None:
        """Queue a highest-priority rescan task without blocking monitor ingestion."""
        if not file_paths:
            return
        self._enqueue_event(
            event_type="HIGH_SCORE_RESCAN",
            src_path=file_paths[0],
            previous_path=None,
            process_metadata=None,
            timestamp=time.time(),
            payload={"paths": file_paths, "reason": reason},
        )

    def _process_event(self, queued_event: _QueuedFileEvent) -> None:
        """Process one queued filesystem event and notify downstream modules."""
        process_alive: Optional[bool] = None
        with self._event_lock:
            self._processing_event_keys.add(queued_event.event_key)
            self._queued_event_keys.discard(queued_event.event_key)
            if queued_event.event_type.upper() == "FILE MODIFIED":
                self._modified_event_index.pop(os.path.normcase(str(Path(queued_event.src_path))), None)

        try:
            if queued_event.event_type.upper() in {"HIGH_SCORE_RESCAN", "ENTROPY_RESCAN"}:
                self._dispatch_high_priority_rescan(queued_event)
                return

            if queued_event.process_metadata is None:
                queued_event.process_metadata = self._process_resolver.resolve(
                    Path(queued_event.src_path),
                    previous_path=Path(queued_event.previous_path) if queued_event.previous_path else None,
                    event_type=queued_event.event_type,
                    time_budget_seconds=0.08,
                )

            process_lookup_pid = queued_event.process_metadata.pid if queued_event.process_metadata else None
            if process_lookup_pid is not None:
                try:
                    process_alive = psutil.Process(process_lookup_pid).is_running()
                except Exception:
                    process_alive = False

            path = Path(queued_event.src_path)
            event_time = datetime.fromtimestamp(queued_event.timestamp).strftime("%Y-%m-%d %H:%M:%S")

            status_before = self.get_burst_status()
            runtime_status = {
                "process_alive": bool(process_alive) if process_alive is not None else "unknown",
                "queue_pending": int(status_before.get("pending_count", 0)),
                "queue_processed": int(status_before.get("processed_event_count", 0)),
                "process_completed": False,
            }

            process_state = self.behavior_tracker.record_event(
                queued_event.event_type,
                queued_event.src_path,
                queued_event.process_metadata,
                previous_path=queued_event.previous_path,
                runtime_status=runtime_status,
            )
            file_identifier = self._compute_file_identifier(path, queued_event.previous_path)

            try:
                resolved_path = str(path.resolve() if path.exists() else path.absolute())
            except Exception:
                resolved_path = str(path.absolute())

            self.logger.debug(
                "event=%s time=%s file=%s pid=%s process=%s",
                queued_event.event_type,
                event_time,
                resolved_path,
                queued_event.process_metadata.pid,
                queued_event.process_metadata.name,
            )

            self._process_resolver.remember(path, queued_event.process_metadata)
            if queued_event.previous_path:
                self._process_resolver.remember(Path(queued_event.previous_path), queued_event.process_metadata)

            if self._event_callback is not None:
                try:
                    self._event_callback(
                        queued_event.event_type,
                        str(resolved_path),
                        queued_event.process_metadata.name,
                        queued_event.process_metadata.pid,
                        queued_event.process_metadata.executable,
                        queued_event.process_metadata.parent_name,
                        queued_event.previous_path,
                        file_identifier,
                    )

                    if (
                        queued_event.previous_path
                        and getattr(self.behavior_tracker, "_extension_monitor_enabled", True)
                        and is_genuine_extension_change(
                            queued_event.previous_path,
                            str(resolved_path),
                            ignored_extensions=getattr(self.behavior_tracker, "_ignored_extensions", None),
                        )
                    ):
                        self._event_callback(
                            "FILE EXTENSION CHANGED",
                            str(resolved_path),
                            queued_event.process_metadata.name,
                            queued_event.process_metadata.pid,
                            queued_event.process_metadata.executable,
                            queued_event.process_metadata.parent_name,
                            queued_event.previous_path,
                            file_identifier,
                        )
                except Exception as cb_exc:
                    self.logger.error(
                        "[ENTROPY_TRACE][FSM->CALLBACK] dispatch_error file=%s err=%s",
                        queued_event.src_path,
                        cb_exc,
                    )
            else:
                self.logger.warning(
                    "[ENTROPY_TRACE][FSM->CALLBACK] event_callback is None; event dropped file=%s",
                    queued_event.src_path,
                )

            # Legacy high-score rescan dispatch is intentionally disabled.
            # Entropy scoring is now computed inside ProcessBehaviorTracker.
        except Exception as exc:
            self.logger.error(f"Failed to process queued filesystem event for {queued_event.src_path}: {exc}", exc_info=True)
        finally:
            with self._event_lock:
                self._processing_event_keys.discard(queued_event.event_key)

    def _maybe_trigger_high_score_rescan(self, process_state: ProcessState) -> None:
        """Trigger filesystem-truth entropy rescans for high-score suspicious activity."""
        return

    def _dispatch_high_priority_rescan(self, queued_event: _QueuedFileEvent) -> None:
        """Dispatch highest-priority entropy rescans to downstream callback."""
        if self._high_score_callback is None:
            return
        payload_paths = queued_event.payload.get("paths") if queued_event.payload else None
        if not payload_paths:
            payload_paths = [queued_event.src_path]
        context = queued_event.payload.get("context", {}) if queued_event.payload else {}
        try:
            self._high_score_callback(list(payload_paths), context)
        except Exception as exc:
            self.logger.error("Failed high-priority rescan callback: %s", exc, exc_info=True)

    @staticmethod
    def _compute_file_identifier(path: Path, previous_path: Optional[str]) -> Optional[str]:
        """Build a stable file identity for rename/extension change tracking."""
        candidate_paths: List[Path] = [path]
        if previous_path:
            candidate_paths.append(Path(previous_path))

        for candidate in candidate_paths:
            try:
                stat = candidate.stat()
                inode = int(getattr(stat, "st_ino", 0) or 0)
                device = int(getattr(stat, "st_dev", 0) or 0)
                if inode > 0:
                    return f"{device}:{inode}"
            except Exception:
                continue

        for candidate in candidate_paths:
            try:
                return f"path:{os.path.normcase(os.path.realpath(str(candidate)))}"
            except Exception:
                continue

        return None


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
        high_score_callback: Optional[Callable[[List[str], Dict[str, Any]], None]] = None,
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
            high_score_callback=high_score_callback,
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
            self.handler.stop()
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
