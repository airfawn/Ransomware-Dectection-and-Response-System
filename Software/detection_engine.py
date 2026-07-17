"""Detection engine interface for RDRS.

This module provides an extensible architecture for behavioral detection engines.
New detection modules (entropy analysis, registry monitoring, network analysis)
can be added by implementing the DetectionEngine interface.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional, Protocol, Set
from datetime import datetime


@dataclass(frozen=True)
class DetectionResult:
    """Result of a detection rule evaluation.
    
    Attributes:
        rule_name: Unique identifier for the rule.
        reason: Human-readable explanation of the detection.
        score_delta: Score change (positive for suspicious behavior).
        severity: Optional severity level (low, medium, high, critical).
        metadata: Additional context-specific information.
    """
    
    rule_name: str
    reason: str
    score_delta: int
    severity: Optional[str] = None
    metadata: Optional[dict] = None


class ProcessContext(Protocol):
    """Protocol defining the interface for process behavioral context.
    
    This allows detection engines to access process state without
    tight coupling to the ProcessState implementation.
    """
    
    @property
    def pid(self) -> Optional[int]:
        """Process ID."""
        ...
    
    @property
    def executable(self) -> Optional[str]:
        """Executable path."""
        ...
    
    @property
    def process_age_seconds(self) -> Optional[float]:
        """Age of process in seconds."""
        ...
    
    @property
    def total_events(self) -> int:
        """Total event count."""
        ...
    
    @property
    def created(self) -> int:
        """Files created count."""
        ...
    
    @property
    def modified(self) -> int:
        """Files modified count."""
        ...
    
    @property
    def deleted(self) -> int:
        """Files deleted count."""
        ...
    
    @property
    def events_last_second(self) -> int:
        """Events in the last second."""
        ...
    
    @property
    def events_last_minute(self) -> int:
        """Events in the last minute."""
        ...
    
    @property
    def recent_directories_last_second(self) -> Set[str]:
        """Directories touched in the last second."""
        ...

    def count_extension_changes(self, window_seconds: float) -> int:
        """Count of genuine file-extension-change events within a time window.

        Args:
            window_seconds: Size of the trailing time window, in seconds.

        Returns:
            Number of extension-change events recorded within the window.
        """
        ...


class DetectionEngine(ABC):
    """Abstract base class for all detection engines.
    
    Detection engines evaluate process behavior and return detection results.
    They can maintain internal state and implement any analysis logic.
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Unique name identifying this detection engine."""
        pass
    
    @property
    @abstractmethod
    def enabled(self) -> bool:
        """Whether this engine is currently enabled."""
        pass
    
    @abstractmethod
    def evaluate(
        self,
        process_context: ProcessContext,
        event_type: str,
        timestamp: float,
        file_path: str,
    ) -> List[DetectionResult]:
        """Evaluate process behavior and return any detections.
        
        Args:
            process_context: Current state of the process.
            event_type: Type of event (FILE CREATED, FILE MODIFIED, FILE DELETED).
            timestamp: Epoch timestamp of the event.
            file_path: Path to the affected file.
        
        Returns:
            List of detection results (empty if no detections).
        """
        pass
    
    @abstractmethod
    def is_rule_active(self, rule_name: str, process_context: ProcessContext) -> bool:
        """Check if a specific rule is currently active for the process.
        
        Args:
            rule_name: Name of the rule to check.
            process_context: Current state of the process.
        
        Returns:
            True if the rule is active, False otherwise.
        """
        pass
    
    def reset(self) -> None:
        """Reset engine state (optional, called when monitoring restarts)."""
        pass


class FileActivityEngine(DetectionEngine):
    """Detection engine for filesystem activity patterns.
    
    This is the current behavioral detection engine, refactored to use
    the extensible interface.
    """
    
    def __init__(self, config: dict):
        """Initialize the file activity detection engine.
        
        Args:
            config: Configuration dictionary with thresholds and weights.
        """
        self._enabled = True
        self._config = config
        
        # Rule definitions
        self._rules = {
            "Rule1_FileBurst": {
                "weight": config.get("rule_weights", {}).get("Rule1_FileBurst", 20),
                "threshold": config.get("high_ops_threshold", 10),
                "reason": "More than {threshold} file operations within 1 second",
            },
            "Rule2_MultipleDirectories": {
                "weight": config.get("rule_weights", {}).get("Rule2_MultipleDirectories", 30),
                "threshold": config.get("multi_dir_threshold", 1),
                "reason": "Touched multiple directories within 1 second",
            },
            "Rule3_YoungProcessBurst": {
                "weight": config.get("rule_weights", {}).get("Rule3_YoungProcessBurst", 10),
                "age_threshold": config.get("young_process_age_threshold", 3600.0),
                "ops_threshold": config.get("young_process_ops_threshold", 10),
                "reason": "Young process with high file activity",
            },
        }
    
    @property
    def name(self) -> str:
        return "FileActivityEngine"
    
    @property
    def enabled(self) -> bool:
        return self._enabled
    
    def evaluate(
        self,
        process_context: ProcessContext,
        event_type: str,
        timestamp: float,
        file_path: str,
    ) -> List[DetectionResult]:
        """Evaluate file activity patterns."""
        results: List[DetectionResult] = []
        
        # Rule 1: High operation rate
        if self._check_rule1(process_context):
            rule = self._rules["Rule1_FileBurst"]
            results.append(DetectionResult(
                rule_name="Rule1_FileBurst",
                reason=rule["reason"].format(threshold=rule["threshold"]),
                score_delta=rule["weight"],
                severity="medium",
            ))
        
        # Rule 2: Multiple directories
        if self._check_rule2(process_context):
            rule = self._rules["Rule2_MultipleDirectories"]
            results.append(DetectionResult(
                rule_name="Rule2_MultipleDirectories",
                reason=rule["reason"],
                score_delta=rule["weight"],
                severity="high",
            ))
        
        # Rule 3: Young process burst
        if self._check_rule3(process_context):
            rule = self._rules["Rule3_YoungProcessBurst"]
            results.append(DetectionResult(
                rule_name="Rule3_YoungProcessBurst",
                reason=rule["reason"],
                score_delta=rule["weight"],
                severity="medium",
            ))
        
        return results
    
    def is_rule_active(self, rule_name: str, process_context: ProcessContext) -> bool:
        """Check if a rule is currently active."""
        if rule_name == "Rule1_FileBurst":
            return self._check_rule1(process_context)
        elif rule_name == "Rule2_MultipleDirectories":
            return self._check_rule2(process_context)
        elif rule_name == "Rule3_YoungProcessBurst":
            return self._check_rule3(process_context)
        return False
    
    def _is_rule_enabled(self, rule_name: str) -> bool:
        """Return whether a rule is currently enabled.

        Reads live from the config dict passed at construction time (which
        is the actual ``__dict__`` of the shared ``DetectionConfig``
        instance), so toggling a rule from the GUI's Active Rules page takes
        effect immediately without recreating the engine.
        """
        return self._config.get("rule_enabled", {}).get(rule_name, True)

    def _check_rule1(self, ctx: ProcessContext) -> bool:
        """Check high operation rate rule."""
        if not self._is_rule_enabled("Rule1_FileBurst"):
            return False
        threshold = self._rules["Rule1_FileBurst"]["threshold"]
        return ctx.events_last_second > threshold
    
    def _check_rule2(self, ctx: ProcessContext) -> bool:
        """Check multiple directories rule."""
        if not self._is_rule_enabled("Rule2_MultipleDirectories"):
            return False
        threshold = self._rules["Rule2_MultipleDirectories"]["threshold"]
        return len(ctx.recent_directories_last_second) > threshold
    
    def _check_rule3(self, ctx: ProcessContext) -> bool:
        """Check young process burst rule."""
        if not self._is_rule_enabled("Rule3_YoungProcessBurst"):
            return False
        rule = self._rules["Rule3_YoungProcessBurst"]
        age_threshold = rule["age_threshold"]
        ops_threshold = rule["ops_threshold"]
        
        return (
            ctx.process_age_seconds is not None
            and ctx.process_age_seconds < age_threshold
            and ctx.events_last_second > ops_threshold
        )


class EntropyAnalysisEngine(DetectionEngine):
    """Detection engine that scores processes on entropy-increase alerts.

    This engine is activated by the EntropyMonitor (entropy/monitor.py).
    When the EntropyMonitor detects a suspicious entropy increase it calls
    notify_entropy_event(), which this engine records.  The next call to
    evaluate() (triggered by any file event on the same process) converts
    the pending alert into a DetectionResult with the configured score delta.

    The Entropy Module itself NEVER modifies scores — it only calls this
    engine via notify_entropy_event().  The Engine (this class) decides
    the score delta.

    Score rationale:
        A default of +30 is assigned per entropy alert.  This matches the
        multi-directory rule weight and reflects that a single file's entropy
        spike is strong evidence but not conclusive on its own.  The score is
        configurable via config.yaml (entropy.score).
    """

    def __init__(self, score_delta: int = 30) -> None:
        """Initialise the engine.

        Args:
            score_delta: Score to add per confirmed entropy increase event.
                         Should be sourced from config.entropy.score.
        """
        import threading as _threading
        self._enabled = True
        self._score_delta = score_delta
        # Queue of pending entropy events waiting to be scored.
        self._pending_alerts: List[dict] = []
        self._lock = _threading.Lock()

    @property
    def name(self) -> str:
        return "EntropyAnalysisEngine"

    @property
    def enabled(self) -> bool:
        return self._enabled

    def notify_entropy_event(self, file_path: str, entropy_delta: float) -> None:
        """Record a pending entropy-increase alert for the next evaluate() call.

        Called by the GUI bridge on the Qt main thread after receiving an
        EntropyIncreaseDetected signal from the EntropyMonitor.

        Args:
            file_path:     The affected file path.
            entropy_delta: The entropy increase in bits.
        """
        with self._lock:
            self._pending_alerts.append({
                "file_path": file_path,
                "delta": entropy_delta,
            })

    def evaluate(
        self,
        process_context: ProcessContext,
        event_type: str,
        timestamp: float,
        file_path: str,
    ) -> List[DetectionResult]:
        """Return DetectionResults for any queued entropy alerts."""
        with self._lock:
            pending = self._pending_alerts.copy()
            self._pending_alerts.clear()

        results: List[DetectionResult] = []
        for alert in pending:
            results.append(DetectionResult(
                rule_name="EntropyIncrease",
                reason=(
                    f"File entropy increased by {alert['delta']:.2f} bits/byte "
                    f"in {alert['file_path']} — possible encryption in progress"
                ),
                score_delta=self._score_delta,
                severity="high",
                metadata={"file_path": alert["file_path"], "entropy_delta": alert["delta"]},
            ))
        return results

    def is_rule_active(self, rule_name: str, process_context: ProcessContext) -> bool:
        if rule_name == "EntropyIncrease":
            with self._lock:
                return len(self._pending_alerts) > 0
        return False


class ExtensionChangeEngine(DetectionEngine):
    """Detection engine for mass file-extension-change bursts.

    Ransomware commonly renames files after encrypting their contents
    (e.g. ``report.docx`` -> ``report.locked``).  A legitimate process
    rarely changes the extensions of many files within a short window, so a
    burst of such changes from a single process is a strong ransomware
    signature.

    This engine follows the exact same convention as ``FileActivityEngine``:
    it exposes a ``_rules`` dict so ``DetectionOrchestrator.get_active_rules``
    can auto-discover it, and the rule contributes its weight to
    ``ProcessState.score`` only while the burst condition remains true —
    i.e. the score bonus is applied once per detection window and is
    automatically removed once the burst subsides (no manual bookkeeping
    required to avoid double-counting).

    Genuine extension-change detection itself (what counts as a "real"
    change vs. benign autosave churn) lives in
    ``monitor.extension_monitor`` — this engine only decides *scoring*
    based on the per-process statistics already recorded on
    ``ProcessState``.
    """

    def __init__(self, config: dict):
        """Initialize the extension-change burst detection engine.

        Args:
            config: Configuration dictionary (``DetectionConfig.__dict__``)
                with ``extension_change_threshold``,
                ``extension_change_window_seconds`` and ``rule_weights``.
        """
        self._enabled = True
        self._config = config
        self._rules = {
            "Rule4_ExtensionChangeBurst": {
                "weight": config.get("rule_weights", {}).get("Rule4_ExtensionChangeBurst", 30),
                "threshold": config.get("extension_change_threshold", 5),
                "window_seconds": config.get("extension_change_window_seconds", 10.0),
                "reason": (
                    "Extension Change Detection rule triggered: more than {threshold} "
                    "file extension changes within {window:.0f}s — possible mass encryption"
                ),
            },
        }

    @property
    def name(self) -> str:
        return "ExtensionChangeEngine"

    @property
    def enabled(self) -> bool:
        return self._enabled

    def evaluate(
        self,
        process_context: ProcessContext,
        event_type: str,
        timestamp: float,
        file_path: str,
    ) -> List[DetectionResult]:
        """Evaluate the mass extension-change burst rule."""
        results: List[DetectionResult] = []

        if self._check_burst(process_context):
            rule = self._rules["Rule4_ExtensionChangeBurst"]
            results.append(DetectionResult(
                rule_name="Rule4_ExtensionChangeBurst",
                reason=rule["reason"].format(threshold=rule["threshold"], window=rule["window_seconds"]),
                score_delta=rule["weight"],
                severity="high",
            ))

        return results

    def is_rule_active(self, rule_name: str, process_context: ProcessContext) -> bool:
        """Check if the extension-change burst rule is currently active."""
        if rule_name == "Rule4_ExtensionChangeBurst":
            return self._check_burst(process_context)
        return False

    def _check_burst(self, ctx: ProcessContext) -> bool:
        """Return True when extension changes within the window exceed the threshold."""
        if not self._config.get("rule_enabled", {}).get("Rule4_ExtensionChangeBurst", True):
            return False
        rule = self._rules["Rule4_ExtensionChangeBurst"]
        count_fn = getattr(ctx, "count_extension_changes", None)
        if count_fn is None:
            return False
        try:
            count = count_fn(rule["window_seconds"])
        except Exception:
            return False
        return count >= rule["threshold"]


class NetworkActivityEngine(DetectionEngine):
    """Placeholder for future network activity monitoring.
    
    This engine will detect suspicious network connections.
    """
    
    def __init__(self):
        self._enabled = False  # Not yet implemented
    
    @property
    def name(self) -> str:
        return "NetworkActivityEngine"
    
    @property
    def enabled(self) -> bool:
        return self._enabled
    
    def evaluate(
        self,
        process_context: ProcessContext,
        event_type: str,
        timestamp: float,
        file_path: str,
    ) -> List[DetectionResult]:
        """Future: Monitor network connections."""
        return []
    
    def is_rule_active(self, rule_name: str, process_context: ProcessContext) -> bool:
        return False


class DetectionOrchestrator:
    """Coordinates multiple detection engines.
    
    This class manages a collection of detection engines and aggregates
    their results. New engines can be registered dynamically.
    """
    
    def __init__(self):
        self._engines: List[DetectionEngine] = []
    
    def register_engine(self, engine: DetectionEngine) -> None:
        """Register a new detection engine.
        
        Args:
            engine: The detection engine to register.
        """
        if engine not in self._engines:
            self._engines.append(engine)
    
    def unregister_engine(self, engine: DetectionEngine) -> None:
        """Unregister a detection engine.
        
        Args:
            engine: The detection engine to remove.
        """
        if engine in self._engines:
            self._engines.remove(engine)
    
    def evaluate_all(
        self,
        process_context: ProcessContext,
        event_type: str,
        timestamp: float,
        file_path: str,
    ) -> List[DetectionResult]:
        """Run all enabled engines and aggregate results.
        
        Args:
            process_context: Current state of the process.
            event_type: Type of event.
            timestamp: Event timestamp.
            file_path: Affected file path.
        
        Returns:
            Combined list of all detection results.
        """
        all_results: List[DetectionResult] = []
        
        for engine in self._engines:
            if not engine.enabled:
                continue
            
            try:
                results = engine.evaluate(process_context, event_type, timestamp, file_path)
                all_results.extend(results)
            except Exception as exc:
                # Log but don't crash on engine errors
                import logging
                logging.error(f"Detection engine {engine.name} failed: {exc}")
        
        return all_results
    
    def get_active_rules(self, process_context: ProcessContext) -> Set[str]:
        """Get all currently active rules across all engines.
        
        Args:
            process_context: Current state of the process.
        
        Returns:
            Set of active rule names.
        """
        active_rules: Set[str] = set()
        
        for engine in self._engines:
            if not engine.enabled:
                continue
            
            # Query each engine for its active rules
            # This is engine-specific, so we catch any errors
            try:
                if hasattr(engine, "_rules"):
                    for rule_name in engine._rules.keys():
                        if engine.is_rule_active(rule_name, process_context):
                            active_rules.add(rule_name)
            except Exception:
                pass
        
        return active_rules
    
    def reset_all(self) -> None:
        """Reset all detection engines."""
        for engine in self._engines:
            try:
                engine.reset()
            except Exception:
                pass
