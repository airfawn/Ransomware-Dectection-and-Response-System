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
    
    def _check_rule1(self, ctx: ProcessContext) -> bool:
        """Check high operation rate rule."""
        threshold = self._rules["Rule1_FileBurst"]["threshold"]
        return ctx.events_last_second > threshold
    
    def _check_rule2(self, ctx: ProcessContext) -> bool:
        """Check multiple directories rule."""
        threshold = self._rules["Rule2_MultipleDirectories"]["threshold"]
        return len(ctx.recent_directories_last_second) > threshold
    
    def _check_rule3(self, ctx: ProcessContext) -> bool:
        """Check young process burst rule."""
        rule = self._rules["Rule3_YoungProcessBurst"]
        age_threshold = rule["age_threshold"]
        ops_threshold = rule["ops_threshold"]
        
        return (
            ctx.process_age_seconds is not None
            and ctx.process_age_seconds < age_threshold
            and ctx.events_last_second > ops_threshold
        )


class EntropyAnalysisEngine(DetectionEngine):
    """Placeholder for future entropy analysis detection.
    
    This engine will analyze file entropy to detect encryption patterns.
    """
    
    def __init__(self):
        self._enabled = False  # Not yet implemented
    
    @property
    def name(self) -> str:
        return "EntropyAnalysisEngine"
    
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
        """Future: Analyze file entropy patterns."""
        return []
    
    def is_rule_active(self, rule_name: str, process_context: ProcessContext) -> bool:
        return False


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
