"""Centralized configuration for RDRS.

This module provides a single source of truth for all configuration parameters,
thresholds, and limits used throughout the application.  It supports both
development and production environments and is designed for easy tuning.

Runtime values are loaded from config.yaml (searched next to the executable or
in the source tree).  If the file is absent or malformed the application falls
back to the dataclass defaults — ensuring the application always starts.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import re
import sys
import logging

from utils.paths import get_base_dir, get_log_dir, get_config_dir

logger = logging.getLogger(__name__)


@dataclass
class MonitoringConfig:
    """Configuration for filesystem monitoring."""

    # Default directory used by the desktop file monitor path selector.
    file_monitor_directory: str = str(Path.home())
    """Directory used by the File Monitoring engine in Desktop mode."""
    
    # Event processing
    max_event_history_per_process: int = 1000
    """Maximum number of events to retain per process (memory management)."""
    
    event_window_seconds: float = 60.0
    """Time window for rate calculations (events per minute)."""
    
    process_cache_size: int = 1024
    """Maximum entries in the process resolver cache."""
    
    # Stale process cleanup
    process_inactivity_threshold: float = 300.0
    """Seconds of inactivity before a process is considered stale (5 minutes)."""
    
    stale_process_cleanup_interval: float = 120.0
    """How often to scan for and remove stale processes (2 minutes)."""
    
    # Performance tuning
    gui_refresh_interval_ms: int = 500
    """Milliseconds between GUI table updates (reduce for better performance)."""
    
    max_gui_events_displayed: int = 5000
    """Maximum number of events to display in the file monitoring table."""


@dataclass
class DetectionConfig:
    """Configuration for behavioral detection rules."""
    
    # Rule thresholds
    high_ops_threshold: int = 10
    """Operations per second to trigger high operation rate rule."""
    
    multi_dir_threshold: int = 1
    """Number of directories in 1 second to trigger multi-directory rule."""
    
    young_process_age_threshold: float = 3600.0
    """Process age (seconds) for young process rule (1 hour)."""
    
    young_process_ops_threshold: int = 10
    """Operations per second for young process rule."""
    
    extension_change_threshold: int = 5
    """Number of genuine file-extension changes by one process within the
    detection window that is treated as a mass-encryption burst."""
    
    extension_change_window_seconds: float = 10.0
    """Trailing time window (seconds) used to evaluate the extension-change
    burst rule."""
    
    # Scoring weights
    rule_weights: Dict[str, int] = field(default_factory=lambda: {
        "Rule1_FileBurst": 20,
        "Rule2_MultipleDirectories": 30,
        "Rule3_YoungProcessBurst": 10,
        "Rule4_ExtensionChangeBurst": 30,
    })

    # Per-rule enable/disable switches. A disabled rule never contributes to
    # a process's score, even while its trigger condition would otherwise
    # hold true. Edited from the "Active Rules" GUI page.
    rule_enabled: Dict[str, bool] = field(default_factory=lambda: {
        "Rule1_FileBurst": True,
        "Rule2_MultipleDirectories": True,
        "Rule3_YoungProcessBurst": True,
        "Rule4_ExtensionChangeBurst": True,
    })
    
    # Classification thresholds
    alert_threshold: int = 50
    """Score threshold for Alert classification."""
    
    suspicious_threshold: int = 1
    """Score threshold for Suspicious classification (0 is Normal)."""


@dataclass
class GUIConfig:
    """Configuration for GUI appearance and behavior."""
    
    # Window defaults
    default_window_width: int = 1400
    default_window_height: int = 900
    
    # Theme colors
    background_primary: str = "#171b25"
    background_secondary: str = "#1f2430"
    background_sidebar: str = "qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #171b25, stop:1 #20263a)"
    
    accent_color: str = "#2d3a5a"
    text_primary: str = "#f0f0f0"
    text_secondary: str = "#d9d9d9"
    
    # Status colors
    color_success: str = "#4CAF50"
    color_danger: str = "#f44336"
    color_warning: str = "#ff9800"
    color_active: str = "#00a000"
    
    # Event type colors
    color_created: str = "#007a00"
    color_deleted: str = "#a00000"
    color_modified: str = "#003a9e"
    
    # Classification colors
    classification_colors: Dict[str, str] = field(default_factory=lambda: {
        "Normal": "#4CAF50",
        "Suspicious": "#ff9800",
        "Alert": "#f44336",
        "Inactive": "#808080",
    })
    
    # Table settings
    table_font_size: int = 12
    header_font_size: int = 14
    
    # Process details panel
    process_details_max_events: int = 1000
    """Maximum events to display in process details timeline."""


@dataclass
class LoggingConfig:
    """Configuration for logging."""
    
    log_level: str = "INFO"
    """Default log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)."""
    
    log_to_file: bool = False
    """Whether to enable file logging."""
    
    log_file_name: str = "rdrs.log"
    """Name of the log file."""
    
    log_file_max_bytes: int = 10 * 1024 * 1024
    """Maximum size of log file before rotation (10 MB)."""
    
    log_file_backup_count: int = 3
    """Number of backup log files to keep."""
    
    console_log_format: str = "%(asctime)s %(levelname)s %(message)s"
    file_log_format: str = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    date_format: str = "%Y-%m-%d %H:%M:%S"


@dataclass
class PathConfig:
    """Configuration for file paths and directories.
    
    This class now delegates to utils.paths module for cross-platform
    frozen/source environment support.
    """
    
    @staticmethod
    def get_base_dir() -> Path:
        """Return the base directory for the application.
        
        This handles both development and PyInstaller frozen execution.
        Delegates to utils.paths.get_base_dir().
        """
        return get_base_dir()
    
    @staticmethod
    def get_log_dir() -> Path:
        """Return the directory for log files."""
        return get_log_dir()
    
    @staticmethod
    def get_config_dir() -> Path:
        """Return the directory for configuration files."""
        return get_config_dir()


@dataclass
class EntropyConfig:
    """Configuration for the Shannon Entropy detection module."""

    # File extensions to check for entropy (lowercase, no leading dot).
    # Populated from config.yaml; sensible defaults are provided here.
    file_extensions: List[str] = field(default_factory=lambda: [
        "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf",
        "txt", "csv", "jpg", "jpeg", "png", "zip",
        "py", "js", "ts", "html", "xml", "json",
        "db", "sqlite", "sqlite3",
    ])

    # Directories to watch — resolved at runtime so "~" is expanded.
    directories: List[str] = field(default_factory=lambda: ["~"])

    # Bytes to read per file (5 MB default).
    sample_size_bytes: int = 5 * 1024 * 1024

    # Entropy increase (bits) above which an event is emitted to the Engine.
    # See config.yaml for rationale.
    threshold: float = 1.4

    # Score delta the Engine adds on EntropyIncreaseDetected.
    score: int = 30


@dataclass
class DatabaseConfig:
    """Configuration for SQLite database file names and retention policies."""

    metadata_db: str = "metadata.db"
    logs_db: str = "logs.db"
    alerts_db: str = "alerts.db"

    # Days to retain deleted-file records in metadata.db before purging.
    metadata_retention_days: int = 30

    # Maximum rows in the logs table; oldest rows purged when exceeded.
    max_log_rows: int = 500_000


@dataclass
class AlertsConfig:
    """Configuration for alert thresholds and notifications."""

    # Process score at or above which the Home page shows a red alert banner.
    process_alert_threshold: int = 70


@dataclass
class ExtensionMonitorConfig:
    """Configuration for the File Extension Change Monitor."""

    enabled: bool = True
    """Master on/off switch for extension-change detection."""

    ignored_extensions: List[str] = field(default_factory=lambda: [
        "tmp", "temp", "swp", "swx", "swo", "bak",
        "crdownload", "part", "partial", "download",
    ])
    """Destination extensions treated as benign churn (autosave/temp/partial
    downloads) and therefore excluded from detection, even though they
    technically change the extension."""


@dataclass
class AppConfig:
    """Master configuration container for the entire application."""

    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    gui: GUIConfig = field(default_factory=GUIConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    paths: PathConfig = field(default_factory=PathConfig)
    entropy: EntropyConfig = field(default_factory=EntropyConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    alerts: AlertsConfig = field(default_factory=AlertsConfig)
    extension_monitor: ExtensionMonitorConfig = field(default_factory=ExtensionMonitorConfig)

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary for serialization."""
        return {
            "monitoring": self.monitoring.__dict__,
            "detection": {
                **self.detection.__dict__,
                "rule_weights": self.detection.rule_weights.copy(),
                "rule_enabled": self.detection.rule_enabled.copy(),
            },
            "gui": {
                **self.gui.__dict__,
                "classification_colors": self.gui.classification_colors.copy(),
            },
            "logging": self.logging.__dict__,
            "entropy": self.entropy.__dict__,
            "database": self.database.__dict__,
            "alerts": self.alerts.__dict__,
            "extension_monitor": {
                **self.extension_monitor.__dict__,
                "ignored_extensions": self.extension_monitor.ignored_extensions.copy(),
            },
        }


# ---------------------------------------------------------------------------
# YAML loading helpers
# ---------------------------------------------------------------------------

def _find_config_yaml() -> Optional[Path]:
    """Search for config.yaml in order of priority.

    Priority:
    1. Next to the executable / sys._MEIPASS (frozen builds).
    2. Next to this source file's parent (Software/ directory).
    3. Current working directory.

    Returns:
        Path to config.yaml or None if not found.
    """
    candidates: List[Path] = []

    if getattr(sys, "frozen", False):
        # PyInstaller: bundled assets are in sys._MEIPASS
        candidates.append(Path(sys._MEIPASS) / "config.yaml")
        # Also check next to the actual executable
        candidates.append(Path(sys.executable).parent / "config.yaml")
    else:
        # Source mode: config.yaml sits in Software/
        candidates.append(Path(__file__).resolve().parent / "config.yaml")

    candidates.append(Path.cwd() / "config.yaml")

    for candidate in candidates:
        if candidate.is_file():
            return candidate

    return None


def _load_yaml_config(path: Path) -> Dict[str, Any]:
    """Load and parse a YAML config file.

    Args:
        path: Path to config.yaml.

    Returns:
        Parsed dictionary, or empty dict on error.
    """
    try:
        import yaml  # PyYAML — optional but strongly recommended
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return data
    except ImportError:
        logger.warning(
            "PyYAML is not installed.  Install it with: pip install pyyaml\n"
            "Falling back to built-in defaults."
        )
        return {}
    except Exception as exc:
        logger.warning("Failed to parse config.yaml (%s): %s — using defaults.", path, exc)
        return {}


def _apply_yaml_to_config(cfg: AppConfig, data: Dict[str, Any]) -> None:
    """Overwrite cfg fields with values from the parsed YAML dict.

    Only keys that exist in the YAML are applied; missing keys retain defaults.

    Args:
        cfg: AppConfig instance to modify in-place.
        data: Parsed YAML dictionary.
    """
    # -- monitoring section --------------------------------------------------
    mon = data.get("monitoring") or {}
    if "file_monitor_directory" in mon:
        cfg.monitoring.file_monitor_directory = str(mon["file_monitor_directory"])

    # -- entropy section -----------------------------------------------------
    ent = data.get("entropy") or {}
    if "sample_size_mb" in ent:
        cfg.entropy.sample_size_bytes = int(ent["sample_size_mb"]) * 1024 * 1024
    if "threshold" in ent:
        cfg.entropy.threshold = float(ent["threshold"])
    if "score" in ent:
        cfg.entropy.score = int(ent["score"])
    if "enabled" in ent:
        cfg.entropy.enabled = bool(ent["enabled"])
    if "file_extensions" in mon:
        exts = mon["file_extensions"]
        if isinstance(exts, list):
            cfg.entropy.file_extensions = [str(e).lower().lstrip(".") for e in exts]
    if "directories" in mon:
        dirs = mon["directories"]
        if isinstance(dirs, list):
            cfg.entropy.directories = [str(d) for d in dirs]

    # -- database section ----------------------------------------------------
    db = data.get("database") or {}
    if "metadata_db" in db:
        cfg.database.metadata_db = str(db["metadata_db"])
    if "logs_db" in db:
        cfg.database.logs_db = str(db["logs_db"])
    if "alerts_db" in db:
        cfg.database.alerts_db = str(db["alerts_db"])
    if "metadata_retention_days" in db:
        cfg.database.metadata_retention_days = int(db["metadata_retention_days"])
    if "max_log_rows" in db:
        cfg.database.max_log_rows = int(db["max_log_rows"])

    # -- alerts section ------------------------------------------------------
    al = data.get("alerts") or {}
    if "process_alert_threshold" in al:
        cfg.alerts.process_alert_threshold = int(al["process_alert_threshold"])

    # -- detection section ----------------------------------------------------
    det = data.get("detection") or {}
    if "extension_change_threshold" in det:
        cfg.detection.extension_change_threshold = int(det["extension_change_threshold"])
    if "extension_change_window_seconds" in det:
        cfg.detection.extension_change_window_seconds = float(det["extension_change_window_seconds"])
    if "rule_weights" in det and isinstance(det["rule_weights"], dict):
        cfg.detection.rule_weights.update({k: int(v) for k, v in det["rule_weights"].items()})
    if "rule_enabled" in det and isinstance(det["rule_enabled"], dict):
        cfg.detection.rule_enabled.update({k: bool(v) for k, v in det["rule_enabled"].items()})

    # -- extension_monitor section --------------------------------------------
    ext_mon = data.get("extension_monitor") or {}
    if "enabled" in ext_mon:
        cfg.extension_monitor.enabled = bool(ext_mon["enabled"])
    if "ignored_extensions" in ext_mon and isinstance(ext_mon["ignored_extensions"], list):
        cfg.extension_monitor.ignored_extensions = [
            str(e).lower().lstrip(".") for e in ext_mon["ignored_extensions"]
        ]


# ---------------------------------------------------------------------------
# Global config instance
# ---------------------------------------------------------------------------

# Global configuration instance
_config: AppConfig = AppConfig()


def get_config() -> AppConfig:
    """Return the global configuration instance.

    Returns:
        The application configuration object.
    """
    return _config


def reload_config() -> None:
    """Reload configuration: first resets to defaults, then applies config.yaml."""
    global _config
    _config = AppConfig()
    yaml_path = _find_config_yaml()
    if yaml_path is not None:
        data = _load_yaml_config(yaml_path)
        try:
            _apply_yaml_to_config(_config, data)
            logger.debug("Loaded config.yaml from %s", yaml_path)
        except Exception as exc:
            # Never crash startup due to invalid config values. Keep defaults.
            logger.warning(
                "Invalid values found in config.yaml (%s): %s — using safe defaults for invalid entries.",
                yaml_path,
                exc,
            )
    else:
        logger.debug("config.yaml not found — using built-in defaults.")


def save_rule_settings(rule_weights: Dict[str, int], rule_enabled: Dict[str, bool]) -> bool:
    """Persist rule weight/enabled changes to both the live config and config.yaml.

    Used by the GUI's "Active Rules" page. Updates the in-memory AppConfig
    immediately (so running detection reflects the change on the very next
    evaluated event) and performs a targeted text edit of config.yaml that
    preserves all existing comments/formatting elsewhere in the file.

    Args:
        rule_weights: Mapping of rule name -> new score weight. May be a
            partial update (only changed rules need to be included).
        rule_enabled: Mapping of rule name -> new enabled flag. May be a
            partial update.

    Returns:
        True if config.yaml was found and successfully rewritten on disk.
        False if config.yaml could not be located/written (the in-memory
        config is still updated in that case, so detection behavior changes
        for the current session even though it won't survive a restart).
    """
    # Update the live config immediately regardless of on-disk outcome.
    _config.detection.rule_weights.update(rule_weights)
    _config.detection.rule_enabled.update(rule_enabled)

    yaml_path = _find_config_yaml()
    if yaml_path is None:
        logger.warning("config.yaml not found — rule changes applied in-memory only (not persisted).")
        return False

    try:
        text = yaml_path.read_text(encoding="utf-8")
    except Exception as exc:
        logger.warning("Failed to read config.yaml for saving rule settings: %s", exc)
        return False

    # Weight lines look like "  Rule1_FileBurst: 20" — the numeric value
    # unambiguously distinguishes them from the boolean rule_enabled lines.
    for rule_name, weight in rule_weights.items():
        pattern = re.compile(rf'(?m)^(\s*{re.escape(rule_name)}:\s*)\d+[ \t]*$')
        if pattern.search(text):
            text = pattern.sub(rf'\g<1>{int(weight)}', text)

    if "rule_enabled:" in text:
        for rule_name, enabled in rule_enabled.items():
            pattern = re.compile(rf'(?mi)^(\s*{re.escape(rule_name)}:\s*)(?:true|false)[ \t]*$')
            if pattern.search(text):
                text = pattern.sub(rf'\g<1>{str(bool(enabled)).lower()}', text)
            else:
                # Rule not yet listed under rule_enabled — append it.
                block_pattern = re.compile(r'(?m)^(\s*)rule_enabled:\s*$')
                match = block_pattern.search(text)
                if match:
                    indent = match.group(1) + "  "
                    insert_at = match.end()
                    text = (
                        text[:insert_at]
                        + f"\n{indent}{rule_name}: {str(bool(enabled)).lower()}"
                        + text[insert_at:]
                    )
    else:
        # No rule_enabled mapping exists yet — insert one right after
        # rule_weights so the new switches are discoverable and documented.
        weights_block_pattern = re.compile(r'(?m)^(\s*)rule_weights:\s*(?:\n\1\s+\S+:\s*\d+\s*)+')
        match = weights_block_pattern.search(text)
        lines = [
            "",
            "  # Per-rule enable/disable switches. A disabled rule never",
            "  # contributes to a process's score, even if its trigger condition holds.",
            "  rule_enabled:",
        ]
        for rule_name in cfg_rule_order():
            lines.append(f"    {rule_name}: {str(bool(rule_enabled.get(rule_name, True))).lower()}")
        insertion = "\n".join(lines)
        if match:
            insert_at = match.end()
            text = text[:insert_at] + insertion + text[insert_at:]
        else:
            text += "\ndetection:\n  rule_enabled:\n" + "\n".join(
                f"    {r}: {str(bool(rule_enabled.get(r, True))).lower()}" for r in cfg_rule_order()
            ) + "\n"

    try:
        yaml_path.write_text(text, encoding="utf-8")
    except Exception as exc:
        logger.warning("Failed to write config.yaml with updated rule settings: %s", exc)
        return False

    logger.info("Persisted rule settings to %s", yaml_path)
    return True


def cfg_rule_order() -> List[str]:
    """Return the canonical rule name ordering used when writing config.yaml."""
    return [
        "Rule1_FileBurst",
        "Rule2_MultipleDirectories",
        "Rule3_YoungProcessBurst",
        "Rule4_ExtensionChangeBurst",
    ]


def _find_top_level_section_span(text: str, section_name: str) -> Optional[Tuple[int, int]]:
    """Return the (start, end) character span of a top-level YAML section's body.

    The span covers everything from just after the "section_name:" line up to
    (but not including) the next top-level key, or end of file. Used to scope
    scalar-key edits to a single section so identically-named keys in other
    sections (e.g. "enabled:" appears under both entropy: and
    extension_monitor:) are never touched by mistake.

    Args:
        text: Full config.yaml contents.
        section_name: Top-level section name (e.g. "entropy").

    Returns:
        (start, end) character offsets, or None if the section is not found.
    """
    section_pattern = re.compile(rf'(?m)^{re.escape(section_name)}:[ \t]*$')
    match = section_pattern.search(text)
    if not match:
        return None
    start = match.end()
    next_top_level = re.compile(r'(?m)^[A-Za-z_][A-Za-z0-9_]*:\s*(#.*)?$')
    next_match = next_top_level.search(text, start)
    end = next_match.start() if next_match else len(text)
    return start, end


def _patch_scalar_in_section(
    text: str,
    section_name: str,
    key: str,
    new_value: str,
    value_pattern: str,
) -> str:
    """Update (or insert) a top-level scalar key within a named YAML section.

    Args:
        text: Full config.yaml contents.
        section_name: Top-level section name (e.g. "entropy").
        key: Scalar key to update (e.g. "score", "enabled").
        new_value: Replacement value, already formatted as YAML scalar text.
        value_pattern: Regex fragment matching the key's existing value type
            (e.g. r"\\d+" for ints, r"true|false" for booleans) so the same
            key name in a different section is never accidentally matched.

    Returns:
        Updated text. Unchanged if the section could not be found.
    """
    span = _find_top_level_section_span(text, section_name)
    if span is None:
        return text
    start, end = span
    section_body = text[start:end]

    key_pattern = re.compile(rf'(?mi)^(\s*{re.escape(key)}:\s*)(?:{value_pattern})[ \t]*$')
    if key_pattern.search(section_body):
        section_body = key_pattern.sub(rf'\g<1>{new_value}', section_body, count=1)
    else:
        section_body = f"  {key}: {new_value}\n" + section_body.lstrip("\n")

    return text[:start] + section_body + text[end:]


def _patch_list_in_section(
    text: str,
    section_name: str,
    key: str,
    items: List[str],
) -> str:
    """Update (or insert) a simple YAML list key within a top-level section.

    Args:
        text: Full config.yaml contents.
        section_name: Top-level section name (e.g. "monitoring").
        key: List key to update (e.g. "directories").
        items: List item values to write.

    Returns:
        Updated text (unchanged if section not found).
    """
    span = _find_top_level_section_span(text, section_name)
    if span is None:
        return text
    start, end = span
    section_body = text[start:end]

    lines = section_body.splitlines(keepends=True)
    key_re = re.compile(rf'^(\s*){re.escape(key)}:[ \t]*$')

    for idx, raw_line in enumerate(lines):
        line = raw_line.rstrip("\n")
        match = key_re.match(line)
        if not match:
            continue

        key_indent = match.group(1)
        list_indent = key_indent + "  "

        j = idx + 1
        while j < len(lines):
            current_line = lines[j]
            stripped = current_line.strip()
            leading_spaces = len(current_line) - len(current_line.lstrip(" "))

            if stripped.startswith("-") and leading_spaces >= len(list_indent):
                j += 1
                continue
            break

        new_block = [f"{list_indent}- {item}\n" for item in items]
        lines = lines[: idx + 1] + new_block + lines[j:]
        section_body = "".join(lines)
        return text[:start] + section_body + text[end:]

    insertion = [f"  {key}:\n"] + [f"    - {item}\n" for item in items]
    section_body = "".join(insertion) + section_body.lstrip("\n")
    return text[:start] + section_body + text[end:]


def save_startup_directories(entropy_directory: str, file_monitor_directory: str) -> bool:
    """Persist startup-selected directories to live config and config.yaml.

    Args:
        entropy_directory: Directory selected for entropy monitoring cache/rebuild.
        file_monitor_directory: Directory selected for desktop file monitor path.

    Returns:
        True when persisted to config.yaml, False on write/read failures.
    """
    entropy_path = str(Path(entropy_directory).expanduser())
    file_monitor_path = str(Path(file_monitor_directory).expanduser())

    _config.entropy.directories = [entropy_path]
    _config.monitoring.file_monitor_directory = file_monitor_path

    yaml_path = _find_config_yaml()
    if yaml_path is None:
        logger.warning("config.yaml not found — startup directory changes applied in-memory only.")
        return False

    try:
        text = yaml_path.read_text(encoding="utf-8")
    except Exception as exc:
        logger.warning("Failed to read config.yaml while saving startup directories: %s", exc)
        return False

    text = _patch_list_in_section(text, "monitoring", "directories", [f'"{entropy_path}"'])
    text = _patch_scalar_in_section(
        text,
        "monitoring",
        "file_monitor_directory",
        f'"{file_monitor_path}"',
        r'.*',
    )

    try:
        yaml_path.write_text(text, encoding="utf-8")
    except Exception as exc:
        logger.warning("Failed to write config.yaml with startup directories: %s", exc)
        return False

    logger.info("Persisted startup directories to %s", yaml_path)
    return True


def save_entropy_rule_settings(score: Optional[int] = None, enabled: Optional[bool] = None) -> bool:
    """Persist Entropy rule (score/enabled) changes to both the live config and config.yaml.

    Mirrors save_rule_settings() but targets config.entropy.score/enabled
    instead of config.detection.rule_weights/rule_enabled, since the Entropy
    rule's tunables live in a different top-level YAML section. Used by the
    GUI's "Active Rules" page for the Entropy row.

    Args:
        score: New score delta, or None to leave unchanged.
        enabled: New enabled flag, or None to leave unchanged.

    Returns:
        True if config.yaml was found and successfully rewritten on disk.
    """
    if score is not None:
        _config.entropy.score = int(score)
    if enabled is not None:
        _config.entropy.enabled = bool(enabled)

    yaml_path = _find_config_yaml()
    if yaml_path is None:
        logger.warning("config.yaml not found — entropy rule change applied in-memory only (not persisted).")
        return False

    try:
        text = yaml_path.read_text(encoding="utf-8")
    except Exception as exc:
        logger.warning("Failed to read config.yaml for saving entropy settings: %s", exc)
        return False

    if score is not None:
        text = _patch_scalar_in_section(text, "entropy", "score", str(int(score)), r'\d+')
    if enabled is not None:
        text = _patch_scalar_in_section(text, "entropy", "enabled", str(bool(enabled)).lower(), r'true|false')

    try:
        yaml_path.write_text(text, encoding="utf-8")
    except Exception as exc:
        logger.warning("Failed to write config.yaml with updated entropy settings: %s", exc)
        return False

    logger.info("Persisted entropy rule settings to %s", yaml_path)
    return True


# Apply YAML config at import time so the first call to get_config() is
# already populated with the user's settings.
reload_config()
