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
from typing import Dict, Any, List, Optional
import sys
import logging

from utils.paths import get_base_dir, get_log_dir, get_config_dir

logger = logging.getLogger(__name__)


@dataclass
class MonitoringConfig:
    """Configuration for filesystem monitoring."""
    
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
    
    # Scoring weights
    rule_weights: Dict[str, int] = field(default_factory=lambda: {
        "Rule1_FileBurst": 20,
        "Rule2_MultipleDirectories": 30,
        "Rule3_YoungProcessBurst": 10,
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

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary for serialization."""
        return {
            "monitoring": self.monitoring.__dict__,
            "detection": {
                **self.detection.__dict__,
                "rule_weights": self.detection.rule_weights.copy(),
            },
            "gui": {
                **self.gui.__dict__,
                "classification_colors": self.gui.classification_colors.copy(),
            },
            "logging": self.logging.__dict__,
            "entropy": self.entropy.__dict__,
            "database": self.database.__dict__,
            "alerts": self.alerts.__dict__,
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

    # -- entropy section -----------------------------------------------------
    ent = data.get("entropy") or {}
    if "sample_size_mb" in ent:
        cfg.entropy.sample_size_bytes = int(ent["sample_size_mb"]) * 1024 * 1024
    if "threshold" in ent:
        cfg.entropy.threshold = float(ent["threshold"])
    if "score" in ent:
        cfg.entropy.score = int(ent["score"])
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
        _apply_yaml_to_config(_config, data)
        logger.debug("Loaded config.yaml from %s", yaml_path)
    else:
        logger.debug("config.yaml not found — using built-in defaults.")


# Apply YAML config at import time so the first call to get_config() is
# already populated with the user's settings.
reload_config()
