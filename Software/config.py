"""Centralized configuration for RDRS.

This module provides a single source of truth for all configuration parameters,
thresholds, and limits used throughout the application. It supports both
development and production environments and is designed for easy tuning.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Any
import sys

from utils.paths import get_base_dir, get_log_dir, get_config_dir


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
class AppConfig:
    """Master configuration container for the entire application."""
    
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    gui: GUIConfig = field(default_factory=GUIConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    paths: PathConfig = field(default_factory=PathConfig)
    
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
        }


# Global configuration instance
_config: AppConfig = AppConfig()


def get_config() -> AppConfig:
    """Return the global configuration instance.
    
    Returns:
        The application configuration object.
    """
    return _config


def reload_config() -> None:
    """Reload configuration from defaults (future: from file)."""
    global _config
    _config = AppConfig()
