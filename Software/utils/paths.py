"""Cross-platform path utilities for frozen and development environments.

This module provides helpers to resolve asset and log directories correctly
whether the application is running from source or as a PyInstaller bundle.
"""

import sys
from pathlib import Path


def get_base_dir() -> Path:
    """Return the base directory for the application.
    
    This handles both development (source) and PyInstaller frozen execution:
    - Frozen mode: Returns sys._MEIPASS (bundle extraction directory)
    - Source mode: Returns the directory containing this module's parent
    
    Returns:
        Path object pointing to the base application directory.
    """
    if getattr(sys, "frozen", False):
        # Running as PyInstaller executable
        # sys._MEIPASS is set by PyInstaller to the bundle extraction directory
        return Path(sys._MEIPASS)
    else:
        # Running as source script
        # Return the Software/ directory (parent of utils/)
        return Path(__file__).resolve().parent.parent


def get_log_dir() -> Path:
    """Return the directory for log files.
    
    Creates the directory if it doesn't exist.
    
    Returns:
        Path object pointing to the logs directory.
    """
    log_dir = get_base_dir() / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir


def get_config_dir() -> Path:
    """Return the directory for configuration files.
    
    Creates the directory if it doesn't exist.
    
    Returns:
        Path object pointing to the config directory.
    """
    config_dir = get_base_dir() / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


def is_frozen() -> bool:
    """Check whether the application is running as a PyInstaller bundle.
    
    Returns:
        True if running from a frozen bundle, False if running from source.
    """
    return getattr(sys, "frozen", False)
