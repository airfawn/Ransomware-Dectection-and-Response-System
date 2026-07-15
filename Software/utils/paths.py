"""Cross-platform path utilities for frozen and development environments.

This module provides helpers to resolve asset and log directories correctly
whether the application is running from source or as a PyInstaller bundle.

Key distinction:
  - get_base_dir()  → bundled read-only assets (inside sys._MEIPASS or source tree)
  - get_data_dir()  → writable user data (databases, logs) that MUST survive
                      across PyInstaller runs.  Never placed inside the bundle.
"""

import sys
import platform
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


def get_data_dir() -> Path:
    """Return the platform-appropriate writable user data directory for RDRS.

    This directory stores persistent, writable data (SQLite databases, user logs)
    that must survive between PyInstaller runs.  It is NEVER located inside the
    bundle itself, because PyInstaller's onefile mode extracts to a temp directory
    that is deleted on exit.

    Platform locations:
      - macOS  : ~/Library/Application Support/RDRS/
      - Windows: %APPDATA%/RDRS/          (C:/Users/<user>/AppData/Roaming/RDRS/)
      - Linux  : ~/.local/share/RDRS/

    The directory is created automatically if it does not exist.

    Returns:
        Path to the writable RDRS data directory.
    """
    system = platform.system()
    if system == "Darwin":
        base = Path.home() / "Library" / "Application Support" / "RDRS"
    elif system == "Windows":
        import os
        appdata = os.environ.get("APPDATA")
        if appdata:
            base = Path(appdata) / "RDRS"
        else:
            base = Path.home() / "AppData" / "Roaming" / "RDRS"
    else:
        # Linux / other UNIX
        base = Path.home() / ".local" / "share" / "RDRS"

    base.mkdir(parents=True, exist_ok=True)
    return base


def is_frozen() -> bool:
    """Check whether the application is running as a PyInstaller bundle.
    
    Returns:
        True if running from a frozen bundle, False if running from source.
    """
    return getattr(sys, "frozen", False)
