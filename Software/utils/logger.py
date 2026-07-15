"""Logger helper used by the RDRS monitor.

This module provides enhanced logging with support for both console and file output,
configurable levels, and proper error handling.
"""

import logging
import logging.handlers
from pathlib import Path
from typing import Optional

try:
    from config import get_config
    _CONFIG_AVAILABLE = True
except ImportError:
    _CONFIG_AVAILABLE = False


def setup_logger(
    name: str = "rdrs",
    log_level: Optional[str] = None,
    log_to_file: Optional[bool] = None,
    log_file_path: Optional[Path] = None,
) -> logging.Logger:
    """Create a logger configured for console and optional file output.
    
    Args:
        name: Logger name (default: "rdrs").
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_to_file: Whether to enable file logging.
        log_file_path: Path to the log file (auto-generated if None).
    
    Returns:
        Configured logger instance.
    """
    logger = logging.getLogger(name)
    
    # Prevent duplicate handlers
    if logger.handlers:
        return logger
    
    # Load configuration
    if _CONFIG_AVAILABLE:
        config = get_config().logging
        log_level = log_level or config.log_level
        log_to_file = log_to_file if log_to_file is not None else config.log_to_file
        
        if log_to_file and log_file_path is None:
            from config import PathConfig
            log_dir = PathConfig.get_log_dir()
            log_file_path = log_dir / config.log_file_name
        
        console_format = config.console_log_format
        file_format = config.file_log_format
        date_format = config.date_format
        max_bytes = config.log_file_max_bytes
        backup_count = config.log_file_backup_count
    else:
        # Fallback defaults if config unavailable
        log_level = log_level or "INFO"
        log_to_file = log_to_file if log_to_file is not None else False
        console_format = "%(asctime)s %(levelname)s %(message)s"
        file_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        date_format = "%Y-%m-%d %H:%M:%S"
        max_bytes = 10 * 1024 * 1024
        backup_count = 3
    
    # Set log level
    level = getattr(logging, log_level.upper(), logging.INFO)
    logger.setLevel(level)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_formatter = logging.Formatter(fmt=console_format, datefmt=date_format)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler (with rotation)
    if log_to_file and log_file_path:
        try:
            log_file_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.handlers.RotatingFileHandler(
                filename=str(log_file_path),
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding="utf-8",
            )
            file_handler.setLevel(level)
            file_formatter = logging.Formatter(fmt=file_format, datefmt=date_format)
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)
        except Exception as exc:
            logger.error(f"Failed to create file handler for {log_file_path}: {exc}")
    
    return logger


def get_logger(name: str = "rdrs") -> logging.Logger:
    """Get an existing logger or create a new one.
    
    Args:
        name: Logger name.
    
    Returns:
        Logger instance.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        return setup_logger(name)
    return logger
