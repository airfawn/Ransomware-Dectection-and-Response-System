#!/usr/bin/env python3
"""Entry point for the RDRS filesystem monitoring module."""

import argparse
from pathlib import Path

from monitor.filesystem_monitor import FileSystemMonitor
from utils.logger import setup_logger


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments for the monitoring application."""
    parser = argparse.ArgumentParser(
        description="RDRS File System Monitor: watch file create/delete/modify events in real time."
    )
    parser.add_argument(
        "--path",
        type=Path,
        default=Path.home(),
        help="Directory to monitor. Defaults to the current user's home directory.",
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Monitor directories recursively.",
    )
    return parser.parse_args()


def run_monitor(target_path: Path, recursive: bool, logger=None) -> None:
    """Create and start the filesystem monitor.

    Args:
        target_path: Directory to monitor.
        recursive: Whether to watch subdirectories.
        logger: Optional logger instance. A configured default logger is created
            when one is not supplied.
    """
    monitor_logger = logger or setup_logger()
    monitor = FileSystemMonitor(target_path=target_path, recursive=recursive, logger=monitor_logger)

    monitor_logger.info("Starting RDRS filesystem monitor for %s", target_path)
    try:
        monitor.start()
        monitor.join()
    except KeyboardInterrupt:
        monitor_logger.info("Stopping monitor due to user interrupt.")
    finally:
        monitor.stop()


def main() -> None:
    """Parse CLI arguments and start the monitor."""
    args = parse_args()
    run_monitor(args.path, args.recursive)


if __name__ == "__main__":
    main()
