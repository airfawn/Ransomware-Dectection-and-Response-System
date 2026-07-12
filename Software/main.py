#!/usr/bin/env python3
"""Entry point for the RDRS filesystem monitoring module."""

import argparse
from pathlib import Path

from monitor.filesystem_monitor import FileSystemMonitor
from utils.logger import setup_logger


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments for the monitoring application."""
    parser = argparse.ArgumentParser(
        description="RDRS File System Monitor: watch file create/delete events in real time."
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


def main() -> None:
    """Create and start the filesystem monitor."""
    args = parse_args()
    logger = setup_logger()
    monitor = FileSystemMonitor(target_path=args.path, recursive=args.recursive, logger=logger)

    logger.info("Starting RDRS filesystem monitor for %s", args.path)
    try:
        monitor.start()
        monitor.join()
    except KeyboardInterrupt:
        logger.info("Stopping monitor due to user interrupt.")
    finally:
        monitor.stop()


if __name__ == "__main__":
    main()
