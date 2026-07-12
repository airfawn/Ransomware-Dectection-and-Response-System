"""Filesystem monitor module for RDRS.

This module provides a class that watches a target directory for file creation
and deletion events and prints enriched event details to the terminal.
"""

import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

import psutil
from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileDeletedEvent
from watchdog.observers import Observer


@dataclass(frozen=True)
class ProcessMetadata:
    """Process metadata captured for an event."""

    pid: Optional[int]
    name: Optional[str]
    executable: Optional[str]
    parent_name: Optional[str]


class ProcessResolver:
    """Resolve process metadata for a filesystem event.

    The filesystem event itself does not carry a PID, so this class performs a
    best-effort lookup using psutil open file handles.
    """

    @staticmethod
    def resolve(path: Path) -> ProcessMetadata:
        """Return process metadata matching an open file handle for the path."""
        normalized_target = ProcessResolver._normalize_path(path)

        for process in psutil.process_iter(["pid", "name", "exe", "ppid"]):
            try:
                for open_file in process.open_files():
                    if ProcessResolver._normalize_path(Path(open_file.path)) == normalized_target:
                        parent_name = ProcessResolver._get_parent_name(process)
                        return ProcessMetadata(
                            pid=process.pid,
                            name=process.name(),
                            executable=process.exe() if process.exe() else None,
                            parent_name=parent_name,
                        )
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
            except Exception:
                continue

        # If no process owns the file, return unknown metadata.
        return ProcessMetadata(pid=None, name=None, executable=None, parent_name=None)

    @staticmethod
    def _normalize_path(path: Path) -> str:
        """Normalize filesystem paths for comparison."""
        try:
            normalized = os.path.normcase(str(path.resolve()))
        except Exception:
            normalized = os.path.normcase(str(path.absolute()))
        return normalized

    @staticmethod
    def _get_parent_name(process: psutil.Process) -> Optional[str]:
        """Return the parent process name or None if unavailable."""
        try:
            parent = process.parent()
            return parent.name() if parent else None
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return None


class FileSystemMonitorHandler(FileSystemEventHandler):
    """Watchdog event handler specialized for file creation and deletion."""

    def __init__(self, logger):
        super().__init__()
        self.logger = logger

    def on_created(self, event: FileCreatedEvent) -> None:
        """Handle file creation events."""
        if event.is_directory:
            return
        self._report_event("FILE CREATED", event.src_path)

    def on_deleted(self, event: FileDeletedEvent) -> None:
        """Handle file deletion events."""
        if event.is_directory:
            return
        self._report_event("FILE DELETED", event.src_path)

    def _report_event(self, event_type: str, src_path: str) -> None:
        """Format and print an event report to the terminal."""
        try:
            path = Path(src_path)
            event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            process_metadata = ProcessResolver.resolve(path)

            output = ["=" * 38]
            output.append(f"EVENT: {event_type}")
            output.append("")
            output.append("Time:")
            output.append(event_time)
            output.append("")
            output.append("File:")
            output.append(str(path.resolve() if path.exists() else path.absolute()))
            output.append("")
            output.append("File Name:")
            output.append(path.name)
            output.append("")
            output.append("Process:")
            output.append(process_metadata.name or "Unknown")
            output.append("")
            output.append("PID:")
            output.append(str(process_metadata.pid) if process_metadata.pid else "Unknown")
            output.append("")
            output.append("Executable:")
            output.append(process_metadata.executable or "Unknown")
            output.append("")
            output.append("Parent Process:")
            output.append(process_metadata.parent_name or "Unknown")
            output.append("=" * 38)

            self.logger.info("\n" + "\n".join(output))
        except Exception as exc:
            self.logger.error("Failed to report filesystem event for %s: %s", src_path, exc)


class FileSystemMonitor:
    """Main monitor class for watching filesystem changes."""

    def __init__(self, target_path: Path, recursive: bool, logger):
        self.target_path = target_path
        self.recursive = recursive
        self.logger = logger
        self.observer = Observer()
        self.handler = FileSystemMonitorHandler(logger=self.logger)

    def start(self) -> None:
        """Start watching the configured path."""
        if not self.target_path.exists():
            raise FileNotFoundError(f"Monitor path does not exist: {self.target_path}")

        self.observer.schedule(self.handler, str(self.target_path), recursive=self.recursive)
        self.observer.start()
        self.logger.info("Monitoring %s (recursive=%s)", self.target_path, self.recursive)

    def stop(self) -> None:
        """Stop the observer cleanly."""
        self.observer.stop()
        self.observer.join(timeout=5)

    def join(self) -> None:
        """Wait for the monitor thread until stopped."""
        try:
            while self.observer.is_alive():
                self.observer.join(timeout=1)
        except KeyboardInterrupt:
            self.stop()
