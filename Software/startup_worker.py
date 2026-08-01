"""Threaded startup worker for RDRS initialization pipeline."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict

from PyQt5.QtCore import QObject, pyqtSignal

from config import reload_config, get_config
from database import get_metadata_db, get_logs_db, get_alerts_db
from entropy_loader import build_entropy_cache

logger = logging.getLogger(__name__)


class StartupWorker(QObject):
    """Executes startup initialization steps off the GUI thread."""

    step_started = pyqtSignal(int, int, str, str)
    step_completed = pyqtSignal(str, str)
    overall_progress = pyqtSignal(int)
    entropy_progress = pyqtSignal(int, int, str, int)
    failed = pyqtSignal(str, str)
    succeeded = pyqtSignal(dict)
    finished = pyqtSignal()

    def __init__(self, *, entropy_dir: Path, file_monitor_dir: Path) -> None:
        super().__init__()
        self._entropy_dir = Path(entropy_dir).expanduser()
        self._file_monitor_dir = Path(file_monitor_dir).expanduser()
        self._total_steps = 8

    def run(self) -> None:
        """Execute all startup tasks sequentially."""
        try:
            ctx: Dict[str, Any] = {}
            self._run_step(1, "Loading Configuration", "Loading config.yaml", self._step_load_config, ctx)
            self._run_step(2, "Initializing Settings", "Applying runtime settings", self._step_init_settings, ctx)
            self._run_step(3, "Connecting Database", "Opening SQLite databases", self._step_connect_db, ctx)
            self._run_step(4, "Loading Previous Logs", "Reading persisted monitoring history", self._step_load_logs, ctx)
            self._run_step(5, "Building Entropy Database", "Scanning files for entropy cache", self._step_build_entropy, ctx)
            self._run_step(6, "Initializing Monitoring Modules", "Preparing monitor modules", self._step_init_modules, ctx)
            self._run_step(7, "Verifying Modules", "Verifying module readiness", self._step_verify_modules, ctx)
            self._run_step(8, "Launching Dashboard", "Finalizing startup", self._step_launch_dashboard, ctx)

            self.succeeded.emit(
                {
                    "entropy_dir": str(self._entropy_dir),
                    "file_monitor_dir": str(self._file_monitor_dir),
                    "logs_loaded": ctx.get("logs_loaded", 0),
                    "entropy_total": ctx.get("entropy_total", 0),
                    "entropy_processed": ctx.get("entropy_processed", 0),
                }
            )
        except Exception as exc:
            self.failed.emit("Initialization", str(exc))
        finally:
            self.finished.emit()

    def _run_step(self, index: int, title: str, status: str, fn, ctx: Dict[str, Any]) -> None:
        self.step_started.emit(index, self._total_steps, title, status)
        message = fn(ctx)
        self.step_completed.emit(title, message)
        self.overall_progress.emit(int((index / self._total_steps) * 100))

    def _step_load_config(self, ctx: Dict[str, Any]) -> str:
        reload_config()
        cfg = get_config()
        ctx["config"] = cfg
        return "Completed"

    def _step_init_settings(self, ctx: Dict[str, Any]) -> str:
        cfg = ctx["config"]
        # Consume values to ensure all expected sections are available early.
        _ = cfg.monitoring.file_monitor_directory
        _ = cfg.entropy.threshold
        _ = cfg.detection.rule_weights
        return "Completed"

    def _step_connect_db(self, ctx: Dict[str, Any]) -> str:
        metadata_db = get_metadata_db()
        logs_db = get_logs_db()
        alerts_db = get_alerts_db()
        ctx["metadata_db"] = metadata_db
        ctx["logs_db"] = logs_db
        ctx["alerts_db"] = alerts_db
        return "Connected"

    def _step_load_logs(self, ctx: Dict[str, Any]) -> str:
        logs_db = ctx["logs_db"]
        count = int(logs_db.count_events())
        ctx["logs_loaded"] = count
        return f"Loaded {count} log entries"

    def _step_build_entropy(self, ctx: Dict[str, Any]) -> str:
        cfg = ctx["config"]
        metadata_db = ctx["metadata_db"]

        summary = build_entropy_cache(
            metadata_db=metadata_db,
            roots=[self._entropy_dir],
            allowed_extensions=set(cfg.entropy.file_extensions),
            sample_size_bytes=cfg.entropy.sample_size_bytes,
            progress_callback=self.entropy_progress.emit,
        )
        ctx["entropy_total"] = summary.total_files
        ctx["entropy_processed"] = summary.processed_files
        self._persist_initial_entropy_baseline(metadata_db, ctx)
        return f"Scanned {summary.processed_files} / {summary.total_files} files"

    def _persist_initial_entropy_baseline(self, metadata_db, ctx: Dict[str, Any]) -> None:
        """Compute and persist startup baseline values for score-50 validation."""
        rows = metadata_db.get_entropy_existing()
        entropy_values = [
            float(row["entropy"])
            for row in rows
            if row["entropy"] is not None
        ]
        if entropy_values:
            initial_average_entropy = sum(entropy_values) / len(entropy_values)
            initial_max_entropy = max(entropy_values)
        else:
            initial_average_entropy = None
            initial_max_entropy = None

        metadata_db.set_runtime_entropy_baseline(
            initial_average_entropy=initial_average_entropy,
            initial_max_entropy=initial_max_entropy,
            baseline_file_count=len(entropy_values),
            source_roots=str(self._entropy_dir),
        )

        ctx["initial_average_entropy"] = initial_average_entropy
        ctx["initial_max_entropy"] = initial_max_entropy
        ctx["baseline_file_count"] = len(entropy_values)

        logger.debug(
            "Entropy baseline initialized (avg=%s, max=%s, files=%s, root=%s)",
            f"{initial_average_entropy:.6f}" if initial_average_entropy is not None else "None",
            f"{initial_max_entropy:.6f}" if initial_max_entropy is not None else "None",
            len(entropy_values),
            self._entropy_dir,
        )

    def _step_init_modules(self, ctx: Dict[str, Any]) -> str:
        # Importing validates that monitor modules are available.
        from monitor.session import MonitorSession  # noqa: F401
        from monitor.filesystem_monitor import FileSystemMonitor  # noqa: F401

        return "Ready"

    def _step_verify_modules(self, ctx: Dict[str, Any]) -> str:
        ok = all(ctx.get(name) is not None for name in ("metadata_db", "logs_db", "alerts_db"))
        if not ok:
            raise RuntimeError("One or more database modules are not ready")
        if not self._file_monitor_dir.exists():
            raise RuntimeError(f"File monitoring directory does not exist: {self._file_monitor_dir}")
        if not self._entropy_dir.exists():
            raise RuntimeError(f"Entropy monitoring directory does not exist: {self._entropy_dir}")
        return "All modules ready"

    def _step_launch_dashboard(self, ctx: Dict[str, Any]) -> str:
        return "Ready to launch"
