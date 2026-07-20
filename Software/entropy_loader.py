"""Entropy database loading helpers for startup and on-demand rebuilds.

This module is intentionally independent from GUI widgets and detection logic.
It only performs entropy-cache construction work and emits progress through a
caller-provided callback.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional, Sequence, Set

try:
    from PyQt5.QtCore import QObject, pyqtSignal
    _QT_AVAILABLE = True
except ImportError:
    _QT_AVAILABLE = False

    class QObject:  # type: ignore[override]
        """Fallback QObject shim for non-GUI test environments."""

    class _NullSignal:
        def emit(self, *args, **kwargs) -> None:
            return

    def pyqtSignal(*args, **kwargs):  # type: ignore[override]
        """Fallback signal factory returning a no-op signal."""
        return _NullSignal()

from entropy.calculator import calculate_entropy
from database.metadata_db import MetadataDatabase

logger = logging.getLogger(__name__)


def _build_file_identity(path: Path) -> str:
    """Return stable file identity, preferring filesystem inode/device."""
    try:
        stat = path.stat()
        inode = int(getattr(stat, "st_ino", 0) or 0)
        device = int(getattr(stat, "st_dev", 0) or 0)
        if inode > 0:
            return f"{device}:{inode}"
    except Exception:
        pass
    return f"path:{os.path.normcase(os.path.realpath(str(path)))}"


@dataclass(frozen=True)
class EntropyLoadSummary:
    """Result summary for an entropy database build/rebuild run."""

    total_files: int
    processed_files: int
    added_files: int = 0
    removed_files: int = 0
    updated_files: int = 0


def _iter_candidate_files(roots: Sequence[Path], allowed_extensions: Set[str]) -> Iterable[Path]:
    """Yield files under roots that match allowed extensions."""
    normalized_ext = {ext.lower().lstrip(".") for ext in allowed_extensions}
    for root in roots:
        expanded = Path(root).expanduser()
        if not expanded.exists():
            continue
        if expanded.is_file():
            if expanded.suffix.lower().lstrip(".") in normalized_ext:
                yield expanded
            continue

        for dirpath, _, files in os.walk(expanded):
            for name in files:
                path = Path(dirpath) / name
                if path.suffix.lower().lstrip(".") in normalized_ext:
                    yield path


def count_candidate_files(roots: Sequence[Path], allowed_extensions: Set[str]) -> int:
    """Count files that will be processed for entropy loading."""
    return sum(1 for _ in _iter_candidate_files(roots, allowed_extensions))


def build_entropy_cache(
    *,
    metadata_db: MetadataDatabase,
    roots: Sequence[Path],
    allowed_extensions: Set[str],
    sample_size_bytes: int,
    progress_callback: Optional[Callable[[int, int, str, int], None]] = None,
) -> EntropyLoadSummary:
    """Build/rebuild entropy metadata cache from the filesystem.

    The filesystem is treated as the source of truth. Existing metadata rows
    are updated from fresh entropy calculations and rows for deleted files are
    removed so the database stays aligned with what is currently on disk.
    """
    start = time.time()
    candidates = list(_iter_candidate_files(roots, allowed_extensions))
    current_paths = {str(path.resolve()) for path in candidates if path.exists()}

    # Startup must treat filesystem as source of truth and rebuild from scratch.
    metadata_db.reset_runtime_state()

    try:
        existing_rows = metadata_db.get_all_existing()
        existing_paths = {row["file_path"] for row in existing_rows if row["file_path"]}
    except Exception:
        existing_paths = set()

    removed_paths = sorted(existing_paths - current_paths)
    added_files = 0
    updated_files = 0
    processed = 0
    total = len(candidates)

    if progress_callback is not None:
        progress_callback(0, total, "", 0)

    logger.info("[ENTROPY_SCAN][startup] starting filesystem rebuild roots=%s files=%s", roots, total)

    for idx, path in enumerate(candidates, start=1):
        file_name = path.name
        resolved_path = str(path.resolve())
        try:
            stat = path.stat()
            size = stat.st_size
            mtime = stat.st_mtime
        except OSError as exc:
            logger.warning("[ENTROPY_SCAN][inaccessible] file=%s error=%s", resolved_path, exc)
            size = None
            mtime = None

        previous_record = None
        previous_entropy = None

        entropy_value = None
        if size is not None and mtime is not None:
            try:
                entropy_value = calculate_entropy(path, sample_size_bytes)
            except Exception as exc:
                logger.warning("[ENTROPY_SCAN][scan_failed] file=%s error=%s", resolved_path, exc)

        if entropy_value is None:
            logger.warning("[ENTROPY_SCAN][skip] file=%s could not be read", resolved_path)
        else:
            metadata_db.upsert_entropy_cache(
                path=resolved_path,
                entropy=entropy_value,
                file_size=size,
                modified_time=mtime,
                exists=True,
            )
            metadata_db.upsert_file(
                file_path=resolved_path,
                file_name=file_name,
                current_entropy=entropy_value,
                previous_entropy=previous_entropy,
                file_size=size,
                last_modified_ts=mtime,
                file_id=_build_file_identity(path),
                baseline_entropy=entropy_value,
            )
            processed += 1
            added_files += 1

        percent = int((idx / total) * 100) if total > 0 else 100
        if progress_callback is not None:
            progress_callback(idx, total, file_name, percent)

    for removed_path in removed_paths:
        try:
            metadata_db.delete_file(removed_path)
            metadata_db.delete_entropy_cache(removed_path)
        except Exception as exc:
            logger.warning("[ENTROPY_SCAN][delete_failed] file=%s error=%s", removed_path, exc)

    duration = time.time() - start
    logger.info(
        "[ENTROPY_SCAN][completed] files=%s added=%s removed=%s updated=%s duration=%.2fs",
        total,
        added_files,
        len(removed_paths),
        updated_files,
        duration,
    )

    if progress_callback is not None and total == 0:
        progress_callback(0, 0, "", 100)

    return EntropyLoadSummary(
        total_files=total,
        processed_files=processed,
        added_files=added_files,
        removed_files=len(removed_paths),
        updated_files=updated_files,
    )


def rescan_specific_files(
    *,
    metadata_db: MetadataDatabase,
    files_to_scan: Sequence[Path],
    allowed_extensions: Set[str],
    sample_size_bytes: int,
    progress_callback: Optional[Callable[[int, int, str, int], None]] = None,
) -> EntropyLoadSummary:
    """Recalculate entropy for specific files only."""
    start = time.time()
    normalized_extensions = {ext.lower().lstrip(".") for ext in allowed_extensions}
    current_paths = []
    for path in files_to_scan:
        if not path.exists() or not path.is_file():
            continue
        if path.suffix.lower().lstrip(".") not in normalized_extensions:
            continue
        current_paths.append(path)

    total = len(current_paths)
    if progress_callback is not None:
        progress_callback(0, total, "", 0)

    processed = 0
    updated = 0
    added = 0
    for idx, path in enumerate(current_paths, start=1):
        file_name = path.name
        resolved_path = str(path.resolve())
        try:
            stat = path.stat()
            size = stat.st_size
            mtime = stat.st_mtime
        except OSError as exc:
            logger.warning("[ENTROPY_SCAN][inaccessible] file=%s error=%s", resolved_path, exc)
            continue

        previous_record = metadata_db.get_file(resolved_path)
        previous_entropy = previous_record["current_entropy"] if previous_record is not None else None
        entropy_value = calculate_entropy(path, sample_size_bytes)
        if entropy_value is None:
            continue

        metadata_db.upsert_entropy_cache(
            path=resolved_path,
            entropy=entropy_value,
            file_size=size,
            modified_time=mtime,
            exists=True,
        )
        metadata_db.upsert_file(
            file_path=resolved_path,
            file_name=file_name,
            current_entropy=entropy_value,
            previous_entropy=previous_entropy,
            file_size=size,
            last_modified_ts=mtime,
            file_id=_build_file_identity(path),
        )
        processed += 1
        if previous_record is None:
            added += 1
        else:
            updated += 1

        percent = int((idx / total) * 100) if total > 0 else 100
        if progress_callback is not None:
            progress_callback(idx, total, file_name, percent)

    duration = time.time() - start
    logger.info(
        "[ENTROPY_SCAN][rescanned] files=%s added=%s updated=%s duration=%.2fs",
        total,
        added,
        updated,
        duration,
    )

    if progress_callback is not None and total == 0:
        progress_callback(0, 0, "", 100)

    return EntropyLoadSummary(total_files=total, processed_files=processed, added_files=added, updated_files=updated)


class EntropyBuildWorker(QObject):
    """Qt worker used for background entropy rebuild tasks."""

    progress = pyqtSignal(int, int, str, int)
    completed = pyqtSignal(int, int, int, int, int)
    failed = pyqtSignal(str)

    def __init__(
        self,
        *,
        metadata_db: MetadataDatabase,
        root: Path,
        allowed_extensions: Set[str],
        sample_size_bytes: int,
    ) -> None:
        super().__init__()
        self._metadata_db = metadata_db
        self._root = root
        self._allowed_extensions = allowed_extensions
        self._sample_size_bytes = sample_size_bytes

    def run(self) -> None:
        """Execute cache rebuild in the current worker thread."""
        try:
            summary = build_entropy_cache(
                metadata_db=self._metadata_db,
                roots=[self._root],
                allowed_extensions=self._allowed_extensions,
                sample_size_bytes=self._sample_size_bytes,
                progress_callback=self.progress.emit,
            )
            self.completed.emit(
                summary.total_files,
                summary.processed_files,
                summary.added_files,
                summary.removed_files,
                summary.updated_files,
            )
        except Exception as exc:
            logger.exception("[ENTROPY_SCAN][worker_failed] %s", exc)
            self.failed.emit(str(exc))


class EntropyRescanWorker(QObject):
    """Qt worker used for background rescans of selected files."""

    progress = pyqtSignal(int, int, str, int)
    completed = pyqtSignal(int, int, int, int, int)
    failed = pyqtSignal(str)

    def __init__(
        self,
        *,
        metadata_db: MetadataDatabase,
        files_to_scan: Sequence[Path],
        allowed_extensions: Set[str],
        sample_size_bytes: int,
    ) -> None:
        super().__init__()
        self._metadata_db = metadata_db
        self._files_to_scan = list(files_to_scan)
        self._allowed_extensions = allowed_extensions
        self._sample_size_bytes = sample_size_bytes

    def run(self) -> None:
        try:
            summary = rescan_specific_files(
                metadata_db=self._metadata_db,
                files_to_scan=self._files_to_scan,
                allowed_extensions=self._allowed_extensions,
                sample_size_bytes=self._sample_size_bytes,
                progress_callback=self.progress.emit,
            )
            self.completed.emit(
                summary.total_files,
                summary.processed_files,
                summary.added_files,
                summary.removed_files,
                summary.updated_files,
            )
        except Exception as exc:
            logger.exception("[ENTROPY_SCAN][rescan_failed] %s", exc)
            self.failed.emit(str(exc))
