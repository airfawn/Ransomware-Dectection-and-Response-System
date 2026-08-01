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


def _iter_all_files(roots: Sequence[Path]) -> Iterable[Path]:
    """Yield all files under roots regardless of extension."""
    for root in roots:
        expanded = Path(root).expanduser()
        if not expanded.exists():
            continue
        if expanded.is_file():
            yield expanded
            continue

        for dirpath, _, files in os.walk(expanded):
            for name in files:
                yield Path(dirpath) / name


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
    normalized_ext = {ext.lower().lstrip(".") for ext in allowed_extensions}
    all_current_files = [path for path in _iter_all_files(roots) if path.exists() and path.is_file()]

    pre_reset_rows = []
    try:
        pre_reset_rows = metadata_db.get_all_existing()
    except Exception:
        pre_reset_rows = []

    entropy_cache_rows = []
    try:
        entropy_cache_rows = metadata_db.get_entropy_existing()
    except Exception:
        entropy_cache_rows = []

    existing_by_id = {}
    existing_by_path = {}
    existing_paths = set()
    for row in pre_reset_rows:
        row_path = row["file_path"]
        row_id = row["file_id"] if "file_id" in row.keys() else None
        if row_path:
            existing_paths.add(row_path)
            existing_by_path[row_path] = row
        if row_id:
            existing_by_id[row_id] = row

    entropy_cache_by_path = {}
    for row in entropy_cache_rows:
        path_key = row["path"]
        if path_key:
            entropy_cache_by_path[path_key] = row

    candidates: list[Path] = []
    for path in all_current_files:
        resolved_path = str(path.resolve())
        ext = path.suffix.lower().lstrip(".")
        file_id = _build_file_identity(path)
        known_tracked = resolved_path in existing_paths or (file_id is not None and file_id in existing_by_id)
        if ext in normalized_ext or known_tracked:
            candidates.append(path)

    removed_records: list[tuple[str, Optional[str]]] = []
    added_files = 0
    updated_files = 0
    processed = 0
    total = len(candidates)
    seen_ids: Set[str] = set()
    seen_paths: Set[str] = set()

    if progress_callback is not None:
        progress_callback(0, total, "", 0)

    logger.info("[ENTROPY_SCAN][startup] starting filesystem rebuild roots=%s files=%s", roots, total)

    for idx, path in enumerate(candidates, start=1):
        file_name = path.name
        resolved_path = str(path.resolve())
        current_ext = path.suffix.lower().lstrip(".")
        file_id = _build_file_identity(path)

        existing_row = None
        if file_id and file_id in existing_by_id:
            existing_row = existing_by_id[file_id]
        elif resolved_path in existing_by_path:
            existing_row = existing_by_path[resolved_path]

        baseline_entropy = None
        previous_entropy = None
        original_path = None
        if existing_row is not None:
            previous_entropy = existing_row["current_entropy"]
            baseline_entropy = existing_row["baseline_entropy"] if "baseline_entropy" in existing_row.keys() else None
            original_path = existing_row["file_path"]
        try:
            stat = path.stat()
            size = stat.st_size
            mtime = stat.st_mtime
        except OSError as exc:
            logger.warning("[ENTROPY_SCAN][inaccessible] file=%s error=%s", resolved_path, exc)
            size = None
            mtime = None

        entropy_value = None
        reused_entropy = False
        if size is not None and mtime is not None:
            cached = entropy_cache_by_path.get(resolved_path)
            if (
                cached is not None
                and cached["entropy"] is not None
                and int(cached["file_size"] or -1) == int(size)
                and float(cached["modified_time"] or -1.0) == float(mtime)
            ):
                entropy_value = float(cached["entropy"])
                reused_entropy = True
            else:
                try:
                    entropy_value = calculate_entropy(path, sample_size_bytes)
                except Exception as exc:
                    logger.warning("[ENTROPY_SCAN][scan_failed] file=%s error=%s", resolved_path, exc)

        if entropy_value is None:
            logger.warning("[ENTROPY_SCAN][skip] file=%s could not be read", resolved_path)
        else:
            if file_id:
                seen_ids.add(file_id)
            seen_paths.add(resolved_path)

            if original_path and original_path != resolved_path:
                try:
                    metadata_db.rename_entropy_path(original_path, resolved_path)
                except Exception:
                    pass

            metadata_db.upsert_entropy_cache(
                path=resolved_path,
                entropy=entropy_value,
                file_size=size,
                modified_time=mtime,
                exists=True,
            )
            updated = False
            if file_id:
                updated = metadata_db.update_file_by_identifier(
                    file_id=file_id,
                    file_path=resolved_path,
                    file_name=file_name,
                    current_entropy=entropy_value,
                    previous_entropy=previous_entropy,
                    file_size=size,
                    last_modified_ts=mtime,
                    exists=True,
                )

            if not updated:
                metadata_db.upsert_file(
                    file_path=resolved_path,
                    file_name=file_name,
                    current_entropy=entropy_value,
                    previous_entropy=previous_entropy,
                    file_size=size,
                    last_modified_ts=mtime,
                    file_id=file_id,
                    baseline_entropy=baseline_entropy if baseline_entropy is not None else entropy_value,
                    first_seen=existing_row["first_seen"] if existing_row is not None and "first_seen" in existing_row.keys() else None,
                )
            processed += 1
            if existing_row is None:
                added_files += 1
            else:
                updated_files += 1

            if file_id:
                metadata_db.upsert_entropy_identity(file_id, resolved_path, exists=True)

            if reused_entropy:
                logger.debug(
                    "[ENTROPY_SCAN][cache_hit] file=%s size=%s mtime=%.6f",
                    resolved_path,
                    size,
                    float(mtime),
                )


        percent = int((idx / total) * 100) if total > 0 else 100
        if progress_callback is not None:
            progress_callback(idx, total, file_name, percent)

    for row in pre_reset_rows:
        row_path = row["file_path"]
        row_id = row["file_id"] if "file_id" in row.keys() else None
        if row_id and row_id in seen_ids:
            continue
        if row_path in seen_paths:
            continue
        if row_path and Path(row_path).exists():
            continue
        removed_records.append((row_path, row_id))

    dedup_records: dict[str, Optional[str]] = {}
    for removed_path, removed_id in removed_records:
        dedup_records[removed_path] = removed_id

    for removed_path, removed_id in sorted(dedup_records.items()):
        try:
            metadata_db.delete_file(removed_path)
            metadata_db.delete_entropy_cache(removed_path)
            if removed_id:
                metadata_db.mark_entropy_identity_deleted(removed_id)
        except Exception as exc:
            logger.warning("[ENTROPY_SCAN][delete_failed] file=%s error=%s", removed_path, exc)

    duration = time.time() - start
    logger.info(
        "[ENTROPY_SCAN][completed] files=%s added=%s removed=%s updated=%s duration=%.2fs",
        total,
        added_files,
        len(dedup_records),
        updated_files,
        duration,
    )

    if progress_callback is not None and total == 0:
        progress_callback(0, 0, "", 100)

    return EntropyLoadSummary(
        total_files=total,
        processed_files=processed,
        added_files=added_files,
        removed_files=len(dedup_records),
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
