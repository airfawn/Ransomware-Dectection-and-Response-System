"""Entropy database loading helpers for startup and on-demand rebuilds.

This module is intentionally independent from GUI widgets and detection logic.
It only performs entropy-cache construction work and emits progress through a
caller-provided callback.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional, Sequence, Set

from PyQt5.QtCore import QObject, pyqtSignal

from entropy.calculator import calculate_entropy
from database.metadata_db import MetadataDatabase


@dataclass(frozen=True)
class EntropyLoadSummary:
    """Result summary for an entropy database build/rebuild run."""

    total_files: int
    processed_files: int


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
    """Build/rebuild entropy metadata cache for the selected roots.

    Args:
        metadata_db: Metadata database handle.
        roots: Root directories/files to scan.
        allowed_extensions: Allowed extension set (lowercase, no dot).
        sample_size_bytes: Number of bytes sampled for entropy calculations.
        progress_callback: Optional callback receiving
            ``(current, total, file_name, percent)``.

    Returns:
        EntropyLoadSummary containing total and processed counts.
    """
    # Two-pass approach keeps memory usage stable under large trees while
    # still allowing accurate total progress (required by splash/rebuild UI).
    total = count_candidate_files(roots, allowed_extensions)

    if progress_callback is not None:
        progress_callback(0, total, "", 0)

    processed = 0
    for idx, path in enumerate(_iter_candidate_files(roots, allowed_extensions), start=1):
        file_name = path.name

        try:
            stat = path.stat()
            size = stat.st_size
            mtime = stat.st_mtime
        except OSError:
            size = None
            mtime = None

        # Reuse persisted cache when file metadata is unchanged to avoid
        # repeated entropy calculations during rebuilds.
        entropy_value = None
        if size is not None and mtime is not None:
            cached = metadata_db.get_entropy_record(str(path))
            if (
                cached is not None
                and cached["exists"] == 1
                and cached["file_size"] == size
                and cached["modified_time"] == mtime
                and cached["entropy"] is not None
            ):
                entropy_value = cached["entropy"]

        if entropy_value is None:
            entropy_value = calculate_entropy(path, sample_size_bytes)

        if entropy_value is not None:
            previous_record = metadata_db.get_file(str(path))
            previous_entropy = (
                previous_record["current_entropy"] if previous_record is not None else None
            )

            metadata_db.upsert_entropy_cache(
                path=str(path),
                entropy=entropy_value,
                file_size=size,
                modified_time=mtime,
                exists=True,
            )
            metadata_db.upsert_file(
                file_path=str(path),
                file_name=file_name,
                current_entropy=entropy_value,
                previous_entropy=previous_entropy,
                file_size=size,
                last_modified_ts=mtime,
            )
            processed += 1

        percent = int((idx / total) * 100) if total > 0 else 100
        if progress_callback is not None:
            progress_callback(idx, total, file_name, percent)

    if progress_callback is not None and total == 0:
        progress_callback(0, 0, "", 100)

    return EntropyLoadSummary(total_files=total, processed_files=processed)


class EntropyBuildWorker(QObject):
    """Qt worker used for background entropy rebuild tasks."""

    progress = pyqtSignal(int, int, str, int)
    completed = pyqtSignal(int, int)
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
            self.completed.emit(summary.total_files, summary.processed_files)
        except Exception as exc:
            self.failed.emit(str(exc))
