"""Entropy scan helpers for startup baseline and on-demand validation.

This module computes aggregate entropy values only. It does not persist per-file
entropy rows.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Sequence, Set

try:
    from PyQt5.QtCore import QObject, pyqtSignal
except ImportError:
    class QObject:  # type: ignore[override]
        pass

    class _NullSignal:
        def emit(self, *args, **kwargs) -> None:
            return

    def pyqtSignal(*args, **kwargs):  # type: ignore[override]
        return _NullSignal()

from entropy.calculator import calculate_entropy
from database.metadata_db import MetadataDatabase


@dataclass(frozen=True)
class EntropyLoadSummary:
    """Result of an aggregate entropy scan."""

    total_files: int
    processed_files: int
    average_entropy: Optional[float]


def _iter_candidate_files(roots: Sequence[Path], allowed_extensions: Set[str]):
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
            for file_name in files:
                candidate = Path(dirpath) / file_name
                if candidate.suffix.lower().lstrip(".") in normalized_ext:
                    yield candidate


def build_entropy_cache(
    *,
    metadata_db: MetadataDatabase,
    roots: Sequence[Path],
    allowed_extensions: Set[str],
    sample_size_bytes: int,
    progress_callback: Optional[Callable[[int, int, str, int], None]] = None,
) -> EntropyLoadSummary:
    """Compute startup baseline average entropy from the configured scope.

    Despite the historical function name, this now performs aggregate-only
    scanning and stores no per-file entropy data.
    """
    files = [path for path in _iter_candidate_files(roots, allowed_extensions) if path.exists() and path.is_file()]
    total = len(files)
    if progress_callback is not None:
        progress_callback(0, total, "", 0)

    entropy_values = []
    for index, path in enumerate(files, start=1):
        value = calculate_entropy(path, sample_size_bytes)
        if value is not None:
            entropy_values.append(float(value))
        if progress_callback is not None:
            percent = int((index / total) * 100) if total > 0 else 100
            progress_callback(index, total, path.name, percent)

    average = (sum(entropy_values) / len(entropy_values)) if entropy_values else None
    metadata_db.set_runtime_entropy_baseline(
        average_entropy=average,
        file_count=len(entropy_values),
        source_roots=",".join(str(Path(root).expanduser()) for root in roots),
    )

    if progress_callback is not None and total == 0:
        progress_callback(0, 0, "", 100)

    return EntropyLoadSummary(
        total_files=total,
        processed_files=len(entropy_values),
        average_entropy=average,
    )


def rescan_specific_files(
    *,
    metadata_db: MetadataDatabase,
    files_to_scan,
    allowed_extensions: Set[str],
    sample_size_bytes: int,
    progress_callback: Optional[Callable[[int, int, str, int], None]] = None,
) -> EntropyLoadSummary:
    """Compatibility API for targeted scans using aggregate-only persistence."""
    roots = [Path(path) for path in files_to_scan]
    return build_entropy_cache(
        metadata_db=metadata_db,
        roots=roots,
        allowed_extensions=allowed_extensions,
        sample_size_bytes=sample_size_bytes,
        progress_callback=progress_callback,
    )


class EntropyBuildWorker(QObject):
    """Qt worker for startup baseline scan execution."""

    progress = pyqtSignal(int, int, str, int)
    completed = pyqtSignal(int, int, float)
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
                float(summary.average_entropy or 0.0),
            )
        except Exception as exc:
            self.failed.emit(str(exc))


class EntropyRescanWorker(QObject):
    """Compatibility worker retained for imports; performs the same aggregate scan."""

    progress = pyqtSignal(int, int, str, int)
    completed = pyqtSignal(int, int, float)
    failed = pyqtSignal(str)

    def __init__(
        self,
        *,
        metadata_db: MetadataDatabase,
        files_to_scan,
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
            roots = []
            for path in self._files_to_scan:
                roots.append(Path(path))
            summary = build_entropy_cache(
                metadata_db=self._metadata_db,
                roots=roots,
                allowed_extensions=self._allowed_extensions,
                sample_size_bytes=self._sample_size_bytes,
                progress_callback=self.progress.emit,
            )
            self.completed.emit(
                summary.total_files,
                summary.processed_files,
                float(summary.average_entropy or 0.0),
            )
        except Exception as exc:
            self.failed.emit(str(exc))
