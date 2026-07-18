"""Compatibility shim for the entropy loader module used by tests and callers."""

from entropy_loader import (
    build_entropy_cache,
    rescan_specific_files,
    EntropyBuildWorker,
    EntropyRescanWorker,
)

__all__ = [
    "build_entropy_cache",
    "rescan_specific_files",
    "EntropyBuildWorker",
    "EntropyRescanWorker",
]
