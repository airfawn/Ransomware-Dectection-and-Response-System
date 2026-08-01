#!/usr/bin/env python3
"""Safe Windows-focused entropy-change simulator for RDRS validation.

This module is a controlled test harness. It only touches files inside its
own temporary sandbox and never performs networking, persistence, privilege
changes, or system-wide operations.
"""

from __future__ import annotations

import argparse
import os
import random
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional


@dataclass(frozen=True)
class SimulatorReport:
    root: str
    baseline_files_created: int
    modified_files: int
    mode: str


class SafeEntropyChangeSimulator:
    """Create and modify test files inside a strict temporary sandbox only."""

    def __init__(
        self,
        *,
        preserve_directory: bool = False,
        seed: int = 1337,
        file_count: int = 25,
    ) -> None:
        self._preserve_directory = bool(preserve_directory)
        self._seed = int(seed)
        self._file_count = max(1, int(file_count))
        self._temp_dir_obj: Optional[tempfile.TemporaryDirectory[str]] = None
        self.root: Optional[Path] = None
        self._files: List[Path] = []
        self._touched_paths: set[str] = set()

    @property
    def files(self) -> List[Path]:
        return list(self._files)

    def create_sandbox(self) -> Path:
        """Create a new temporary sandbox directory for simulation."""
        if self.root is not None:
            return self.root
        self._temp_dir_obj = tempfile.TemporaryDirectory(prefix="rdrs_entropy_sim_")
        self.root = Path(self._temp_dir_obj.name) / "RDRS_entropy_test"
        self.root.mkdir(parents=True, exist_ok=True)
        return self.root

    def create_low_entropy_baseline_files(self) -> List[Path]:
        """Create deterministic low-entropy baseline files in the sandbox."""
        root = self.create_sandbox()
        created: List[Path] = []
        line = "RDRS_BASELINE_RECORD|section=alpha|value=0000000000\n"
        payload = (line * 256).encode("utf-8")
        for idx in range(self._file_count):
            file_path = root / f"file_{idx:02d}.txt"
            self._assert_inside_sandbox(file_path)
            file_path.write_bytes(payload)
            created.append(file_path)
            self._remember_touch(file_path)
        self._files = created
        return list(created)

    def modify_files_high_entropy(self, *, count: Optional[int] = None, bytes_per_file: int = 4096) -> List[Path]:
        """Overwrite selected files with deterministic pseudo-random bytes."""
        selected = self._select_files(count)
        rng = random.Random(self._seed)
        modified: List[Path] = []
        for path in selected:
            self._assert_inside_sandbox(path)
            data = bytes(rng.getrandbits(8) for _ in range(max(1, int(bytes_per_file))))
            path.write_bytes(data)
            modified.append(path)
            self._remember_touch(path)
        return modified

    def modify_files_low_entropy(self, *, count: Optional[int] = None, bytes_per_file: int = 4096) -> List[Path]:
        """Overwrite selected files with low-entropy structured text content."""
        selected = self._select_files(count)
        modified: List[Path] = []
        for index, path in enumerate(selected):
            self._assert_inside_sandbox(path)
            token = f"RDRS_LOW_ENTROPY_BLOCK_{index % 5:02d}|"
            payload = (token * max(1, bytes_per_file // max(1, len(token)) + 1)).encode("utf-8")
            path.write_bytes(payload[: max(1, int(bytes_per_file))])
            modified.append(path)
            self._remember_touch(path)
        return modified

    def modify_files_with_unstable_writes(
        self,
        *,
        count: Optional[int] = None,
        bytes_per_file: int = 4096,
        chunks: int = 8,
    ) -> List[Path]:
        """Write files in small chunks to simulate in-flight modifications."""
        selected = self._select_files(count)
        rng = random.Random(self._seed + 97)
        modified: List[Path] = []
        chunk_count = max(1, int(chunks))
        chunk_size = max(1, int(bytes_per_file) // chunk_count)
        for path in selected:
            self._assert_inside_sandbox(path)
            with path.open("wb") as handle:
                for _ in range(chunk_count):
                    handle.write(bytes(rng.getrandbits(8) for _ in range(chunk_size)))
                    handle.flush()
            modified.append(path)
            self._remember_touch(path)
        return modified

    def delete_files(self, *, count: int) -> List[Path]:
        """Delete a subset of sandbox files to simulate stale records safely."""
        selected = self._select_files(count)
        deleted: List[Path] = []
        for path in selected:
            self._assert_inside_sandbox(path)
            if path.exists():
                path.unlink()
                deleted.append(path)
                self._remember_touch(path)
        return deleted

    def assert_all_touches_inside_sandbox(self) -> None:
        """Verify all simulator operations stayed within the sandbox."""
        if self.root is None:
            return
        root_resolved = self.root.resolve()
        for value in self._touched_paths:
            target = Path(value)
            if root_resolved not in [target, *target.parents]:
                raise AssertionError(f"Touched path outside sandbox: {target}")

    def cleanup(self) -> None:
        """Remove temporary directory unless preservation is requested."""
        if self._preserve_directory:
            return
        if self._temp_dir_obj is not None:
            self._temp_dir_obj.cleanup()
            self._temp_dir_obj = None
        elif self.root is not None and self.root.exists():
            shutil.rmtree(self.root, ignore_errors=True)
        self.root = None
        self._files = []
        self._touched_paths.clear()

    def _select_files(self, count: Optional[int]) -> List[Path]:
        if not self._files:
            self.create_low_entropy_baseline_files()
        target_count = len(self._files) if count is None else max(0, int(count))
        return list(self._files[:target_count])

    def _assert_inside_sandbox(self, file_path: Path) -> None:
        if self.root is None:
            raise RuntimeError("Sandbox is not initialized")
        root = self.root.resolve()
        resolved = file_path.resolve(strict=False)
        if root not in [resolved, *resolved.parents]:
            raise ValueError(f"Refusing to access path outside sandbox: {resolved}")

    def _remember_touch(self, file_path: Path) -> None:
        self._touched_paths.add(str(file_path.resolve(strict=False)))


def run_cli(mode: str, file_count: int, modify_count: int, keep: bool) -> SimulatorReport:
    simulator = SafeEntropyChangeSimulator(preserve_directory=keep, file_count=file_count)
    try:
        root = simulator.create_sandbox()
        simulator.create_low_entropy_baseline_files()

        if mode == "high":
            modified = simulator.modify_files_high_entropy(count=modify_count)
        elif mode == "low":
            modified = simulator.modify_files_low_entropy(count=modify_count)
        elif mode == "unstable":
            modified = simulator.modify_files_with_unstable_writes(count=modify_count)
        else:
            raise ValueError(f"Unsupported mode: {mode}")

        simulator.assert_all_touches_inside_sandbox()
        report = SimulatorReport(
            root=str(root),
            baseline_files_created=file_count,
            modified_files=len(modified),
            mode=mode,
        )
        return report
    finally:
        simulator.cleanup()


def _parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Safe entropy-change simulator for RDRS validation")
    parser.add_argument("--mode", choices=["high", "low", "unstable"], default="high")
    parser.add_argument("--file-count", type=int, default=25)
    parser.add_argument("--modify-count", type=int, default=25)
    parser.add_argument("--keep", action="store_true", help="Preserve temporary directory for debugging")
    return parser.parse_args(argv)


def main() -> None:
    args = _parse_args()
    report = run_cli(
        mode=args.mode,
        file_count=max(1, int(args.file_count)),
        modify_count=max(0, int(args.modify_count)),
        keep=bool(args.keep),
    )
    print(f"mode={report.mode}")
    print(f"root={report.root}")
    print(f"baseline_files_created={report.baseline_files_created}")
    print(f"modified_files={report.modified_files}")


if __name__ == "__main__":
    main()