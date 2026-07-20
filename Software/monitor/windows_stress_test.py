#!/usr/bin/env python3
"""Windows-focused filesystem stress harness for RDRS.

This script creates, modifies, renames, moves, and deletes batches of files
under a monitored temporary directory while counting the events that reach the
filesystem monitor callback.

It is designed to be run on Windows 11 against a real watchdog observer.
Use ``--strict`` to fail the run when callback counts fall below the expected
per-operation totals.
"""

from __future__ import annotations

import argparse
import collections
import logging
import shutil
import tempfile
import time
from pathlib import Path

from monitor.filesystem_monitor import FileSystemMonitor


class _CountingLogger(logging.Logger):
    pass


def _build_logger() -> logging.Logger:
    logger = logging.getLogger("rdrs.windows_stress_test")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(handler)
    return logger


def _wait_for_events(timeout: float = 2.0) -> None:
    time.sleep(timeout)


def run_batch(count: int, strict: bool = False) -> dict[str, int]:
    logger = _build_logger()
    counts = collections.Counter()

    with tempfile.TemporaryDirectory(prefix="rdrs_windows_stress_") as tmpdir:
        root = Path(tmpdir)
        incoming = root / "incoming"
        moved = root / "moved"
        incoming.mkdir(parents=True, exist_ok=True)
        moved.mkdir(parents=True, exist_ok=True)

        def callback(event_type, file_path, process_name, pid, executable, parent, previous_path=None, file_identifier=None):
            counts[event_type] += 1

        monitor = FileSystemMonitor(
            target_path=root,
            recursive=True,
            logger=logger,
            event_callback=callback,
        )
        monitor.start()
        _wait_for_events(0.5)

        created_paths: list[Path] = []
        for index in range(count):
            nested_dir = incoming / f"batch_{index % 10}" / f"group_{index % 5}"
            nested_dir.mkdir(parents=True, exist_ok=True)
            file_path = nested_dir / f"file_{index}.txt"
            file_path.write_text(f"seed-{index}\n", encoding="utf-8")
            created_paths.append(file_path)

        _wait_for_events()

        for file_path in created_paths:
            with file_path.open("a", encoding="utf-8") as handle:
                handle.write("modified\n")

        _wait_for_events()

        renamed_paths: list[Path] = []
        for file_path in created_paths:
            renamed = file_path.with_name(f"{file_path.stem}.renamed{file_path.suffix}")
            file_path.rename(renamed)
            renamed_paths.append(renamed)

        _wait_for_events()

        moved_paths: list[Path] = []
        for file_path in renamed_paths:
            destination = moved / file_path.name
            shutil.move(str(file_path), str(destination))
            moved_paths.append(destination)

        _wait_for_events()

        for file_path in moved_paths:
            file_path.unlink(missing_ok=True)

        _wait_for_events()
        monitor.stop()

    print(f"Batch size: {count}")
    for key in ["FILE CREATED", "FILE MODIFIED", "FILE MOVED", "FILE DELETED"]:
        print(f"{key}: {counts.get(key, 0)}")

    if strict:
        failures = []
        if counts.get("FILE CREATED", 0) < count:
            failures.append(f"created={counts.get('FILE CREATED', 0)} < {count}")
        if counts.get("FILE MODIFIED", 0) < count:
            failures.append(f"modified={counts.get('FILE MODIFIED', 0)} < {count}")
        if counts.get("FILE MOVED", 0) < count:
            failures.append(f"moved={counts.get('FILE MOVED', 0)} < {count}")
        if counts.get("FILE DELETED", 0) < count:
            failures.append(f"deleted={counts.get('FILE DELETED', 0)} < {count}")
        if failures:
            raise AssertionError("; ".join(failures))

    return dict(counts)


def main() -> None:
    parser = argparse.ArgumentParser(description="RDRS Windows filesystem stress harness")
    parser.add_argument(
        "--counts",
        type=int,
        nargs="+",
        default=[100, 500, 1000, 5000, 10000],
        help="Batch sizes to run",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail when counts fall below the requested batch size.",
    )
    args = parser.parse_args()

    for count in args.counts:
        print("=" * 72)
        run_batch(count, strict=args.strict)


if __name__ == "__main__":
    main()
