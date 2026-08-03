#!/usr/bin/env python3
"""Release stress benchmark harness for RDRS.

This utility runs controlled, non-destructive stress scenarios and prints
measured metrics for backend burst handling, GUI pipeline backlog behavior,
long-run stability, and restart/shutdown cycles.
"""

from __future__ import annotations

import argparse
import collections
import json
import logging
import os
import queue
import shutil
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from unittest.mock import patch

# Ensure local project imports work when run as scripts/release_stress_benchmark.py
_THIS_FILE = Path(__file__).resolve()
_PROJECT_ROOT = _THIS_FILE.parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

try:
    import psutil
except Exception:
    psutil = None

from database.metadata_db import MetadataDatabase
from monitor.filesystem_monitor import FileSystemMonitor, ProcessMetadata
import ransomwaredetector as rd


@dataclass
class BurstMetrics:
    events_requested: int
    callback_events: int
    created: int
    modified: int
    moved: int
    deleted: int
    ingestion_seconds: float
    total_processing_seconds: float
    steady_state_recovery_seconds: float
    max_queue_size: int
    max_pending_count: int
    max_processing_count: int
    merged_duplicate_events: int
    deferred_low_priority_events: int
    processed_event_count: int
    burst_packets: int
    process_state_update_count: int
    gui_update_count: Optional[int]
    log_update_count: Optional[int]
    cpu_peak_percent: Optional[float]
    memory_peak_mb: Optional[float]
    result: str


class _CountingLogger:
    def __init__(self) -> None:
        self.process_state_blocks = 0
        self.detection_blocks = 0
        self.exceptions = 0

    def info(self, msg: str, *args, **kwargs) -> None:
        text = msg % args if args else str(msg)
        if "[ProcessState]" in text:
            self.process_state_blocks += 1
        if "[Detection]" in text:
            self.detection_blocks += 1
        return

    def warning(self, *args, **kwargs) -> None:
        return

    def debug(self, *args, **kwargs) -> None:
        return

    def error(self, *args, **kwargs) -> None:
        return

    def exception(self, *args, **kwargs) -> None:
        self.exceptions += 1
        return


class _PageStackStub:
    def __init__(self, index: int = 0) -> None:
        self._index = index

    def currentIndex(self) -> int:
        return self._index

    def setCurrentIndex(self, index: int) -> None:
        self._index = index


class _LabelStub:
    def __init__(self) -> None:
        self.text = ""
        self.style = ""

    def setText(self, text: str) -> None:
        self.text = text

    def setStyleSheet(self, style: str) -> None:
        self.style = style


class _ButtonStub:
    def __init__(self) -> None:
        self.text = ""
        self.style = ""

    def setText(self, text: str) -> None:
        self.text = text

    def setStyleSheet(self, style: str) -> None:
        self.style = style


def _enqueue_synthetic_burst(monitor: FileSystemMonitor, root: Path, count: int) -> None:
    """Inject a controlled mixed burst directly into the monitor queue.

    This avoids OS watcher jitter and expensive per-event process scans,
    while still exercising the real queueing, burst worker, scoring, and
    callback pathways.
    """
    incoming = root / "incoming"
    incoming.mkdir(parents=True, exist_ok=True)

    process_meta = ProcessMetadata(
        pid=7777,
        name="benchproc",
        executable="/usr/bin/benchproc",
        parent_name="bench-parent",
        start_time="2026-08-03 00:00:00",
        start_time_epoch=time.time() - 120.0,
    )

    for index in range(count):
        base = incoming / f"burst_{index % 50}" / f"f_{index}.txt"
        base.parent.mkdir(parents=True, exist_ok=True)
        if not base.exists():
            base.write_text("x", encoding="utf-8")

        event_selector = index % 4
        if event_selector == 0:
            event_type = "FILE CREATED"
            src = str(base)
            previous = None
        elif event_selector == 1:
            event_type = "FILE MODIFIED"
            src = str(base)
            previous = None
        elif event_selector == 2:
            moved = base.with_name(f"{base.stem}.moved{base.suffix}")
            event_type = "FILE MOVED"
            src = str(moved)
            previous = str(base)
        else:
            event_type = "FILE DELETED"
            src = str(base)
            previous = None

        monitor.handler._enqueue_event(
            event_type=event_type,
            src_path=src,
            previous_path=previous,
            process_metadata=process_meta,
            timestamp=time.time(),
        )


def _wait_for_steady_state(monitor: FileSystemMonitor, timeout_s: float = 60.0) -> Tuple[float, Dict[str, int]]:
    started = time.monotonic()
    quiet_since = None
    snapshot = monitor.handler.get_burst_status()

    while (time.monotonic() - started) <= timeout_s:
        snapshot = monitor.handler.get_burst_status()
        queue_size = int(snapshot.get("queue_size", 0))
        pending = int(snapshot.get("pending_count", 0))
        processing = int(snapshot.get("processing_count", 0))

        if queue_size == 0 and pending == 0 and processing == 0:
            if quiet_since is None:
                quiet_since = time.monotonic()
            elif (time.monotonic() - quiet_since) >= 0.5:
                break
        else:
            quiet_since = None

        time.sleep(0.02)

    return time.monotonic() - started, {
        "queue_size": int(snapshot.get("queue_size", 0)),
        "pending_count": int(snapshot.get("pending_count", 0)),
        "processing_count": int(snapshot.get("processing_count", 0)),
    }


def run_backend_burst(count: int) -> BurstMetrics:
    logger = _CountingLogger()
    callback_counts = collections.Counter()

    with tempfile.TemporaryDirectory(prefix="rdrs_release_burst_") as tmpdir:
        root = Path(tmpdir)
        metadata_db = MetadataDatabase(root / "metadata.db")

        with patch("monitor.filesystem_monitor.get_metadata_db", return_value=metadata_db):
            monitor = FileSystemMonitor(
                target_path=root,
                recursive=True,
                logger=logger,
                event_callback=lambda event_type, *_args, **_kwargs: callback_counts.update([event_type]),
            )

        max_queue_size = 0
        max_pending_count = 0
        max_processing_count = 0
        cpu_peak = None
        rss_peak = None
        sampling = True

        def _sampler() -> None:
            nonlocal max_queue_size, max_pending_count, max_processing_count, cpu_peak, rss_peak
            proc = psutil.Process(os.getpid()) if psutil else None
            if proc is not None:
                try:
                    proc.cpu_percent(None)
                except Exception:
                    proc = None

            while sampling:
                status = monitor.handler.get_burst_status()
                max_queue_size = max(max_queue_size, int(status.get("queue_size", 0)))
                max_pending_count = max(max_pending_count, int(status.get("pending_count", 0)))
                max_processing_count = max(max_processing_count, int(status.get("processing_count", 0)))

                if proc is not None:
                    try:
                        cpu_now = float(proc.cpu_percent(None))
                        rss_now = float(proc.memory_info().rss) / (1024.0 * 1024.0)
                        cpu_peak = cpu_now if cpu_peak is None else max(cpu_peak, cpu_now)
                        rss_peak = rss_now if rss_peak is None else max(rss_peak, rss_now)
                    except Exception:
                        proc = None

                time.sleep(0.05)

        sampler_thread = threading.Thread(target=_sampler, name="rdrs-release-sampler", daemon=True)

        monitor.start()
        sampler_thread.start()
        time.sleep(0.2)

        ingestion_start = time.monotonic()
        _enqueue_synthetic_burst(monitor, root, count)

        ingestion_end = time.monotonic()

        steady_recovery_seconds, final_status = _wait_for_steady_state(monitor)
        total_done = time.monotonic()

        sampling = False
        sampler_thread.join(timeout=2.0)

        status = monitor.handler.get_burst_status()
        monitor.stop()
        metadata_db.close()

    callback_total = int(sum(callback_counts.values()))
    expected_min = max(1, int(count * 0.9))
    result = "PASS" if callback_total >= expected_min and final_status["queue_size"] == 0 else "FAIL"

    return BurstMetrics(
        events_requested=count,
        callback_events=callback_total,
        created=int(callback_counts.get("FILE CREATED", 0)),
        modified=int(callback_counts.get("FILE MODIFIED", 0)),
        moved=int(callback_counts.get("FILE MOVED", 0)),
        deleted=int(callback_counts.get("FILE DELETED", 0)),
        ingestion_seconds=ingestion_end - ingestion_start,
        total_processing_seconds=total_done - ingestion_start,
        steady_state_recovery_seconds=steady_recovery_seconds,
        max_queue_size=max_queue_size,
        max_pending_count=max_pending_count,
        max_processing_count=max_processing_count,
        merged_duplicate_events=int(status.get("merged_duplicate_events", 0)),
        deferred_low_priority_events=int(status.get("deferred_low_priority_events", 0)),
        processed_event_count=int(status.get("processed_event_count", 0)),
        burst_packets=int(status.get("packet_count", 0)),
        process_state_update_count=logger.process_state_blocks,
        gui_update_count=None,
        log_update_count=callback_total,
        cpu_peak_percent=cpu_peak,
        memory_peak_mb=rss_peak,
        result=result,
    )


def _make_gui_shell(initial_index: int = 0):
    gui = rd.RdrsGui.__new__(rd.RdrsGui)
    gui.page_stack = _PageStackStub(initial_index)
    gui._filesystem_event_gui_queue = queue.Queue(maxsize=100000)
    gui.event_rows = []
    gui.event_count = 0

    gui._pending_log_refresh = False
    gui._pending_counter_refresh = False
    gui._pending_process_state_refresh = False
    gui._pending_suspicious_refresh = False
    gui._pending_metrics_refresh = False
    gui._pending_total_events_refresh = False
    gui._selected_home_process_key = None

    gui.total_events_label = _LabelStub()
    gui.home_button = _ButtonStub()
    gui.incident_button = _ButtonStub()
    gui.monitoring_button = _ButtonStub()
    gui.processes_button = _ButtonStub()
    gui.entropy_button = _ButtonStub()
    gui.rules_button = _ButtonStub()

    counters = {
        "trim": 0,
        "log_refresh": 0,
        "counter_refresh": 0,
        "process_refresh": 0,
        "suspicious_refresh": 0,
        "metrics_refresh": 0,
    }

    gui._trim_gui_event_cache = lambda: counters.__setitem__("trim", counters["trim"] + 1)
    gui._refresh_log_table_view = lambda: counters.__setitem__("log_refresh", counters["log_refresh"] + 1)
    gui._refresh_file_event_counters = lambda: counters.__setitem__("counter_refresh", counters["counter_refresh"] + 1)
    gui._refresh_process_state_tables = lambda: counters.__setitem__("process_refresh", counters["process_refresh"] + 1)
    gui._refresh_suspicious_process_table = lambda: counters.__setitem__("suspicious_refresh", counters["suspicious_refresh"] + 1)
    gui._refresh_dashboard_metrics = lambda: counters.__setitem__("metrics_refresh", counters["metrics_refresh"] + 1)
    gui._populate_incident_page = lambda *_args, **_kwargs: None
    gui._refresh_entropy_table = lambda: None

    return gui, counters


def run_gui_pipeline_burst(count: int) -> Dict[str, float]:
    gui, counters = _make_gui_shell(initial_index=0)

    for i in range(count):
        gui._filesystem_event_gui_queue.put_nowait(
            {
                "event_type": "FILE MODIFIED",
                "timestamp": f"t{i}",
                "file": f"/tmp/f{i}.txt",
                "message": "burst",
            }
        )

    start = time.monotonic()
    flush_calls = 0

    while not gui._filesystem_event_gui_queue.empty():
        rd.RdrsGui._flush_pending_gui_updates(gui)
        flush_calls += 1
        if flush_calls % 4 == 0:
            rd.RdrsGui.select_page(gui, 1)
        elif flush_calls % 2 == 0:
            rd.RdrsGui.select_page(gui, 0)

    rd.RdrsGui.select_page(gui, 1)
    rd.RdrsGui._flush_pending_gui_updates(gui)
    flush_calls += 1

    elapsed = time.monotonic() - start
    return {
        "events": float(count),
        "flush_calls": float(flush_calls),
        "elapsed_seconds": elapsed,
        "gui_update_count": float(counters["log_refresh"] + counters["counter_refresh"] + counters["metrics_refresh"]),
        "log_update_count": float(counters["log_refresh"]),
        "process_state_update_count": float(counters["process_refresh"]),
        "result": "PASS" if counters["log_refresh"] < max(10.0, count / 20.0) else "FAIL",
    }


def run_long_run(duration_seconds: float, burst_size: int, cycles: int) -> Dict[str, float]:
    logger = _CountingLogger()

    with tempfile.TemporaryDirectory(prefix="rdrs_release_longrun_") as tmpdir:
        root = Path(tmpdir)
        metadata_db = MetadataDatabase(root / "metadata.db")

        with patch("monitor.filesystem_monitor.get_metadata_db", return_value=metadata_db):
            monitor = FileSystemMonitor(
                target_path=root,
                recursive=True,
                logger=logger,
                event_callback=lambda *_args, **_kwargs: None,
            )

        start_threads = threading.active_count()
        start_rss = None
        if psutil:
            try:
                start_rss = float(psutil.Process(os.getpid()).memory_info().rss) / (1024.0 * 1024.0)
            except Exception:
                start_rss = None

        monitor.start()
        started = time.monotonic()
        cycle = 0
        max_queue = 0

        while (time.monotonic() - started) < duration_seconds:
            _enqueue_synthetic_burst(monitor, root, burst_size)
            cycle += 1
            max_queue = max(max_queue, int(monitor.handler.get_burst_status().get("queue_size", 0)))
            if cycle >= cycles:
                break

        _wait_for_steady_state(monitor, timeout_s=max(30.0, duration_seconds * 2.0))
        status = monitor.handler.get_burst_status()
        tracker_records = len(monitor.behavior_tracker.get_all_processes())
        entropy_armed = len(getattr(monitor.behavior_tracker, "_entropy_validation_armed", {}))
        monitor.stop()

        end_threads = threading.active_count()
        end_rss = None
        if psutil:
            try:
                end_rss = float(psutil.Process(os.getpid()).memory_info().rss) / (1024.0 * 1024.0)
            except Exception:
                end_rss = None

        metadata_db.close()

    memory_growth = None
    if start_rss is not None and end_rss is not None:
        memory_growth = end_rss - start_rss

    return {
        "duration_seconds": duration_seconds,
        "cycles_run": float(cycle),
        "max_queue_size": float(max_queue),
        "processed_event_count": float(status.get("processed_event_count", 0)),
        "deferred_low_priority_events": float(status.get("deferred_low_priority_events", 0)),
        "thread_delta": float(end_threads - start_threads),
        "memory_growth_mb": memory_growth if memory_growth is not None else float("nan"),
        "remaining_process_records": float(tracker_records),
        "remaining_entropy_armed": float(entropy_armed),
        "exceptions": float(logger.exceptions),
        "result": "PASS" if logger.exceptions == 0 and end_threads <= (start_threads + 2) else "FAIL",
    }


def run_restart_cycles(cycles: int, burst_size: int) -> Dict[str, float]:
    logger = _CountingLogger()
    failures = 0

    with tempfile.TemporaryDirectory(prefix="rdrs_release_restart_") as tmpdir:
        root = Path(tmpdir)

        for i in range(cycles):
            metadata_db = MetadataDatabase(root / f"metadata_{i}.db")

            with patch("monitor.filesystem_monitor.get_metadata_db", return_value=metadata_db):
                monitor = FileSystemMonitor(
                    target_path=root,
                    recursive=True,
                    logger=logger,
                    event_callback=lambda *_args, **_kwargs: None,
                )

            try:
                monitor.start()
                _enqueue_synthetic_burst(monitor, root, burst_size)
                _wait_for_steady_state(monitor, timeout_s=40.0)
                monitor.stop()
            except Exception:
                failures += 1
            finally:
                metadata_db.close()

    return {
        "cycles": float(cycles),
        "burst_size": float(burst_size),
        "failures": float(failures),
        "exceptions": float(logger.exceptions),
        "result": "PASS" if failures == 0 and logger.exceptions == 0 else "FAIL",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="RDRS release stress benchmark")
    parser.add_argument("--counts", nargs="+", type=int, default=[100, 500, 1000, 5000, 10000])
    parser.add_argument("--long-run-seconds", type=float, default=20.0)
    parser.add_argument("--long-run-burst", type=int, default=300)
    parser.add_argument("--long-run-cycles", type=int, default=10)
    parser.add_argument("--restart-cycles", type=int, default=4)
    parser.add_argument("--restart-burst", type=int, default=200)
    parser.add_argument("--output-json", type=str, default="")
    args = parser.parse_args()

    burst_results = [run_backend_burst(count) for count in args.counts]
    gui_results = [run_gui_pipeline_burst(count) for count in [100, 500, 1000, 5000]]
    long_run = run_long_run(args.long_run_seconds, args.long_run_burst, args.long_run_cycles)
    restart = run_restart_cycles(args.restart_cycles, args.restart_burst)

    print("\nRDRS Burst Benchmark")
    print("Test                 Events    Duration(s)    MaxQueue    Result")
    print("----------------------------------------------------------------")
    for row in burst_results:
        label = {
            100: "Small burst",
            500: "Medium burst",
            1000: "Large burst",
            5000: "Extreme burst",
            10000: "Stress burst",
        }.get(row.events_requested, f"Burst {row.events_requested}")
        print(
            f"{label:<20} {row.events_requested:>6} {row.total_processing_seconds:>13.3f} "
            f"{row.max_queue_size:>10}    {row.result}"
        )

    print("\nGUI Pipeline Burst")
    print("Events    GUI updates    Log updates    Flush calls    Result")
    print("---------------------------------------------------------------")
    for row in gui_results:
        print(
            f"{int(row['events']):>6} {int(row['gui_update_count']):>13} {int(row['log_update_count']):>12} "
            f"{int(row['flush_calls']):>12}    {row['result']}"
        )

    report = {
        "burst_results": [r.__dict__ for r in burst_results],
        "gui_results": gui_results,
        "long_run": long_run,
        "restart": restart,
    }

    if args.output_json:
        Path(args.output_json).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nJSON report written to {args.output_json}")

    print("\nLong-run result:", long_run)
    print("Restart result:", restart)


if __name__ == "__main__":
    main()
