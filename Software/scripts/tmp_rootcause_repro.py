from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from database.alerts_db import AlertsDatabase
from database.logs_db import LogsDatabase
from database.metadata_db import MetadataDatabase
from entropy.monitor import EntropyMonitor
from entropy_loader import build_entropy_cache
from monitor.filesystem_monitor import FileSystemMonitorHandler, ProcessBehaviorTracker, ProcessMetadata


logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("rootcause-repro")


def issue1_entropy_timing(base: Path) -> None:
    print("\n=== ISSUE1_ENTROPY_TIMING_START ===")
    data_dir = base / "issue1"
    data_dir.mkdir(parents=True, exist_ok=True)

    target = data_dir / "victim.txt"
    size_total = 6 * 1024 * 1024
    target.write_bytes((b"A quick brown fox jumps over the lazy dog.\n" * 200000)[:size_total])

    metadata_db = MetadataDatabase(base / "issue1_metadata.db")
    logs_db = LogsDatabase(base / "issue1_logs.db")
    alerts_db = AlertsDatabase(base / "issue1_alerts.db")

    build_entropy_cache(
        metadata_db=metadata_db,
        roots=[data_dir],
        allowed_extensions={"txt"},
        sample_size_bytes=5 * 1024 * 1024,
        progress_callback=None,
    )

    monitor = EntropyMonitor(
        metadata_db=metadata_db,
        logs_db=logs_db,
        alerts_db=alerts_db,
        allowed_extensions={"txt"},
        monitored_roots=[],
        sample_size_bytes=5 * 1024 * 1024,
        threshold=1.4,
        persist_events_to_logs=False,
    )
    monitor.start()

    first_chunk_written = threading.Event()
    continue_writing = threading.Event()

    def encrypt_in_chunks() -> None:
        chunk = 512 * 1024
        chunks_needed = (5 * 1024 * 1024) // chunk
        with target.open("r+b") as fh:
            for i in range(chunks_needed):
                fh.seek(i * chunk)
                fh.write(os.urandom(chunk))
                fh.flush()
                os.fsync(fh.fileno())
                if i == 0:
                    first_chunk_written.set()
                    continue_writing.wait(timeout=10.0)

    t = threading.Thread(target=encrypt_in_chunks, name="repro-encrypt")
    t.start()

    first_chunk_written.wait(timeout=5.0)
    monitor.on_file_event(
        "FILE MODIFIED",
        str(target),
        process_name="sim-ransom",
        pid=44444,
        executable="sim-ransom.exe",
        parent="cmd.exe",
    )

    continue_writing.set()
    t.join(timeout=10.0)

    time.sleep(0.6)
    monitor.on_file_event(
        "FILE MODIFIED",
        str(target),
        process_name="sim-ransom",
        pid=44444,
        executable="sim-ransom.exe",
        parent="cmd.exe",
    )

    time.sleep(1.0)
    monitor.stop()

    row = metadata_db.get_file(str(target))
    print(
        "ISSUE1_FINAL_DB",
        {
            "path": str(target),
            "baseline_entropy": row["baseline_entropy"] if row else None,
            "previous_entropy": row["previous_entropy"] if row else None,
            "current_entropy": row["current_entropy"] if row else None,
        },
    )
    print("=== ISSUE1_ENTROPY_TIMING_END ===")


def issue2_refresh_extension_drop(base: Path) -> None:
    print("\n=== ISSUE2_REFRESH_EXTENSION_DROP_START ===")
    data_dir = base / "issue2"
    data_dir.mkdir(parents=True, exist_ok=True)

    metadata_db = MetadataDatabase(base / "issue2_metadata.db")
    txt = data_dir / "report.txt"
    txt.write_text("sensitive data\n" * 1000, encoding="utf-8")

    s1 = build_entropy_cache(
        metadata_db=metadata_db,
        roots=[data_dir],
        allowed_extensions={"txt"},
        sample_size_bytes=5 * 1024 * 1024,
        progress_callback=None,
    )
    before_count = metadata_db.count_existing()

    locked = data_dir / "report.locked"
    txt.rename(locked)

    s2 = build_entropy_cache(
        metadata_db=metadata_db,
        roots=[data_dir],
        allowed_extensions={"txt"},
        sample_size_bytes=5 * 1024 * 1024,
        progress_callback=None,
    )
    after_count = metadata_db.count_existing()

    print("ISSUE2_SUMMARY", {
        "before_count": before_count,
        "after_count": after_count,
        "scan1": s1,
        "scan2": s2,
    })
    print("=== ISSUE2_REFRESH_EXTENSION_DROP_END ===")


def issue3_entropy_score_noncontribution(base: Path) -> None:
    print("\n=== ISSUE3_SCORE_NONCONTRIBUTION_START ===")
    data_dir = base / "issue3"
    (data_dir / "a").mkdir(parents=True, exist_ok=True)
    (data_dir / "b").mkdir(parents=True, exist_ok=True)

    tracker = ProcessBehaviorTracker(logger=logging.getLogger("tracker"))
    meta = ProcessMetadata(
        pid=55555,
        name="simproc",
        executable="simproc.exe",
        parent_name="cmd.exe",
        start_time="now",
        start_time_epoch=time.time() - 60,
    )

    record = None
    for i in range(12):
        d = "a" if i % 2 == 0 else "b"
        p = data_dir / d / f"f{i}.txt"
        p.write_text("hello world\n" * 200, encoding="utf-8")
        record = tracker.record_event("FILE MODIFIED", str(p), meta)

    print("ISSUE3_FINAL", {
        "score": record.score if record else None,
        "active_rules": sorted(list(record.active_rules)) if record else None,
        "entropy_bonus": (record.entropy_score_bonus if record else None),
    })
    print("=== ISSUE3_SCORE_NONCONTRIBUTION_END ===")


def issue4_process_backlog_after_exit(base: Path) -> None:
    print("\n=== ISSUE4_PROCESS_BACKLOG_AFTER_EXIT_START ===")
    data_dir = base / "issue4"
    data_dir.mkdir(parents=True, exist_ok=True)

    tracker = ProcessBehaviorTracker(logger=logging.getLogger("tracker-backlog"))
    handler = FileSystemMonitorHandler(
        logger=logging.getLogger("fs-handler"),
        behavior_tracker=tracker,
        event_callback=None,
        high_score_callback=None,
    )

    proc = subprocess.Popen(["python", "-c", "pass"])
    pid = proc.pid
    proc.wait(timeout=5.0)

    dead_meta = ProcessMetadata(
        pid=pid,
        name="deadproc",
        executable="deadproc.exe",
        parent_name="cmd.exe",
        start_time="now",
        start_time_epoch=time.time() - 5,
    )

    for i in range(180):
        f = data_dir / f"x{i}.txt"
        f.write_text("x", encoding="utf-8")
        handler._enqueue_event(
            event_type="FILE MODIFIED",
            src_path=str(f),
            previous_path=None,
            process_metadata=dead_meta,
            timestamp=time.time(),
            payload=None,
        )

    deadline = time.time() + 8.0
    while time.time() < deadline:
        st = handler.get_burst_status()
        if st.get("queue_size", 0) == 0 and st.get("pending_count", 0) == 0 and st.get("processing_count", 0) == 0:
            break
        time.sleep(0.05)

    state = tracker.get_process_state(dead_meta)
    print("ISSUE4_FINAL", {
        "dead_pid": pid,
        "process_state_present": state is not None,
        "files_modified": (state.modified if state else None),
        "total_events": (state.total_events if state else None),
        "score": (state.score if state else None),
        "classification": (state.classification if state else None),
    })

    handler.stop()
    print("=== ISSUE4_PROCESS_BACKLOG_AFTER_EXIT_END ===")


def main() -> None:
    base = Path(tempfile.mkdtemp(prefix="rdrs_rootcause_"))
    print("TMP_BASE", str(base))
    try:
        issue1_entropy_timing(base)
        issue2_refresh_extension_drop(base)
        issue3_entropy_score_noncontribution(base)
        issue4_process_backlog_after_exit(base)
    finally:
        shutil.rmtree(base, ignore_errors=True)
        print("TMP_CLEANED", str(base))


if __name__ == "__main__":
    main()
