# Engineering Report: Targeted Architecture Refactor (Entropy, Identity, Attribution, Quarantine)

Date: 2026-07-20
Project: Ransomware Detection and Response System (RDRS)

## 1. Root Causes Discovered

1. Runtime entropy scoring path was effectively tied to legacy high-score rescan dispatch, not strict verification-only entropy.
2. Entropy metadata was keyed primarily by path; identity existed in a side map but core metadata rows did not persist file identity and baseline entropy as first-class fields.
3. Startup baseline build updated rows incrementally; while it removed deleted rows, it did not explicitly hard-reset runtime entropy state at startup.
4. Process attribution lacked richer context fields needed for robust forensic attribution (command line, working directory, username, parent PID, parent executable).
5. Quarantine workflow was manual-first and terminated process before quarantine move; automatic score-threshold containment was not enforced.

## 2. Code Changes Made

### A. Entropy/Data Pipeline and Baseline Architecture

- Extended metadata schema and access layer in database/metadata_db.py:
  - Added non-destructive schema upgrades for file metadata columns:
    - file_id
    - current_path
    - current_filename
    - current_extension
    - baseline_entropy
  - Added get_file_by_identifier(file_id, file_path) for stable-identity lookup fallback.
  - Added reset_runtime_state() to clear runtime metadata/cache/identity map for startup rebuild.
  - Extended upsert_file(...) to accept file_id and baseline_entropy while preserving existing callers.

- Updated startup builder in entropy_loader.py:
  - Startup now explicitly resets runtime metadata state before rebuild.
  - Baseline entries are rebuilt from filesystem truth every launch.
  - File identity is persisted at baseline load time.
  - Baseline entropy is written explicitly for rebuilt rows.

- Updated entropy monitor writes in entropy/monitor.py:
  - Uses stable identity-aware lookup for previous rows.
  - Persists file_id and baseline-aware data in upserts.

### B. Runtime Entropy Redesign (Verification-Based)

- Implemented verification-based entropy scoring in monitor/filesystem_monitor.py inside ProcessBehaviorTracker:
  - Trigger condition: behavioral score reaches configured trigger (monitoring.high_score_rescan_threshold, default 30).
  - Candidate set: up to 10 most-recent unique FILE MODIFIED paths for the process.
  - For each candidate file:
    - Read baseline entropy from runtime DB (baseline_entropy; fallbacks preserved).
    - Calculate current entropy from live file bytes.
    - Compute entropy increase (current - baseline).
  - Compute average entropy increase across evaluated files.
  - Apply entropy score bonus (config.entropy.score, default +30) only when average entropy increase exceeds threshold (config.entropy.threshold).

- Disabled legacy high-score rescan dispatch path from FileSystemMonitorHandler processing loop.
- Stopped wiring legacy high-score callback from GUI monitor session startup.

### C. Stable File Identity Improvements

- File metadata now persists identity and canonical file fields.
- Identity lookup path is preferred when available; path fallback remains.
- Existing extension-change continuity behavior is preserved.

### D. Process Attribution Improvements

- Extended ProcessMetadata and ProcessState with:
  - parent_pid
  - parent_executable
  - command_line
  - working_directory
  - username
- Enhanced resolver extraction to populate the above fields.
- Improved PowerShell attribution by appending script name when .ps1 is visible in command line.
- Extended structured ProcessState log parsing in GUI to capture new attribution fields.

### E. Automatic Quarantine and Quarantine Flow Hardening

- Implemented automatic quarantine trigger at process score >= 50 in GUI process-state update flow.
- Added one-shot guard per process key to avoid repeated auto-quarantine.
- Refactored quarantine workflow to:
  1. suspend process first,
  2. attempt quarantine move,
  3. kill process after quarantine succeeds.
- Added graceful handling of already-exited process condition with explicit message:
  - "Process exited before quarantine could be performed."
- Kept backward-compatible termination wrapper for existing callers/tests.

## 3. Validation Results

Executed targeted regression tests via unittest:

Command:
./rdrs/bin/python -m unittest monitor.test_validation_windows test_rdrs_response_actions -v

Result:
- 13 tests run
- 13 passed
- 0 failures
- 0 errors

Notable validations covered:
1. Startup entropy cache rebuild behavior and deleted-file cleanup.
2. Entropy tracking continuity across extension changes.
3. Verification-based entropy bonus activation test added:
   - Confirms EntropyIncrease active rule and +30 bonus when average increase exceeds threshold.
4. Quarantine action tests updated and passing.
5. Automatic quarantine trigger-at-50 test added and passing.

## 4. Remaining Limitations / Uncertainties

1. Platform-specific NTFS File ID / FRN API extraction is not implemented with native Windows calls; current implementation uses inode/device where available and path fallback otherwise.
2. Full Monkey simulator execution was not run in this session; verification here is based on targeted automated tests.
3. Existing entropy monitor alert path remains present for compatibility but runtime modified-file forwarding from GUI was reduced; behavior should be monitored in integrated end-to-end runs.
4. Schema migration is additive and non-destructive; extremely old/corrupted DB files may still require manual cleanup.

## 5. Backward Compatibility Statement

- Existing detection rules, monitor pipeline, GUI tables, and public method names were preserved.
- Legacy APIs and call patterns continue to work.
- New behavior is additive and targeted to entropy verification, file identity durability, attribution enrichment, and auto-containment at threshold.
