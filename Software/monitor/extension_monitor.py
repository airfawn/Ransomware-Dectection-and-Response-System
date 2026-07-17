"""File Extension Change Monitor for RDRS.

Ransomware routinely renames files after encrypting them — appending or
swapping the original extension for one of its own
(``report.docx`` -> ``report.locked``).  This module provides the pure,
side-effect-free detection logic used to recognise a *genuine* extension
change from a filesystem "moved/renamed" event.

Architecture
------------
Unlike the Entropy Monitor, extension-change detection requires no disk I/O —
it is a cheap string comparison between the previous and new path suffixes.
Because of that it does **not** need its own queue/worker thread; it is
invoked synchronously, in-line, from
:class:`monitor.filesystem_monitor.ProcessBehaviorTracker` on the watchdog
observer thread, keeping latency negligible while still following the
project's "non-blocking observer thread" rule.

This module owns only the *detection* logic (what counts as a genuine
extension change, and which target extensions are ignored as benign churn).
Everything else — score deltas, active-rule bookkeeping and GUI/DB
persistence — is handled by the existing subsystems:

    * Per-process burst statistics & scoring: ``ProcessState`` /
      ``detection_engine.ExtensionChangeEngine`` (existing scoring engine).
    * Structured text logging: ``ProcessBehaviorTracker._log_extension_change``
      (existing logging format, parsed by the GUI exactly like
      ``[Detection]`` / ``[ProcessState]`` blocks).
    * Persistence + GUI display: ``ransomwaredetector.py`` (existing
      logs.db / alerts.db / table widgets).

Isolation guarantees
---------------------
  - This module NEVER touches scores directly.
  - This module NEVER imports from ransomwaredetector, database, or Qt.
  - This module NEVER performs file or network I/O.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Set

# Destination extensions that commonly appear during ordinary application
# behaviour (autosave temp files, partial/incomplete downloads, editor swap
# files, backups) rather than malicious activity.  Extension changes that
# land on one of these are ignored by default to reduce false positives.
# Configurable via config.yaml (extension_monitor.ignored_extensions).
DEFAULT_IGNORED_TARGET_EXTENSIONS: Set[str] = {
    "tmp", "temp", "swp", "swx", "swo", "bak", "crdownload",
    "part", "partial", "download", "ds_store",
}


def get_extension(path: str) -> str:
    """Return the lowercase extension of a path, without the leading dot.

    Args:
        path: A file path or file name.

    Returns:
        Lowercase extension (e.g. "docx"), or "" if the path has none.
    """
    try:
        return Path(path).suffix.lower().lstrip(".")
    except Exception:
        return ""


def is_genuine_extension_change(
    previous_path: str,
    new_path: str,
    *,
    ignored_extensions: Optional[Set[str]] = None,
) -> bool:
    """Determine whether a rename/move event represents a genuine extension change.

    A change is considered genuine when:
        1. Both paths are non-empty.
        2. The (lowercased) extensions actually differ.
        3. The resulting extension is not in the ignored/benign set (which
           filters out ordinary autosave/temp-file churn).

    Args:
        previous_path: The file's path before the event.
        new_path:      The file's path after the event.
        ignored_extensions: Set of lowercase, dot-less extensions to ignore
            on the destination side.  Defaults to
            ``DEFAULT_IGNORED_TARGET_EXTENSIONS``.

    Returns:
        True if this event should be treated as a genuine extension change.
    """
    if not previous_path or not new_path:
        return False

    old_ext = get_extension(previous_path)
    new_ext = get_extension(new_path)

    if old_ext == new_ext:
        return False

    ignored = ignored_extensions if ignored_extensions is not None else DEFAULT_IGNORED_TARGET_EXTENSIONS
    if new_ext in ignored:
        return False

    return True


@dataclass(frozen=True)
class ExtensionChangeEvent:
    """A confirmed, genuine file-extension-change event.

    Attributes:
        timestamp:          Epoch time the change was recorded.
        previous_path:      Original file path (before the rename).
        new_path:            New file path (after the rename).
        original_extension:  Lowercase extension before the change (may be "").
        new_extension:       Lowercase extension after the change (may be "").
        process_name:        Resolved process name, if known.
        pid:                 Resolved process ID, if known.
        executable:          Resolved executable path, if known.
        parent:              Resolved parent process name, if known.
    """

    timestamp: float
    previous_path: str
    new_path: str
    original_extension: str
    new_extension: str
    process_name: Optional[str] = None
    pid: Optional[int] = None
    executable: Optional[str] = None
    parent: Optional[str] = None
