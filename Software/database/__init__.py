"""RDRS database access layer package.

Three databases are maintained:
  metadata_db  — one row per monitored file (entropy, hash, timestamps, …)
  logs_db      — file-system events (created / modified / deleted / renamed)
  alerts_db    — triggered alerts and suspicious-process records

Each database has a dedicated access class.  All classes share a common base
(BaseDatabase) that handles connection pooling, thread safety, and schema
migrations.

Usage example::

    from database import get_metadata_db, get_logs_db, get_alerts_db

    metadata_db = get_metadata_db()
    metadata_db.upsert_file(path=..., current_entropy=7.9, ...)

"""

from database.metadata_db import MetadataDatabase
from database.logs_db import LogsDatabase
from database.alerts_db import AlertsDatabase
from utils.paths import get_data_dir

try:
    from config import get_config
    _CONFIG_AVAILABLE = True
except ImportError:
    _CONFIG_AVAILABLE = False


def _db_path(filename: str):
    return get_data_dir() / filename


def get_metadata_db() -> MetadataDatabase:
    """Return a MetadataDatabase instance using the configured file name."""
    if _CONFIG_AVAILABLE:
        name = get_config().database.metadata_db
    else:
        name = "metadata.db"
    return MetadataDatabase(_db_path(name))


def get_logs_db() -> LogsDatabase:
    """Return a LogsDatabase instance using the configured file name."""
    if _CONFIG_AVAILABLE:
        name = get_config().database.logs_db
        max_rows = get_config().database.max_log_rows
    else:
        name = "logs.db"
        max_rows = 500_000
    return LogsDatabase(_db_path(name), max_rows=max_rows)


def get_alerts_db() -> AlertsDatabase:
    """Return an AlertsDatabase instance using the configured file name."""
    if _CONFIG_AVAILABLE:
        name = get_config().database.alerts_db
    else:
        name = "alerts.db"
    return AlertsDatabase(_db_path(name))


__all__ = [
    "MetadataDatabase",
    "LogsDatabase",
    "AlertsDatabase",
    "get_metadata_db",
    "get_logs_db",
    "get_alerts_db",
]
