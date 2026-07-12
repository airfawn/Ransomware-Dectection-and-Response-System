"""Logger helper used by the RDRS monitor."""

import logging


def setup_logger() -> logging.Logger:
    """Create a logger configured for console output."""
    logger = logging.getLogger("rdrs")
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            fmt="%(asctime)s %(levelname)s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger
