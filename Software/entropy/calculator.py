"""Shannon entropy calculation utilities for RDRS.

This module provides a pure-Python implementation of Shannon entropy that:
  - Reads only a configurable prefix of each file (default 5 MB) to bound I/O.
  - Is side-effect-free and stateless — safe for concurrent use.
  - Handles read errors gracefully, returning None instead of raising.

Shannon Entropy:
    H(X) = -Σ p(x) * log₂(p(x))   for each unique byte value x

    The result is in bits per byte, ranging from 0 (all bytes identical) to
    8.0 (maximally random, i.e. encrypted/compressed data).

Typical ranges:
    0.0 – 1.0  : nearly empty or repetitive files (NUL-padded, XML boilerplate)
    3.5 – 5.5  : plaintext documents, source code
    6.0 – 7.5  : compressed archives (zip, docx internals)
    7.5 – 8.0  : encrypted data (AES-CTR, ransomware ciphertext)
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Optional


def calculate_entropy(file_path: str | Path, sample_size_bytes: int = 5 * 1024 * 1024) -> Optional[float]:
    """Calculate Shannon entropy for a file, reading at most *sample_size_bytes*.

    Args:
        file_path:         Path to the file to analyse.
        sample_size_bytes: Maximum bytes to read.  Defaults to 5 MiB.
                           A value of 0 or negative reads the entire file.

    Returns:
        Entropy in bits per byte (0.0 – 8.0), or ``None`` if the file cannot
        be read (missing, permission denied, zero-length, etc.).
    """
    path = Path(file_path)
    try:
        with path.open("rb") as fh:
            if sample_size_bytes > 0:
                data = fh.read(sample_size_bytes)
            else:
                data = fh.read()
    except (OSError, PermissionError):
        return None

    return _entropy_of_bytes(data)


def _entropy_of_bytes(data: bytes) -> Optional[float]:
    """Compute Shannon entropy for a raw bytes object.

    Args:
        data: Bytes to analyse.

    Returns:
        Entropy in bits per byte, or None if data is empty.
    """
    if not data:
        return None

    total = len(data)

    # Count occurrences of each byte value (0–255) using a fixed-size array.
    # This is faster than Counter for binary data.
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1

    entropy = 0.0
    for count in freq:
        if count == 0:
            continue
        p = count / total
        entropy -= p * math.log2(p)

    return entropy
