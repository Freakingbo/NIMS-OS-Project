"""Error-safe, chunked cryptographic file hashing."""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_CHUNK_SIZE = 65536  # 64 KiB chunks for low memory footprint on large files


def compute_file_hash(
    file_path: str | Path,
    algorithm: str = "sha256",
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> str | None:
    """
    Compute the cryptographic digest of a file in chunks.

    Gracefully handles Windows file locks (PermissionError / OSError) and vanished files
    without raising unhandled exceptions.
    """
    path = Path(file_path)
    try:
        hasher = hashlib.new(algorithm)
    except ValueError as exc:
        logger.error("Invalid hash algorithm '%s': %s", algorithm, exc)
        raise

    try:
        with path.open("rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    except FileNotFoundError:
        logger.debug("File vanished before hashing completed: %s", path)
        return None
    except PermissionError as exc:
        logger.warning("Permission denied or file locked by another process '%s': %s", path, exc)
        return None
    except OSError as exc:
        logger.warning("OS error while hashing '%s': %s", path, exc)
        return None