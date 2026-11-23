"""Cross-platform utility functions for path normalization, privilege checks, and OS metadata."""

from __future__ import annotations

import ctypes
import fnmatch
import logging
import os
import platform
import stat
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def is_windows() -> bool:
    """Return True if running on Windows."""
    return platform.system().lower() == "windows"


def is_linux() -> bool:
    """Return True if running on Linux."""
    return platform.system().lower() == "linux"


def normalize_path(path: str | Path) -> str:
    """Normalize a file path consistently across Windows and Linux using forward slashes."""
    p = Path(path).expanduser()
    try:
        resolved = p.resolve(strict=False)
    except OSError:
        resolved = Path(os.path.abspath(str(p)))
    return resolved.as_posix()


def is_admin() -> bool:
    """Check if the current process is running with Administrator (Windows) or root (Linux) privileges."""
    try:
        if is_windows():
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except Exception as exc:
        logger.debug("Could not determine privilege level: %s", exc)
        return False


def is_protected_path(path: str | Path) -> bool:
    """Heuristic check for OS-protected directories that typically require elevated privileges."""
    norm = normalize_path(path).lower()
    if is_windows():
        protected_prefixes = (
            "c:/windows",
            "c:/program files",
            "c:/program files (x86)",
            "c:/programdata",
        )
        return any(norm.startswith(prefix) for prefix in protected_prefixes)

    protected_prefixes = (
        "/etc",
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/boot",
        "/root",
        "/var/log",
    )
    return any(norm == prefix or norm.startswith(prefix + "/") for prefix in protected_prefixes)


def matches_exclude(path: str | Path, exclude_patterns: list[str]) -> bool:
    """Return True if a path matches any configured glob exclusion pattern."""
    if not exclude_patterns:
        return False
    p = Path(path)
    norm_str = normalize_path(p)
    name = p.name
    for pattern in exclude_patterns:
        clean_pat = pattern.replace("\\", "/")
        if fnmatch.fnmatch(name, clean_pat) or fnmatch.fnmatch(norm_str, clean_pat):
            return True
        if fnmatch.fnmatch(norm_str, f"*/{clean_pat}") or fnmatch.fnmatch(norm_str, f"*/{clean_pat}/*"):
            return True
    return False


def get_file_metadata(path: Path) -> dict[str, Any] | None:
    """Safely extract cross-platform file metadata without following symlinks infinitely."""
    try:
        st = path.lstat()
    except (OSError, PermissionError) as exc:
        logger.warning("Cannot stat path '%s': %s", path, exc)
        return None

    # Ignore symlinks to prevent traversal loops or broken target errors
    if stat.S_ISLNK(st.st_mode):
        logger.debug("Skipping symlink: %s", path)
        return None

    if not stat.S_ISREG(st.st_mode):
        return None

    mode_str = oct(stat.S_IMODE(st.st_mode))
    if is_windows():
        attrs = getattr(st, "st_file_attributes", 0)
        owner_str = f"win_attr:{attrs}"
    else:
        uid = getattr(st, "st_uid", 0)
        gid = getattr(st, "st_gid", 0)
        owner_str = f"{uid}:{gid}"

    return {
        "size": st.st_size,
        "mtime": round(st.st_mtime, 6),
        "permissions": mode_str,
        "owner": owner_str,
    }