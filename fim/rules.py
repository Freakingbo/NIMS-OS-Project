"""Rule-based severity classification engine for file integrity events."""

from __future__ import annotations

from enum import Enum
from pathlib import Path

from fim.config import SeverityRulesConfig
from fim.utils import normalize_path


class Severity(str, Enum):
    """Alert severity levels."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


SEVERITY_ORDER: dict[str, int] = {
    Severity.LOW.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3,
}


class SeverityEngine:
    """Evaluates file paths and metadata against configurable severity rules."""

    def __init__(self, rules: SeverityRulesConfig | None = None) -> None:
        self.rules = rules or SeverityRulesConfig()
        self._normalized_high_paths = [normalize_path(p).lower() for p in self.rules.high_paths]
        self._high_exts = {ext.lower() if ext.startswith(".") else f".{ext.lower()}" for ext in self.rules.high_extensions}
        self._med_exts = {ext.lower() if ext.startswith(".") else f".{ext.lower()}" for ext in self.rules.medium_extensions}
        self._low_exts = {ext.lower() if ext.startswith(".") else f".{ext.lower()}" for ext in self.rules.low_extensions}

    def evaluate(self, file_path: str | Path, event_type: str = "") -> Severity:
        """
        Determine severity (HIGH, MEDIUM, LOW) for a given file path and event type.

        Priority:
        1. System/sensitive directories -> HIGH
        2. Executable/binary extensions -> HIGH
        3. Configuration file extensions -> MEDIUM
        4. User document extensions -> LOW
        5. Default fallback -> MEDIUM
        """
        norm_path = normalize_path(file_path).lower()
        suffix = Path(file_path).suffix.lower()

        for high_dir in self._normalized_high_paths:
            if norm_path == high_dir or norm_path.startswith(high_dir.rstrip("/") + "/"):
                return Severity.HIGH

        if suffix in self._high_exts:
            return Severity.HIGH

        if suffix in self._med_exts:
            return Severity.MEDIUM

        if suffix in self._low_exts:
            return Severity.LOW

        # Permission changes on unknown files warrant elevated attention
        if event_type == "PERMISSION_CHANGED":
            return Severity.MEDIUM

        return Severity.LOW