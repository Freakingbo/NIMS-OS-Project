"""Configuration loading, validation, and default settings management."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]

from fim.utils import normalize_path

logger = logging.getLogger(__name__)

VALID_HASH_ALGORITHMS = {"sha256", "sha512", "sha384", "blake2b"}


def _parse_scalar(val: str) -> Any:
    """Parse a scalar YAML value (bool, int, float, or quoted/unquoted string)."""
    v = val.strip()
    if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
        return v[1:-1]
    low = v.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if low in {"null", "none", "~"}:
        return None
    try:
        return int(v)
    except ValueError:
        pass
    try:
        return float(v)
    except ValueError:
        pass
    return v


def _strip_inline_comment(line: str) -> str:
    """Remove unquoted '#' comments from a YAML line."""
    in_single = False
    in_double = False
    for idx, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            if idx == 0 or line[idx - 1].isspace():
                return line[:idx].rstrip()
    return line.rstrip()


def _fallback_simple_yaml_load(text: str) -> dict[str, Any]:
    """Minimal pure-Python YAML subset parser (mappings, nested dicts, and lists) when PyYAML is absent."""
    root: dict[str, Any] = {}
    stack: list[tuple[int, Any]] = [(-1, root)]

    cleaned_lines: list[tuple[int, str]] = []
    for raw in text.splitlines():
        no_comment = _strip_inline_comment(raw)
        stripped = no_comment.strip()
        if not stripped:
            continue
        indent = len(no_comment) - len(no_comment.lstrip(" "))
        cleaned_lines.append((indent, stripped))

    for idx, (indent, content) in enumerate(cleaned_lines):
        if content.startswith("-") and (len(content) == 1 or content[1].isspace() or content[1] in {'"', "'", ".", "/"}):
            while len(stack) > 1 and (
                indent < stack[-1][0] or (indent == stack[-1][0] and not isinstance(stack[-1][1], list))
            ):
                stack.pop()
            parent = stack[-1][1]
            raw_item = content[1:].strip()
            item_val = _parse_scalar(raw_item) if raw_item else None
            if isinstance(parent, list):
                parent.append(item_val)
            continue

        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]

        if ":" in content:
            key, rest = content.split(":", 1)
            key = key.strip()
            rest = rest.strip()
            if rest == "":
                next_is_list = (
                    idx + 1 < len(cleaned_lines)
                    and cleaned_lines[idx + 1][0] >= indent
                    and cleaned_lines[idx + 1][1].startswith("- ")
                )
                container: Any = [] if next_is_list else {}
                if isinstance(parent, dict):
                    parent[key] = container
                stack.append((indent, container))
            elif rest.startswith("[") and rest.endswith("]"):
                inner = rest[1:-1].strip()
                items = [_parse_scalar(x) for x in inner.split(",") if x.strip()] if inner else []
                if isinstance(parent, dict):
                    parent[key] = items
            else:
                if isinstance(parent, dict):
                    parent[key] = _parse_scalar(rest)

    return root


@dataclass
class SeverityRulesConfig:
    """Rules mapping paths and extensions to severity levels."""

    high_paths: list[str] = field(
        default_factory=lambda: [
            "/etc",
            "/bin",
            "/sbin",
            "/usr/bin",
            "/usr/sbin",
            "C:/Windows/System32",
            "C:/Program Files",
        ]
    )
    high_extensions: list[str] = field(
        default_factory=lambda: [".exe", ".dll", ".sh", ".bin", ".so", ".sys", ".bat", ".ps1"]
    )
    medium_extensions: list[str] = field(
        default_factory=lambda: [".yaml", ".yml", ".json", ".conf", ".cfg", ".ini", ".env", ".toml", ".xml"]
    )
    low_extensions: list[str] = field(
        default_factory=lambda: [".txt", ".md", ".pdf", ".doc", ".docx", ".csv", ".log"]
    )


@dataclass
class EmailAlertConfig:
    """SMTP configuration for optional email alerts."""

    enabled: bool = False
    smtp_host: str = "localhost"
    smtp_port: int = 587
    use_tls: bool = True
    username: str = ""
    password: str = ""
    from_addr: str = "fim-alerts@example.local"
    to_addrs: list[str] = field(default_factory=list)
    min_severity: str = "HIGH"


@dataclass
class AlertsConfig:
    """Alerting output channels configuration."""

    console: bool = True
    log_file: str = "fim_events.jsonl"
    log_max_bytes: int = 5_242_880
    log_backup_count: int = 5
    email: EmailAlertConfig = field(default_factory=EmailAlertConfig)


@dataclass
class FimConfig:
    """Top-level FIM configuration container."""

    watch_paths: list[str] = field(default_factory=lambda: ["."])
    exclude_patterns: list[str] = field(
        default_factory=lambda: [
            "*.tmp",
            "*.swp",
            "*.pyc",
            "__pycache__",
            ".git",
            "*.db",
            "*.db-journal",
            "*.db-wal",
            "*.db-shm",
            "fim_events.jsonl*",
        ]
    )
    hash_algorithm: str = "sha256"
    database_path: str = "fim_baseline.db"
    debounce_seconds: float = 1.0
    severity_rules: SeverityRulesConfig = field(default_factory=SeverityRulesConfig)
    alerts: AlertsConfig = field(default_factory=AlertsConfig)

    @property
    def normalized_watch_paths(self) -> list[Path]:
        """Return resolved Path objects for configured watch paths."""
        return [Path(p).expanduser().resolve() for p in self.watch_paths]


def load_config(config_path: str | Path = "config.yaml") -> FimConfig:
    """Load and validate configuration from a YAML file, falling back to safe defaults."""
    path = Path(config_path)
    if not path.exists():
        logger.warning("Config file '%s' not found; using built-in defaults.", path)
        return FimConfig()

    try:
        raw_text = path.read_text(encoding="utf-8")
        if yaml is not None:
            data: dict[str, Any] = yaml.safe_load(raw_text) or {}
        else:
            data = _fallback_simple_yaml_load(raw_text)
    except Exception as exc:
        raise ValueError(f"Failed to parse YAML configuration '{path}': {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("Configuration file must contain a YAML mapping at the root.")

    watch_paths = data.get("watch_paths")
    if watch_paths is None or watch_paths == {}:
        watch_paths = ["."]
    elif isinstance(watch_paths, str):
        watch_paths = [watch_paths]
    if not isinstance(watch_paths, list) or not all(isinstance(p, str) for p in watch_paths):
        raise ValueError("'watch_paths' must be a list of path strings.")

    exclude_patterns = data.get("exclude_patterns")
    if exclude_patterns is None or exclude_patterns == {}:
        exclude_patterns = FimConfig().exclude_patterns
    elif isinstance(exclude_patterns, str):
        exclude_patterns = [exclude_patterns]
    if not isinstance(exclude_patterns, list):
        raise ValueError("'exclude_patterns' must be a list of glob pattern strings.")

    hash_algo = str(data.get("hash_algorithm", "sha256")).lower()
    if hash_algo not in VALID_HASH_ALGORITHMS:
        raise ValueError(f"Unsupported hash_algorithm '{hash_algo}'. Choose from {VALID_HASH_ALGORITHMS}.")

    db_path = str(data.get("database_path", "fim_baseline.db"))
    debounce = float(data.get("debounce_seconds", 1.0))
    if debounce < 0:
        raise ValueError("'debounce_seconds' must be non-negative.")

    sev_data = data.get("severity_rules", {}) or {}
    default_sev = SeverityRulesConfig()

    def _as_str_list(val: Any, fallback: list[str]) -> list[str]:
        if val is None or val == {}:
            return fallback
        if isinstance(val, str):
            return [val]
        if isinstance(val, list):
            return [str(x) for x in val if x is not None]
        return fallback

    severity_rules = SeverityRulesConfig(
        high_paths=[normalize_path(p) for p in _as_str_list(sev_data.get("high_paths"), default_sev.high_paths)],
        high_extensions=[e.lower() for e in _as_str_list(sev_data.get("high_extensions"), default_sev.high_extensions)],
        medium_extensions=[e.lower() for e in _as_str_list(sev_data.get("medium_extensions"), default_sev.medium_extensions)],
        low_extensions=[e.lower() for e in _as_str_list(sev_data.get("low_extensions"), default_sev.low_extensions)],
    )

    alert_data = data.get("alerts", {}) or {}
    email_data = alert_data.get("email", {}) or {}
    email_cfg = EmailAlertConfig(
        enabled=bool(email_data.get("enabled", False)),
        smtp_host=str(email_data.get("smtp_host", "localhost")),
        smtp_port=int(email_data.get("smtp_port", 587)),
        use_tls=bool(email_data.get("use_tls", True)),
        username=str(email_data.get("username", "")),
        password=str(email_data.get("password", "")),
        from_addr=str(email_data.get("from_addr", "fim-alerts@example.local")),
        to_addrs=_as_str_list(email_data.get("to_addrs"), []),
        min_severity=str(email_data.get("min_severity", "HIGH")).upper(),
    )

    alerts_cfg = AlertsConfig(
        console=bool(alert_data.get("console", True)),
        log_file=str(alert_data.get("log_file", "fim_events.jsonl")),
        log_max_bytes=int(alert_data.get("log_max_bytes", 5_242_880)),
        log_backup_count=int(alert_data.get("log_backup_count", 5)),
        email=email_cfg,
    )

    return FimConfig(
        watch_paths=watch_paths,
        exclude_patterns=exclude_patterns,
        hash_algorithm=hash_algo,
        database_path=db_path,
        debounce_seconds=debounce,
        severity_rules=severity_rules,
        alerts=alerts_cfg,
    )