"""Alert dispatching: Rich console output, rotating JSON-Lines logs, and optional SMTP email."""

from __future__ import annotations

import json
import logging
import smtplib
from email.message import EmailMessage
from logging.handlers import RotatingFileHandler
from pathlib import Path

from rich.console import Console
from rich.table import Table

from fim.config import AlertsConfig
from fim.database import IntegrityEvent
from fim.rules import SEVERITY_ORDER

logger = logging.getLogger(__name__)

SEVERITY_COLORS: dict[str, str] = {
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "bold cyan",
}


class AlertManager:
    """Dispatches integrity alerts to console, rotating JSONL file, and SMTP email."""

    def __init__(self, config: AlertsConfig, console: Console | None = None) -> None:
        self.config = config
        self.console = console or Console()
        self._json_logger = self._setup_json_logger()

    def _setup_json_logger(self) -> logging.Logger:
        jsonl_logger = logging.getLogger(f"fim.events.{id(self)}")
        jsonl_logger.setLevel(logging.INFO)
        jsonl_logger.propagate = False

        if self.config.log_file:
            log_path = Path(self.config.log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            handler = RotatingFileHandler(
                filename=str(log_path),
                maxBytes=self.config.log_max_bytes,
                backupCount=self.config.log_backup_count,
                encoding="utf-8",
            )
            handler.setFormatter(logging.Formatter("%(message)s"))
            jsonl_logger.addHandler(handler)

        return jsonl_logger

    def close(self) -> None:
        """Flush and close all file handlers attached to the JSONL logger (important on Windows)."""
        for handler in list(self._json_logger.handlers):
            handler.flush()
            handler.close()
            self._json_logger.removeHandler(handler)

    def dispatch(self, events: list[IntegrityEvent]) -> None:
        """Send a batch of integrity events across all configured channels."""
        if not events:
            return

        if self.config.log_file:
            for ev in events:
                self._write_jsonl(ev)

        if self.config.console:
            self._print_console_table(events)

        if self.config.email.enabled:
            self._send_email_alerts(events)

    def _write_jsonl(self, event: IntegrityEvent) -> None:
        payload = {
            "timestamp": event.timestamp,
            "event_type": event.event_type,
            "severity": event.severity,
            "path": event.path,
            "old_path": event.old_path,
            "old_hash": event.old_hash,
            "new_hash": event.new_hash,
            "details": event.details,
        }
        self._json_logger.info(json.dumps(payload, ensure_ascii=False))

    def _print_console_table(self, events: list[IntegrityEvent]) -> None:
        table = Table(title="FIM Integrity Alerts", show_lines=False)
        table.add_column("Timestamp", style="dim", no_wrap=True)
        table.add_column("Severity", justify="center")
        table.add_column("Event", style="bold")
        table.add_column("Path", overflow="fold")
        table.add_column("Details", overflow="fold")

        for ev in events:
            color = SEVERITY_COLORS.get(ev.severity, "white")
            table.add_row(
                ev.timestamp,
                f"[{color}]{ev.severity}[/{color}]",
                ev.event_type,
                ev.path,
                ev.details,
            )
        self.console.print(table)

    def _send_email_alerts(self, events: list[IntegrityEvent]) -> None:
        email_cfg = self.config.email
        if not email_cfg.to_addrs:
            logger.warning("Email alerts enabled, but 'to_addrs' is empty.")
            return

        min_rank = SEVERITY_ORDER.get(email_cfg.min_severity.upper(), 3)
        qualifying = [e for e in events if SEVERITY_ORDER.get(e.severity, 1) >= min_rank]
        if not qualifying:
            return

        msg = EmailMessage()
        msg["Subject"] = f"[FIM ALERT] {len(qualifying)} File Integrity Event(s) Detected"
        msg["From"] = email_cfg.from_addr
        msg["To"] = ", ".join(email_cfg.to_addrs)

        lines = ["File System Integrity Monitoring Alert Summary:\n"]
        for ev in qualifying:
            lines.append(f"- [{ev.severity}] {ev.event_type}: {ev.path} ({ev.details}) @ {ev.timestamp}")
        msg.set_content("\n".join(lines))

        try:
            with smtplib.SMTP(email_cfg.smtp_host, email_cfg.smtp_port, timeout=15) as server:
                if email_cfg.use_tls:
                    server.starttls()
                if email_cfg.username and email_cfg.password:
                    server.login(email_cfg.username, email_cfg.password)
                server.send_message(msg)
            logger.info("Sent email alert for %d event(s).", len(qualifying))
        except Exception as exc:
            logger.error("Failed to send SMTP alert email: %s", exc)