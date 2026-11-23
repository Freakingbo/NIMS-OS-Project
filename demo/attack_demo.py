"""Interactive end-to-end simulation demonstrating FIM detection of simulated attack behaviors."""

from __future__ import annotations

import logging
import os
import stat
import sys
import tempfile
from pathlib import Path

# Allow running directly via `python demo/attack_demo.py` from repo root
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rich.console import Console  # noqa: E402
from rich.panel import Panel  # noqa: E402

from fim.alerts import AlertManager  # noqa: E402
from fim.config import AlertsConfig, FimConfig, SeverityRulesConfig  # noqa: E402
from fim.database import FimDatabase  # noqa: E402
from fim.scanner import FileScanner  # noqa: E402
from fim.utils import is_windows  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("fim.demo")


def run_demo() -> None:
    """Create a sandbox directory, establish a baseline, simulate tampering, and display alerts."""
    console = Console()
    console.print(Panel.fit("[bold cyan]FIM Simulated Intrusion & Integrity Drift Demo[/bold cyan]"))

    with tempfile.TemporaryDirectory(prefix="fim_demo_", ignore_cleanup_errors=True) as tmp_dir:
        sandbox = Path(tmp_dir)
        monitored_dir = sandbox / "target_host"
        monitored_dir.mkdir(parents=True, exist_ok=True)

        db_path = sandbox / "fim_demo.db"
        log_path = sandbox / "fim_demo_events.jsonl"

        # Seed initial legitimate files
        config_file = monitored_dir / "sshd_config.conf"
        notes_file = monitored_dir / "release_notes.txt"
        deploy_script = monitored_dir / "deploy.sh"

        config_file.write_text("PermitRootLogin no\nPasswordAuthentication no\n", encoding="utf-8")
        notes_file.write_text("v1.0.0 - Initial production release.\n", encoding="utf-8")
        deploy_script.write_text("#!/bin/bash\necho 'Deploying service...'\n", encoding="utf-8")

        cfg = FimConfig(
            watch_paths=[str(monitored_dir)],
            hash_algorithm="sha256",
            database_path=str(db_path),
            severity_rules=SeverityRulesConfig(),
            alerts=AlertsConfig(console=True, log_file=str(log_path)),
        )

        db = FimDatabase(db_path)
        scanner = FileScanner(cfg, db)
        alert_mgr = AlertManager(cfg.alerts, console=console)

        indexed = scanner.build_baseline()
        console.print(f"[green]Step 1:[/green] Baseline created with {indexed} legitimate files in '{monitored_dir}'.\n")

        # Simulate attacker actions
        console.print("[yellow]Step 2:[/yellow] Simulating attacker actions:")
        console.print("  1. Modifying 'sshd_config.conf' to allow root login (MODIFIED)")
        config_file.write_text("PermitRootLogin yes\nPasswordAuthentication yes\n", encoding="utf-8")

        console.print("  2. Deleting 'release_notes.txt' (DELETED)")
        notes_file.unlink()

        console.print("  3. Dropping malicious executable 'beacon.exe' (CREATED - HIGH)")
        dropped_exe = monitored_dir / "beacon.exe"
        dropped_exe.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00SIMULATED_PAYLOAD")

        console.print("  4. Altering permissions on 'deploy.sh' (PERMISSION_CHANGED)")
        if is_windows():
            os.chmod(deploy_script, stat.S_IREAD)
        else:
            os.chmod(deploy_script, 0o777)

        console.print("\n[cyan]Step 3:[/cyan] Running FIM scan against baseline...\n")
        events = scanner.scan(persist_events=True)
        alert_mgr.dispatch(events)

        valid, verify_msg = db.verify_integrity()
        console.print(f"\n[bold]Baseline Database Integrity Check:[/bold] {verify_msg} (valid={valid})")

        # Close log file handles and restore permissions on Windows so TemporaryDirectory cleanup succeeds
        alert_mgr.close()
        if is_windows():
            os.chmod(deploy_script, stat.S_IREAD | stat.S_IWRITE)


if __name__ == "__main__":
    run_demo()