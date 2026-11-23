"""One-command interactive live demo on real files for presentations."""

from __future__ import annotations

import logging
import os
import shutil
import stat
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rich.console import Console  # noqa: E402
from rich.panel import Panel  # noqa: E402

from fim.alerts import AlertManager  # noqa: E402
from fim.config import AlertsConfig, FimConfig, SeverityRulesConfig  # noqa: E402
from fim.database import FimDatabase  # noqa: E402
from fim.monitor import RealtimeMonitor  # noqa: E402
from fim.reports import export_html  # noqa: E402
from fim.scanner import FileScanner  # noqa: E402
from fim.utils import is_windows  # noqa: E402

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")


def main() -> None:
    console = Console()
    demo_dir = REPO_ROOT / "live_demo_workspace"
    target_dir = demo_dir / "company_server"
    db_path = demo_dir / "fim_live.db"
    log_path = demo_dir / "fim_live.jsonl"
    report_path = demo_dir / "fim_audit_report.html"

    # Clean up any leftover run
    if demo_dir.exists():
        shutil.rmtree(demo_dir, ignore_errors=True)
    target_dir.mkdir(parents=True, exist_ok=True)

    # Seed realistic files
    conf_file = target_dir / "server.conf"
    notes_file = target_dir / "employee_notes.txt"
    script_file = target_dir / "startup.sh"

    conf_file.write_text("port=8080\nallow_root=false\n", encoding="utf-8")
    notes_file.write_text("Q4 Project Roadmap\n", encoding="utf-8")
    script_file.write_text("#!/bin/bash\necho 'Service started'\n", encoding="utf-8")

    cfg = FimConfig(
        watch_paths=[str(target_dir)],
        hash_algorithm="sha256",
        database_path=str(db_path),
        debounce_seconds=0.3,
        severity_rules=SeverityRulesConfig(),
        alerts=AlertsConfig(console=True, log_file=str(log_path)),
    )

    db = FimDatabase(db_path)
    scanner = FileScanner(cfg, db)
    alert_mgr = AlertManager(cfg.alerts, console=console)
    monitor = RealtimeMonitor(cfg, db, alert_mgr)

    console.print(
        Panel.fit(
            f"[bold cyan]FIM Live Interactive Demo[/bold cyan]\n"
            f"Monitoring real directory: [yellow]{target_dir}[/yellow]\n"
            f"Open this folder in File Explorer / Finder if you want to show the files changing live!",
            border_style="cyan",
        )
    )

    # Step 1: Initialize Baseline
    count = scanner.build_baseline()
    ok, msg = db.verify_integrity()
    console.print(f"\n[bold green]✔ Baseline Initialized:[/bold green] {count} files hashed & sealed ({msg})")

    # Start background real-time watcher
    monitor.observer.schedule(monitor.handler, str(target_dir), recursive=True)
    monitor.observer.start()
    time.sleep(0.4)

    try:
        input("\n👉 Press [ENTER] to simulate Step 1: Attacker modifies 'server.conf'...")
        conf_file.write_text("port=8080\nallow_root=true\n", encoding="utf-8")
        time.sleep(0.8)

        input("\n👉 Press [ENTER] to simulate Step 2: Malware drops 'backdoor.exe'...")
        malware_file = target_dir / "backdoor.exe"
        malware_file.write_bytes(b"MZ\x90\x00SIMULATED_MALWARE")
        time.sleep(0.8)

        input("\n👉 Press [ENTER] to simulate Step 3: Attacker changes permissions on 'startup.sh'...")
        if is_windows():
            os.chmod(script_file, stat.S_IREAD)
        else:
            os.chmod(script_file, 0o777)
        time.sleep(0.8)

        input("\n👉 Press [ENTER] to simulate Step 4: Attacker renames & deletes 'employee_notes.txt'...")
        renamed_file = target_dir / "stolen_notes.txt"
        notes_file.rename(renamed_file)
        time.sleep(0.8)
        renamed_file.unlink()
        time.sleep(0.8)

        input("\n👉 Press [ENTER] to generate the HTML Audit Report...")
        events = db.get_events()
        export_html(events, report_path)
        console.print(f"[bold green]✔ HTML Report saved to:[/bold green] {report_path}")

    finally:
        monitor.stop()
        alert_mgr.close()
        if is_windows() and script_file.exists():
            os.chmod(script_file, stat.S_IREAD | stat.S_IWRITE)

    choice = input("\n🧹 Delete demo workspace folder now? [Y/n]: ").strip().lower()
    if choice != "n":
        shutil.rmtree(demo_dir, ignore_errors=True)
        console.print("[dim]Cleaned up live_demo_workspace.[/dim]")
    else:
        console.print(f"[cyan]Files kept at:[/cyan] {demo_dir}")


if __name__ == "__main__":
    main()