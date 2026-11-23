"""Command-line interface for FIM built with Typer and Rich."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.logging import RichHandler

from fim import __version__
from fim.alerts import AlertManager
from fim.config import FimConfig, load_config
from fim.database import FimDatabase
from fim.monitor import RealtimeMonitor
from fim.reports import export_csv, export_html
from fim.scanner import FileScanner
from fim.utils import is_admin, is_protected_path

app = typer.Typer(
    name="fim",
    help="Cross-platform File System Integrity Monitoring (FIM) CLI for Windows and Linux.",
    add_completion=False,
)
console = Console()
logger = logging.getLogger("fim")


def _configure_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True, show_path=False)],
        force=True,
    )


def _check_privileges(cfg: FimConfig) -> None:
    if not is_admin():
        protected = [p for p in cfg.watch_paths if is_protected_path(p)]
        if protected:
            logger.warning(
                "Not running as Administrator/root while watching protected paths (%s). "
                "Some system files may be skipped due to permission errors.",
                ", ".join(protected),
            )


def _load_context(config_path: Path, db_override: Optional[Path]) -> tuple[FimConfig, FimDatabase]:
    cfg = load_config(config_path)
    if db_override is not None:
        cfg.database_path = str(db_override)
    db = FimDatabase(cfg.database_path)
    return cfg, db


@app.command("init")
def cmd_init(
    config: Path = typer.Option(Path("config.yaml"), "--config", "-c", help="Path to YAML configuration file."),
    db_path: Optional[Path] = typer.Option(None, "--db", help="Override SQLite baseline database path."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose debug logging."),
) -> None:
    """Scan configured paths and initialize the cryptographic baseline database."""
    _configure_logging(verbose)
    try:
        cfg, db = _load_context(config, db_path)
        _check_privileges(cfg)
        scanner = FileScanner(cfg, db)
        count = scanner.build_baseline()
        console.print(f"[bold green]Baseline initialized:[/bold green] {count} file(s) recorded in '{cfg.database_path}'.")
    except Exception as exc:
        logger.error("Initialization failed: %s", exc)
        raise typer.Exit(code=1)


@app.command("scan")
def cmd_scan(
    config: Path = typer.Option(Path("config.yaml"), "--config", "-c", help="Path to YAML configuration file."),
    db_path: Optional[Path] = typer.Option(None, "--db", help="Override SQLite baseline database path."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose debug logging."),
) -> None:
    """Compare current filesystem state against the baseline and report changes."""
    _configure_logging(verbose)
    try:
        cfg, db = _load_context(config, db_path)
        _check_privileges(cfg)

        ok, msg = db.verify_integrity()
        if not ok:
            logger.error("Baseline integrity check failed before scan: %s", msg)
            raise typer.Exit(code=2)

        scanner = FileScanner(cfg, db)
        events = scanner.scan(persist_events=True)
        if not events:
            console.print("[bold green]OK:[/bold green] No integrity violations detected.")
            raise typer.Exit(code=0)

        alert_mgr = AlertManager(cfg.alerts, console=console)
        alert_mgr.dispatch(events)
        console.print(f"[bold yellow]Scan complete:[/bold yellow] {len(events)} integrity event(s) detected.")
    except typer.Exit:
        raise
    except Exception as exc:
        logger.error("Scan failed: %s", exc)
        raise typer.Exit(code=1)


@app.command("watch")
def cmd_watch(
    config: Path = typer.Option(Path("config.yaml"), "--config", "-c", help="Path to YAML configuration file."),
    db_path: Optional[Path] = typer.Option(None, "--db", help="Override SQLite baseline database path."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose debug logging."),
) -> None:
    """Monitor configured paths in real time using OS filesystem events (Ctrl+C to stop)."""
    _configure_logging(verbose)
    try:
        cfg, db = _load_context(config, db_path)
        _check_privileges(cfg)

        ok, msg = db.verify_integrity()
        if not ok:
            logger.error("Baseline integrity check failed: %s", msg)
            raise typer.Exit(code=2)

        alert_mgr = AlertManager(cfg.alerts, console=console)
        monitor = RealtimeMonitor(cfg, db, alert_mgr)
        console.print("[bold cyan]FIM real-time watcher active.[/bold cyan] Press Ctrl+C to stop.")
        monitor.start()
    except typer.Exit:
        raise
    except Exception as exc:
        logger.error("Watcher failed: %s", exc)
        raise typer.Exit(code=1)


@app.command("report")
def cmd_report(
    fmt: str = typer.Option("csv", "--format", "-f", help="Report format: 'csv' or 'html'."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path."),
    limit: Optional[int] = typer.Option(None, "--limit", "-n", help="Limit number of most recent events."),
    config: Path = typer.Option(Path("config.yaml"), "--config", "-c", help="Path to YAML configuration file."),
    db_path: Optional[Path] = typer.Option(None, "--db", help="Override SQLite baseline database path."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose debug logging."),
) -> None:
    """Export recorded integrity events to CSV or HTML."""
    _configure_logging(verbose)
    fmt_clean = fmt.lower().strip()
    if fmt_clean not in {"csv", "html"}:
        logger.error("Unsupported report format '%s'. Use 'csv' or 'html'.", fmt)
        raise typer.Exit(code=1)

    try:
        cfg, db = _load_context(config, db_path)
        events = db.get_events(limit=limit)
        out_path = output or Path(f"fim_report.{fmt_clean}")

        if fmt_clean == "csv":
            written = export_csv(events, out_path)
        else:
            written = export_html(events, out_path)

        console.print(f"[bold green]Report exported:[/bold green] {written} ({len(events)} event(s)).")
    except Exception as exc:
        logger.error("Report export failed: %s", exc)
        raise typer.Exit(code=1)


@app.command("update-baseline")
def cmd_update_baseline(
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip interactive confirmation prompt."),
    config: Path = typer.Option(Path("config.yaml"), "--config", "-c", help="Path to YAML configuration file."),
    db_path: Optional[Path] = typer.Option(None, "--db", help="Override SQLite baseline database path."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose debug logging."),
) -> None:
    """Accept the current filesystem state as the new trusted baseline."""
    _configure_logging(verbose)
    try:
        cfg, db = _load_context(config, db_path)
        if not yes:
            confirmed = typer.confirm(
                f"Are you sure you want to overwrite the baseline in '{cfg.database_path}' with current disk state?"
            )
            if not confirmed:
                console.print("[yellow]Baseline update aborted.[/yellow]")
                raise typer.Exit(code=0)

        scanner = FileScanner(cfg, db)
        count = scanner.build_baseline()
        console.print(f"[bold green]Baseline updated:[/bold green] {count} file(s) sealed.")
    except typer.Exit:
        raise
    except Exception as exc:
        logger.error("Baseline update failed: %s", exc)
        raise typer.Exit(code=1)


@app.command("verify-db")
def cmd_verify_db(
    config: Path = typer.Option(Path("config.yaml"), "--config", "-c", help="Path to YAML configuration file."),
    db_path: Optional[Path] = typer.Option(None, "--db", help="Override SQLite baseline database path."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose debug logging."),
) -> None:
    """Verify the cryptographic HMAC integrity of the SQLite baseline database."""
    _configure_logging(verbose)
    try:
        _, db = _load_context(config, db_path)
        valid, message = db.verify_integrity()
        if valid:
            console.print(f"[bold green]VERIFIED:[/bold green] {message}")
            raise typer.Exit(code=0)
        console.print(f"[bold red]FAILED:[/bold red] {message}")
        raise typer.Exit(code=2)
    except typer.Exit:
        raise
    except Exception as exc:
        logger.error("Verification error: %s", exc)
        raise typer.Exit(code=1)


@app.command("version")
def cmd_version() -> None:
    """Print FIM version information."""
    console.print(f"FIM v{__version__}")


def main() -> None:
    """CLI entry point."""
    app()


if __name__ == "__main__":
    main()