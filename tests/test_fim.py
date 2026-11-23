"""Comprehensive pytest suite for FIM covering baselines, events, excludes, rules, DB tampering, and large file hashing."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
from pathlib import Path

import pytest

from fim.config import AlertsConfig, FimConfig, SeverityRulesConfig, load_config
from fim.database import FimDatabase
from fim.hasher import compute_file_hash
from fim.reports import export_csv, export_html
from fim.rules import Severity, SeverityEngine
from fim.scanner import FileScanner
from fim.utils import is_windows, normalize_path


def _make_config(watch_dir: Path, db_path: Path, log_path: Path) -> FimConfig:
    return FimConfig(
        watch_paths=[str(watch_dir)],
        exclude_patterns=["*.tmp", "*.ignore", ".git"],
        hash_algorithm="sha256",
        database_path=str(db_path),
        debounce_seconds=0.1,
        severity_rules=SeverityRulesConfig(),
        alerts=AlertsConfig(console=False, log_file=str(log_path)),
    )


def test_baseline_creation_and_clean_scan(tmp_path: Path) -> None:
    """Verify baseline initialization stores expected file counts and a clean scan produces zero events."""
    watch_dir = tmp_path / "monitored"
    watch_dir.mkdir()
    (watch_dir / "readme.txt").write_text("hello world", encoding="utf-8")
    (watch_dir / "settings.yaml").write_text("debug: false", encoding="utf-8")

    db_path = tmp_path / "fim.db"
    cfg = _make_config(watch_dir, db_path, tmp_path / "events.jsonl")
    db = FimDatabase(db_path)
    scanner = FileScanner(cfg, db)

    count = scanner.build_baseline()
    assert count == 2
    assert db.baseline_count() == 2

    events = scanner.scan()
    assert events == []


def test_detect_all_event_types(tmp_path: Path) -> None:
    """Verify detection of CREATED, MODIFIED, DELETED, MOVED, and PERMISSION_CHANGED events."""
    watch_dir = tmp_path / "monitored"
    watch_dir.mkdir()

    f_modify = watch_dir / "app.conf"
    f_delete = watch_dir / "old_notes.txt"
    f_move = watch_dir / "move_me.txt"
    f_perm = watch_dir / "script.sh"

    f_modify.write_text("port=8080\n", encoding="utf-8")
    f_delete.write_text("obsolete\n", encoding="utf-8")
    f_move.write_text("unique content for move detection 12345\n", encoding="utf-8")
    f_perm.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")

    db_path = tmp_path / "fim.db"
    cfg = _make_config(watch_dir, db_path, tmp_path / "events.jsonl")
    db = FimDatabase(db_path)
    scanner = FileScanner(cfg, db)
    scanner.build_baseline()

    # 1. Modify
    f_modify.write_text("port=9090\n", encoding="utf-8")

    # 2. Delete
    f_delete.unlink()

    # 3. Move
    f_moved_dest = watch_dir / "moved_here.txt"
    f_move.rename(f_moved_dest)

    # 4. Create
    f_created = watch_dir / "payload.exe"
    f_created.write_bytes(b"MZ\x90\x00dummy_binary")

    # 5. Permission change (cross-platform: read-only toggle works on both Windows and Linux)
    if is_windows():
        os.chmod(f_perm, stat.S_IREAD)
    else:
        os.chmod(f_perm, 0o755)

    events = scanner.scan()
    by_type = {e.event_type: e for e in events}

    assert "MODIFIED" in by_type
    assert by_type["MODIFIED"].path == normalize_path(f_modify)
    assert by_type["MODIFIED"].severity == "MEDIUM"

    assert "DELETED" in by_type
    assert by_type["DELETED"].path == normalize_path(f_delete)

    assert "MOVED" in by_type
    assert by_type["MOVED"].old_path == normalize_path(f_move)
    assert by_type["MOVED"].path == normalize_path(f_moved_dest)

    assert "CREATED" in by_type
    assert by_type["CREATED"].path == normalize_path(f_created)
    assert by_type["CREATED"].severity == "HIGH"

    assert "PERMISSION_CHANGED" in by_type
    assert by_type["PERMISSION_CHANGED"].path == normalize_path(f_perm)

    # Restore write permission on Windows so pytest tmp_path cleanup succeeds smoothly
    if is_windows():
        os.chmod(f_perm, stat.S_IWRITE | stat.S_IREAD)


def test_exclude_patterns(tmp_path: Path) -> None:
    """Ensure files and directories matching exclude_patterns are ignored during scans."""
    watch_dir = tmp_path / "monitored"
    watch_dir.mkdir()
    (watch_dir / "valid.txt").write_text("keep me", encoding="utf-8")
    (watch_dir / "scratch.tmp").write_text("ignore me", encoding="utf-8")
    git_dir = watch_dir / ".git"
    git_dir.mkdir()
    (git_dir / "HEAD").write_text("ref: refs/heads/main", encoding="utf-8")

    db_path = tmp_path / "fim.db"
    cfg = _make_config(watch_dir, db_path, tmp_path / "events.jsonl")
    db = FimDatabase(db_path)
    scanner = FileScanner(cfg, db)

    count = scanner.build_baseline()
    assert count == 1

    # Adding another excluded file should not trigger alerts
    (watch_dir / "new.tmp").write_text("still ignored", encoding="utf-8")
    assert scanner.scan() == []


def test_severity_rules(tmp_path: Path) -> None:
    """Verify HIGH, MEDIUM, and LOW severity classifications."""
    rules = SeverityRulesConfig(
        high_paths=[normalize_path(tmp_path / "sysdir")],
        high_extensions=[".exe", ".sh"],
        medium_extensions=[".yaml", ".conf"],
        low_extensions=[".txt", ".md"],
    )
    engine = SeverityEngine(rules)

    assert engine.evaluate(tmp_path / "sysdir" / "notes.txt") == Severity.HIGH
    assert engine.evaluate(tmp_path / "downloads" / "dropper.exe") == Severity.HIGH
    assert engine.evaluate(tmp_path / "config" / "app.yaml") == Severity.MEDIUM
    assert engine.evaluate(tmp_path / "docs" / "todo.md") == Severity.LOW


def test_database_tamper_detection(tmp_path: Path) -> None:
    """Verify that direct SQLite tampering of baseline hashes is caught by verify_integrity()."""
    watch_dir = tmp_path / "monitored"
    watch_dir.mkdir()
    target = watch_dir / "critical.bin"
    target.write_bytes(b"\x01\x02\x03\x04")

    db_path = tmp_path / "fim.db"
    cfg = _make_config(watch_dir, db_path, tmp_path / "events.jsonl")
    db = FimDatabase(db_path)
    scanner = FileScanner(cfg, db)
    scanner.build_baseline()

    ok, _ = db.verify_integrity()
    assert ok is True

    # Simulate an attacker altering the stored SHA-256 directly in SQLite to hide a backdoor
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("UPDATE baseline SET sha256 = '0000000000000000000000000000000000000000000000000000000000000000'")
        conn.commit()

    ok_after, msg = db.verify_integrity()
    assert ok_after is False
    assert "TAMPERING DETECTED" in msg


def test_chunked_hashing_large_file(tmp_path: Path) -> None:
    """Verify chunked SHA-256 matches single-shot hashlib digest on a multi-megabyte file."""
    large_file = tmp_path / "large_blob.bin"
    # Create a ~3.5 MB deterministic payload spanning many 64 KiB chunks
    chunk = os.urandom(65536)
    expected_hasher = hashlib.sha256()

    with large_file.open("wb") as f:
        for _ in range(56):
            f.write(chunk)
            expected_hasher.update(chunk)

    computed = compute_file_hash(large_file, algorithm="sha256", chunk_size=16384)
    assert computed == expected_hasher.hexdigest()


def test_reports_export_and_yaml_loader(tmp_path: Path) -> None:
    """Verify YAML loading and CSV/HTML report exports."""
    yaml_file = tmp_path / "custom_config.yaml"
    yaml_file.write_text(
        """
watch_paths:
  - "."
hash_algorithm: "sha256"
debounce_seconds: 0.5
""",
        encoding="utf-8",
    )
    loaded = load_config(yaml_file)
    assert loaded.hash_algorithm == "sha256"
    assert loaded.debounce_seconds == 0.5

    watch_dir = tmp_path / "monitored"
    watch_dir.mkdir()
    db_path = tmp_path / "fim.db"
    cfg = _make_config(watch_dir, db_path, tmp_path / "events.jsonl")
    db = FimDatabase(db_path)
    scanner = FileScanner(cfg, db)
    scanner.build_baseline()

    (watch_dir / "malicious.exe").write_bytes(b"MZ")
    events = scanner.scan()

    csv_out = export_csv(events, tmp_path / "out.csv")
    html_out = export_html(events, tmp_path / "out.html")

    assert csv_out.exists()
    assert "malicious.exe" in csv_out.read_text(encoding="utf-8")
    assert html_out.exists()
    assert "malicious.exe" in html_out.read_text(encoding="utf-8")