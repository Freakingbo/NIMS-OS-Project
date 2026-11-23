"""Directory traversal, baseline construction, and baseline-vs-filesystem comparison."""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from fim.config import FimConfig
from fim.database import BaselineRecord, FimDatabase, IntegrityEvent
from fim.hasher import compute_file_hash
from fim.rules import SeverityEngine
from fim.utils import get_file_metadata, matches_exclude, normalize_path

logger = logging.getLogger(__name__)


class FileScanner:
    """Scans configured directories to build baselines and detect integrity drift."""

    def __init__(self, config: FimConfig, db: FimDatabase, severity_engine: SeverityEngine | None = None) -> None:
        self.config = config
        self.db = db
        self.severity_engine = severity_engine or SeverityEngine(config.severity_rules)
        self._db_norm_path = normalize_path(config.database_path)
        self._log_norm_path = normalize_path(config.alerts.log_file)

    def _should_skip(self, path: Path) -> bool:
        norm = normalize_path(path)
        if norm == self._db_norm_path or norm.startswith(self._db_norm_path):
            return True
        if norm == self._log_norm_path or norm.startswith(self._log_norm_path):
            return True
        return matches_exclude(path, self.config.exclude_patterns)

    def collect_current_state(self) -> dict[str, BaselineRecord]:
        """Walk all configured watch_paths safely (without following symlinks) and collect file state."""
        state: dict[str, BaselineRecord] = {}
        now_iso = datetime.now(timezone.utc).isoformat()

        for watch_root in self.config.normalized_watch_paths:
            if not watch_root.exists():
                logger.warning("Configured watch path does not exist: %s", watch_root)
                continue

            if watch_root.is_file():
                rec = self._inspect_file(watch_root, now_iso)
                if rec:
                    state[rec.path] = rec
                continue

            for dirpath, dirnames, filenames in os.walk(watch_root, followlinks=False):
                current_dir = Path(dirpath)
                # Filter excluded directories in-place to avoid descending into them
                dirnames[:] = [
                    d for d in dirnames
                    if not self._should_skip(current_dir / d) and not (current_dir / d).is_symlink()
                ]
                for fname in filenames:
                    fpath = current_dir / fname
                    rec = self._inspect_file(fpath, now_iso)
                    if rec:
                        state[rec.path] = rec

        return state

    def _inspect_file(self, fpath: Path, timestamp_iso: str) -> BaselineRecord | None:
        if self._should_skip(fpath):
            return None

        meta = get_file_metadata(fpath)
        if meta is None:
            return None

        digest = compute_file_hash(fpath, algorithm=self.config.hash_algorithm)
        if digest is None:
            return None

        norm_path = normalize_path(fpath)
        return BaselineRecord(
            path=norm_path,
            sha256=digest,
            size=meta["size"],
            mtime=meta["mtime"],
            permissions=meta["permissions"],
            owner=meta["owner"],
            updated_at=timestamp_iso,
        )

    def build_baseline(self) -> int:
        """Scan configured paths and store the resulting baseline in SQLite."""
        records_map = self.collect_current_state()
        count = self.db.replace_baseline(list(records_map.values()))
        logger.info("Baseline built with %d files.", count)
        return count

    def scan(self, persist_events: bool = True) -> list[IntegrityEvent]:
        """
        Compare current filesystem state against stored baseline.

        Detects: CREATED, MODIFIED, DELETED, MOVED (via matching SHA-256 + size), and PERMISSION_CHANGED.
        """
        baseline = self.db.get_all_baseline()
        current = self.collect_current_state()
        now_iso = datetime.now(timezone.utc).isoformat()

        baseline_paths = set(baseline.keys())
        current_paths = set(current.keys())

        added_paths = sorted(current_paths - baseline_paths)
        removed_paths = sorted(baseline_paths - current_paths)
        common_paths = sorted(baseline_paths & current_paths)

        events: list[IntegrityEvent] = []

        # Detect MOVED files by correlating removed and added files with identical hash & size
        removed_by_sig: dict[tuple[str, int], list[str]] = {}
        for r_path in removed_paths:
            b_rec = baseline[r_path]
            removed_by_sig.setdefault((b_rec.sha256, b_rec.size), []).append(r_path)

        matched_added: set[str] = set()
        matched_removed: set[str] = set()

        for a_path in added_paths:
            c_rec = current[a_path]
            sig = (c_rec.sha256, c_rec.size)
            candidates = removed_by_sig.get(sig)
            if candidates:
                old_path = candidates.pop(0)
                matched_added.add(a_path)
                matched_removed.add(old_path)
                sev = self.severity_engine.evaluate(a_path, "MOVED").value
                events.append(
                    IntegrityEvent(
                        event_type="MOVED",
                        path=a_path,
                        old_path=old_path,
                        severity=sev,
                        old_hash=c_rec.sha256,
                        new_hash=c_rec.sha256,
                        details=f"Moved from '{old_path}' to '{a_path}'",
                        timestamp=now_iso,
                    )
                )

        for a_path in added_paths:
            if a_path in matched_added:
                continue
            c_rec = current[a_path]
            sev = self.severity_engine.evaluate(a_path, "CREATED").value
            events.append(
                IntegrityEvent(
                    event_type="CREATED",
                    path=a_path,
                    severity=sev,
                    new_hash=c_rec.sha256,
                    details=f"New file detected (size={c_rec.size}B)",
                    timestamp=now_iso,
                )
            )

        for r_path in removed_paths:
            if r_path in matched_removed:
                continue
            b_rec = baseline[r_path]
            sev = self.severity_engine.evaluate(r_path, "DELETED").value
            events.append(
                IntegrityEvent(
                    event_type="DELETED",
                    path=r_path,
                    severity=sev,
                    old_hash=b_rec.sha256,
                    details="File removed from monitored path",
                    timestamp=now_iso,
                )
            )

        for path in common_paths:
            b_rec = baseline[path]
            c_rec = current[path]

            if b_rec.sha256 != c_rec.sha256:
                sev = self.severity_engine.evaluate(path, "MODIFIED").value
                events.append(
                    IntegrityEvent(
                        event_type="MODIFIED",
                        path=path,
                        severity=sev,
                        old_hash=b_rec.sha256,
                        new_hash=c_rec.sha256,
                        details=f"Content hash changed (size {b_rec.size}B -> {c_rec.size}B)",
                        timestamp=now_iso,
                    )
                )
            elif b_rec.permissions != c_rec.permissions or b_rec.owner != c_rec.owner:
                sev = self.severity_engine.evaluate(path, "PERMISSION_CHANGED").value
                events.append(
                    IntegrityEvent(
                        event_type="PERMISSION_CHANGED",
                        path=path,
                        severity=sev,
                        old_hash=b_rec.sha256,
                        new_hash=c_rec.sha256,
                        details=(
                            f"Metadata changed: mode {b_rec.permissions}->{c_rec.permissions}, "
                            f"owner {b_rec.owner}->{c_rec.owner}"
                        ),
                        timestamp=now_iso,
                    )
                )

        if persist_events and events:
            self.db.record_events(events)

        return events