"""Real-time filesystem monitoring using watchdog with event debouncing and baseline comparison."""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from fim.alerts import AlertManager
from fim.config import FimConfig
from fim.database import BaselineRecord, FimDatabase, IntegrityEvent
from fim.hasher import compute_file_hash
from fim.rules import SeverityEngine
from fim.utils import get_file_metadata, matches_exclude, normalize_path

logger = logging.getLogger(__name__)


class DebouncedFimHandler(FileSystemEventHandler):
    """Watchdog event handler that debounces noisy OS events and evaluates against the baseline."""

    def __init__(
        self,
        config: FimConfig,
        db: FimDatabase,
        alert_manager: AlertManager,
        severity_engine: SeverityEngine,
    ) -> None:
        super().__init__()
        self.config = config
        self.db = db
        self.alert_manager = alert_manager
        self.severity_engine = severity_engine
        self._baseline_cache: dict[str, BaselineRecord] = self.db.get_all_baseline()
        self._lock = threading.Lock()
        self._pending_timers: dict[str, threading.Timer] = {}
        self._db_norm = normalize_path(config.database_path)
        self._log_norm = normalize_path(config.alerts.log_file)

    def _is_ignored(self, path_str: str) -> bool:
        norm = normalize_path(path_str)
        if norm == self._db_norm or norm.startswith(self._db_norm):
            return True
        if norm == self._log_norm or norm.startswith(self._log_norm):
            return True
        return matches_exclude(path_str, self.config.exclude_patterns)

    def _schedule_evaluation(self, path_str: str, hint: str, src_path: str | None = None) -> None:
        if self._is_ignored(path_str):
            return
        norm = normalize_path(path_str)

        with self._lock:
            existing_timer = self._pending_timers.get(norm)
            if existing_timer is not None:
                existing_timer.cancel()

            timer = threading.Timer(
                self.config.debounce_seconds,
                self._evaluate_path,
                args=(norm, hint, normalize_path(src_path) if src_path else None),
            )
            timer.daemon = True
            self._pending_timers[norm] = timer
            timer.start()

    def _evaluate_path(self, norm_path: str, hint: str, old_norm_path: str | None) -> None:
        with self._lock:
            self._pending_timers.pop(norm_path, None)

        path_obj = Path(norm_path)
        now_iso = datetime.now(timezone.utc).isoformat()
        events: list[IntegrityEvent] = []

        with self._lock:
            # Handle explicit move event
            if hint == "MOVED" and old_norm_path:
                old_rec = self._baseline_cache.pop(old_norm_path, None)
                meta = get_file_metadata(path_obj) if path_obj.exists() else None
                if meta is not None:
                    new_hash = compute_file_hash(path_obj, self.config.hash_algorithm)
                    if new_hash:
                        sev = self.severity_engine.evaluate(norm_path, "MOVED").value
                        events.append(
                            IntegrityEvent(
                                event_type="MOVED",
                                path=norm_path,
                                old_path=old_norm_path,
                                severity=sev,
                                old_hash=old_rec.sha256 if old_rec else None,
                                new_hash=new_hash,
                                details=f"Moved from '{old_norm_path}' to '{norm_path}'",
                                timestamp=now_iso,
                            )
                        )
                        self._baseline_cache[norm_path] = BaselineRecord(
                            path=norm_path,
                            sha256=new_hash,
                            size=meta["size"],
                            mtime=meta["mtime"],
                            permissions=meta["permissions"],
                            owner=meta["owner"],
                            updated_at=now_iso,
                        )
                if events:
                    self.db.record_events(events)
                    self.alert_manager.dispatch(events)
                return

            baseline_rec = self._baseline_cache.get(norm_path)

            # File removed
            if not path_obj.exists():
                if baseline_rec is not None:
                    del self._baseline_cache[norm_path]
                    sev = self.severity_engine.evaluate(norm_path, "DELETED").value
                    events.append(
                        IntegrityEvent(
                            event_type="DELETED",
                            path=norm_path,
                            severity=sev,
                            old_hash=baseline_rec.sha256,
                            details="File deleted in real time",
                            timestamp=now_iso,
                        )
                    )
                if events:
                    self.db.record_events(events)
                    self.alert_manager.dispatch(events)
                return

            meta = get_file_metadata(path_obj)
            if meta is None:
                return

            new_hash = compute_file_hash(path_obj, self.config.hash_algorithm)
            if new_hash is None:
                return

            if baseline_rec is None:
                sev = self.severity_engine.evaluate(norm_path, "CREATED").value
                events.append(
                    IntegrityEvent(
                        event_type="CREATED",
                        path=norm_path,
                        severity=sev,
                        new_hash=new_hash,
                        details=f"File created (size={meta['size']}B)",
                        timestamp=now_iso,
                    )
                )
            elif baseline_rec.sha256 != new_hash:
                sev = self.severity_engine.evaluate(norm_path, "MODIFIED").value
                events.append(
                    IntegrityEvent(
                        event_type="MODIFIED",
                        path=norm_path,
                        severity=sev,
                        old_hash=baseline_rec.sha256,
                        new_hash=new_hash,
                        details=f"Content modified (size {baseline_rec.size}B -> {meta['size']}B)",
                        timestamp=now_iso,
                    )
                )
            elif baseline_rec.permissions != meta["permissions"] or baseline_rec.owner != meta["owner"]:
                sev = self.severity_engine.evaluate(norm_path, "PERMISSION_CHANGED").value
                events.append(
                    IntegrityEvent(
                        event_type="PERMISSION_CHANGED",
                        path=norm_path,
                        severity=sev,
                        old_hash=baseline_rec.sha256,
                        new_hash=new_hash,
                        details=(
                            f"Metadata changed: mode {baseline_rec.permissions}->{meta['permissions']}, "
                            f"owner {baseline_rec.owner}->{meta['owner']}"
                        ),
                        timestamp=now_iso,
                    )
                )

            # Update in-memory state so repeated changes emit incremental deltas
            self._baseline_cache[norm_path] = BaselineRecord(
                path=norm_path,
                sha256=new_hash,
                size=meta["size"],
                mtime=meta["mtime"],
                permissions=meta["permissions"],
                owner=meta["owner"],
                updated_at=now_iso,
            )

        if events:
            self.db.record_events(events)
            self.alert_manager.dispatch(events)

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._schedule_evaluation(str(event.src_path), "CREATED")

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._schedule_evaluation(str(event.src_path), "MODIFIED")

    def on_deleted(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._schedule_evaluation(str(event.src_path), "DELETED")

    def on_moved(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._schedule_evaluation(str(event.dest_path), "MOVED", src_path=str(event.src_path))

    def shutdown(self) -> None:
        """Cancel any pending debounce timers on exit."""
        with self._lock:
            for timer in self._pending_timers.values():
                timer.cancel()
            self._pending_timers.clear()


class RealtimeMonitor:
    """Manages the watchdog Observer lifecycle across configured watch paths."""

    def __init__(self, config: FimConfig, db: FimDatabase, alert_manager: AlertManager) -> None:
        self.config = config
        self.db = db
        self.alert_manager = alert_manager
        self.severity_engine = SeverityEngine(config.severity_rules)
        self.handler = DebouncedFimHandler(config, db, alert_manager, self.severity_engine)
        self.observer = Observer()

    def start(self) -> None:
        """Schedule all valid watch paths and block until interrupted (Ctrl+C)."""
        scheduled = 0
        for watch_path in self.config.normalized_watch_paths:
            if not watch_path.exists():
                logger.warning("Watch path does not exist, skipping: %s", watch_path)
                continue
            target_dir = watch_path if watch_path.is_dir() else watch_path.parent
            self.observer.schedule(self.handler, str(target_dir), recursive=True)
            logger.info("Watching directory recursively: %s", target_dir)
            scheduled += 1

        if scheduled == 0:
            raise RuntimeError("No valid watch paths available to monitor.")

        self.observer.start()
        try:
            while self.observer.is_alive():
                time.sleep(0.5)
        except KeyboardInterrupt:
            logger.info("Interrupt received; stopping real-time FIM monitor...")
        finally:
            self.stop()

    def stop(self) -> None:
        """Cleanly stop timers and watchdog observer threads."""
        self.handler.shutdown()
        self.observer.stop()
        self.observer.join(timeout=5.0)
        logger.info("Real-time FIM monitor stopped.")