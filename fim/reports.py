"""Export recorded integrity events into CSV and standalone HTML reports."""

from __future__ import annotations

import csv
import html
from datetime import datetime, timezone
from pathlib import Path

from fim.database import IntegrityEvent


def export_csv(events: list[IntegrityEvent], output_path: str | Path) -> Path:
    """Write integrity events to a UTF-8 CSV file."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "id",
        "timestamp",
        "severity",
        "event_type",
        "path",
        "old_path",
        "old_hash",
        "new_hash",
        "details",
    ]
    with out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for ev in events:
            writer.writerow(
                {
                    "id": ev.id if ev.id is not None else "",
                    "timestamp": ev.timestamp,
                    "severity": ev.severity,
                    "event_type": ev.event_type,
                    "path": ev.path,
                    "old_path": ev.old_path or "",
                    "old_hash": ev.old_hash or "",
                    "new_hash": ev.new_hash or "",
                    "details": ev.details,
                }
            )
    return out


def export_html(events: list[IntegrityEvent], output_path: str | Path) -> Path:
    """Generate a self-contained HTML security audit report of integrity events."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    high_cnt = sum(1 for e in events if e.severity == "HIGH")
    med_cnt = sum(1 for e in events if e.severity == "MEDIUM")
    low_cnt = sum(1 for e in events if e.severity == "LOW")

    rows_html: list[str] = []
    for ev in events:
        sev_cls = ev.severity.lower()
        rows_html.append(
            f"""
            <tr>
                <td>{html.escape(ev.timestamp)}</td>
                <td><span class="badge {sev_cls}">{html.escape(ev.severity)}</span></td>
                <td><strong>{html.escape(ev.event_type)}</strong></td>
                <td class="mono">{html.escape(ev.path)}</td>
                <td class="mono">{html.escape((ev.old_hash or '-')[:16])}</td>
                <td class="mono">{html.escape((ev.new_hash or '-')[:16])}</td>
                <td>{html.escape(ev.details)}</td>
            </tr>
            """
        )

    table_body = "\n".join(rows_html) if rows_html else '<tr><td colspan="7">No integrity events recorded.</td></tr>'

    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>FIM Integrity Audit Report</title>
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 2rem; background: #f8fafc; color: #0f172a; }}
    h1 {{ margin-bottom: 0.25rem; }}
    .meta {{ color: #475569; margin-bottom: 1.5rem; font-size: 0.9rem; }}
    .summary {{ display: flex; gap: 1rem; margin-bottom: 1.5rem; }}
    .card {{ background: #fff; padding: 1rem 1.5rem; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
    .card h3 {{ margin: 0 0 0.25rem 0; font-size: 0.85rem; color: #64748b; text-transform: uppercase; }}
    .card p {{ margin: 0; font-size: 1.5rem; font-weight: bold; }}
    table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
    th, td {{ padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #e2e8f0; font-size: 0.88rem; }}
    th {{ background: #1e293b; color: #f8fafc; }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.82rem; }}
    .badge {{ padding: 0.2rem 0.55rem; border-radius: 4px; font-weight: 700; font-size: 0.75rem; color: #fff; }}
    .badge.high {{ background: #dc2626; }}
    .badge.medium {{ background: #d97706; }}
    .badge.low {{ background: #0284c7; }}
</style>
</head>
<body>
    <h1>File System Integrity Monitoring (FIM) Report</h1>
    <div class="meta">Generated: {html.escape(generated_at)} | Total Events: {len(events)}</div>
    <div class="summary">
        <div class="card"><h3>High Severity</h3><p style="color:#dc2626;">{high_cnt}</p></div>
        <div class="card"><h3>Medium Severity</h3><p style="color:#d97706;">{med_cnt}</p></div>
        <div class="card"><h3>Low Severity</h3><p style="color:#0284c7;">{low_cnt}</p></div>
    </div>
    <table>
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Severity</th>
                <th>Event</th>
                <th>Path</th>
                <th>Old Hash</th>
                <th>New Hash</th>
                <th>Details</th>
            </tr>
        </thead>
        <tbody>
            {table_body}
        </tbody>
    </table>
</body>
</html>
"""
    out.write_text(document, encoding="utf-8")
    return out