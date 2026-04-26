"""JSON report helpers."""

from __future__ import annotations

import json as stdlib_json
from pathlib import Path

from ..errors import ReportError
from ..models import AuditDiff, AuditReport


def render_json_report(report: AuditReport, pretty: bool = True) -> str:
    """Render an audit report as JSON."""

    return stdlib_json.dumps(report.to_dict(), indent=2 if pretty else None)


def render_json_diff(diff: AuditDiff, pretty: bool = True) -> str:
    """Render a report diff as JSON."""

    return stdlib_json.dumps(diff.to_dict(), indent=2 if pretty else None)


def load_json_report(path: str | Path) -> AuditReport:
    """Load a previously saved audit report from disk."""

    try:
        data = stdlib_json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise ReportError(f"Could not load JSON report from {path}: {exc}") from exc
    return AuditReport.from_dict(data)
