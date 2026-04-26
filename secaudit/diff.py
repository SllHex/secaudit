"""Structured diffing helpers for audit reports."""

from __future__ import annotations

from .models import AuditDiff, AuditReport, ResultChange
from .scoring import issue_sort_key


def compare_reports(old_report: AuditReport, new_report: AuditReport) -> AuditDiff:
    """Compute a structured diff between two audit reports."""

    old_map = {(item.module, item.name): item for item in old_report.results}
    new_map = {(item.module, item.name): item for item in new_report.results}

    added = sorted((new_map[key] for key in new_map.keys() - old_map.keys()), key=issue_sort_key)
    removed = sorted((old_map[key] for key in old_map.keys() - new_map.keys()), key=issue_sort_key)
    changed: list[ResultChange] = []
    for key in sorted(old_map.keys() & new_map.keys()):
        old_item = old_map[key]
        new_item = new_map[key]
        old_tuple = (old_item.status, old_item.severity, old_item.summary, old_item.details)
        new_tuple = (new_item.status, new_item.severity, new_item.summary, new_item.details)
        if old_tuple != new_tuple:
            changed.append(
                ResultChange(
                    module=new_item.module,
                    name=new_item.name,
                    old_status=old_item.status,
                    new_status=new_item.status,
                    old_severity=old_item.severity,
                    new_severity=new_item.severity,
                    old_summary=old_item.summary,
                    new_summary=new_item.summary,
                )
            )

    return AuditDiff(
        target=new_report.target or old_report.target,
        score_before=old_report.score,
        score_after=new_report.score,
        grade_before=old_report.grade,
        grade_after=new_report.grade,
        counts_before=old_report.counts,
        counts_after=new_report.counts,
        added=added,
        removed=removed,
        changed=changed,
    )
