"""Risk scoring, severity summaries, and exit policies."""

from __future__ import annotations

from .models import AuditReport, CheckResult, SEVERITY_ORDER, STATUS_ORDER, SeverityType

FAIL_PENALTIES = {"critical": 26.0, "high": 12.0, "medium": 6.0, "low": 2.5, "info": 0.0}
WARN_PENALTIES = {"critical": 10.0, "high": 5.0, "medium": 2.5, "low": 0.75, "info": 0.0}


def issue_sort_key(result: CheckResult) -> tuple[int, int, str, str]:
    """Sort issues by severity, then status, then module and name."""

    return (
        SEVERITY_ORDER.get(result.severity, 99),
        STATUS_ORDER.get(result.status, 99),
        result.module,
        result.name,
    )


def top_issues(results: list[CheckResult], limit: int = 8) -> list[CheckResult]:
    """Return the most important non-pass results."""

    issues = [item for item in results if item.status in {"FAIL", "WARN"}]
    return sorted(issues, key=issue_sort_key)[:limit]


def count_severity_levels(results: list[CheckResult]) -> dict[str, int]:
    """Count non-pass findings by severity and include passed findings."""

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "passed": 0}
    for item in results:
        if item.status == "PASS":
            counts["passed"] += 1
        else:
            counts[item.severity] = counts.get(item.severity, 0) + 1
    return counts


def _diminishing_factor(index: int) -> float:
    """Return the fractional impact for the Nth finding in a severity bucket."""

    if index <= 0:
        return 1.0
    if index == 1:
        return 0.6
    if index == 2:
        return 0.35
    if index == 3:
        return 0.2
    return 0.1


def score_results(results: list[CheckResult]) -> int:
    """Compute a 0-100 security score with diminishing penalties."""

    score = 100.0
    fail_counts: dict[str, int] = {key: 0 for key in FAIL_PENALTIES}
    warn_counts: dict[str, int] = {key: 0 for key in WARN_PENALTIES}
    for item in sorted(results, key=issue_sort_key):
        if item.status == "FAIL":
            severity_count = fail_counts[item.severity]
            fail_counts[item.severity] = severity_count + 1
            score -= FAIL_PENALTIES[item.severity] * _diminishing_factor(severity_count)
        elif item.status == "WARN":
            severity_count = warn_counts[item.severity]
            warn_counts[item.severity] = severity_count + 1
            score -= WARN_PENALTIES[item.severity] * _diminishing_factor(severity_count)
    return max(0, min(100, int(round(score))))


def grade_for_score(score: int) -> str:
    """Translate a numeric score into a letter grade."""

    thresholds = [
        (97, "A+"),
        (93, "A"),
        (90, "A-"),
        (87, "B+"),
        (83, "B"),
        (80, "B-"),
        (77, "C+"),
        (73, "C"),
        (70, "C-"),
        (67, "D+"),
        (63, "D"),
        (60, "D-"),
    ]
    for minimum, grade in thresholds:
        if score >= minimum:
            return grade
    return "F"


def has_severity_at_or_above(report: AuditReport, minimum: SeverityType) -> bool:
    """Return True when any non-pass result meets or exceeds the requested severity."""

    threshold = SEVERITY_ORDER[minimum]
    return any(
        result.status in {"FAIL", "WARN"} and SEVERITY_ORDER.get(result.severity, 999) <= threshold
        for result in report.results
    )


def exit_code_for_report(report: AuditReport, ci: bool = False, fail_on: SeverityType | None = None) -> int:
    """Return the process exit code for a completed report."""

    if ci and report.counts.get("FAIL", 0):
        return 1
    if fail_on and has_severity_at_or_above(report, fail_on):
        return 1
    return 0
