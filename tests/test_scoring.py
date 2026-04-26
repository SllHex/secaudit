from __future__ import annotations

from secaudit.models import AuditReport, CheckResult
from secaudit.scoring import exit_code_for_report, score_results


def test_scoring_is_stable_for_known_findings() -> None:
    results = [
        CheckResult(name="tls-legacy", status="FAIL", severity="high", summary="Legacy TLS enabled.", module="tls"),
        CheckResult(name="csp-style", status="WARN", severity="medium", summary="Inline styles allowed.", module="csp"),
        CheckResult(name="www-dns", status="WARN", severity="low", summary="www missing.", module="dns"),
    ]

    assert score_results(results) == 85


def test_exit_code_respects_ci_and_fail_on() -> None:
    report = AuditReport(
        version="1.1.0",
        target="https://example.com",
        host="example.com",
        generated_at="2026-04-25T00:00:00+00:00",
        duration_seconds=1.2,
        score=85,
        grade="B",
        counts={"PASS": 0, "WARN": 1, "FAIL": 1, "INFO": 0},
        options={},
        modules=[],
        results=[
            CheckResult(name="legacy", status="FAIL", severity="high", summary="Legacy TLS.", module="tls"),
            CheckResult(name="style", status="WARN", severity="medium", summary="Inline styles.", module="csp"),
        ],
    )

    assert exit_code_for_report(report, ci=False, fail_on=None) == 0
    assert exit_code_for_report(report, ci=True, fail_on=None) == 1
    assert exit_code_for_report(report, ci=False, fail_on="high") == 1
    assert exit_code_for_report(report, ci=False, fail_on="critical") == 0
