from __future__ import annotations

from pathlib import Path

from secaudit.models import AuditReport, CheckResult, ModuleRun
from secaudit.reporters.json import load_json_report, render_json_report


def sample_report() -> AuditReport:
    results = [
        CheckResult(name="tls-legacy", status="FAIL", severity="high", summary="Legacy TLS enabled.", module="tls"),
        CheckResult(name="headers-hsts", status="PASS", severity="info", summary="HSTS present.", module="headers"),
    ]
    module = ModuleRun(
        slug="tls",
        name="TLS/Cert",
        description="TLS checks",
        status="FAIL",
        duration_seconds=0.42,
        counts={"PASS": 0, "WARN": 0, "FAIL": 1, "INFO": 0},
        results=[results[0]],
    )
    return AuditReport(
        version="1.1.0",
        target="https://example.com",
        host="example.com",
        generated_at="2026-04-25T00:00:00+00:00",
        duration_seconds=1.2,
        score=88,
        grade="B+",
        counts={"PASS": 1, "WARN": 0, "FAIL": 1, "INFO": 0},
        options={"profile": "standard"},
        modules=[module],
        results=results,
    )


def test_check_result_roundtrip() -> None:
    result = CheckResult(name="test", status="WARN", severity="medium", summary="Example", details="detail", module="dns")
    assert CheckResult.from_dict(result.to_dict()) == result


def test_audit_report_json_roundtrip(tmp_path: Path) -> None:
    report = sample_report()
    path = tmp_path / "report.json"
    path.write_text(render_json_report(report), encoding="utf-8")

    restored = load_json_report(path)

    assert restored.target == report.target
    assert restored.results[0].name == report.results[0].name
    assert restored.modules[0].slug == report.modules[0].slug
