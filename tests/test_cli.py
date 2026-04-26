from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from secaudit.cli import app
from secaudit.models import AuditReport
from secaudit.reporters.json import render_json_report


def test_init_writes_config(tmp_path: Path) -> None:
    runner = CliRunner()
    config_path = tmp_path / "secaudit.toml"

    result = runner.invoke(app, ["init", "--path", str(config_path)])

    assert result.exit_code == 0
    assert config_path.exists()
    contents = config_path.read_text(encoding="utf-8")
    assert 'target = "https://example.com"' in contents
    assert 'banner_variant = "stealth"' in contents


def test_root_defaults_to_scan_using_config(tmp_path: Path, monkeypatch) -> None:
    runner = CliRunner()
    config_path = tmp_path / "secaudit.toml"
    config_path.write_text(
        """
target = "https://example.com"
profile = "quick"
quiet = true
""".strip(),
        encoding="utf-8",
    )

    captured: dict[str, str] = {}

    async def fake_run_once(settings):  # type: ignore[no-untyped-def]
        captured["target"] = settings.target
        captured["profile"] = settings.profile
        report = AuditReport(
            version="1.1.0",
            target=settings.target,
            host="example.com",
            generated_at="2026-04-25T00:00:00+00:00",
            duration_seconds=0.01,
            score=100,
            grade="A+",
            counts={"PASS": 0, "WARN": 0, "FAIL": 0, "INFO": 0},
            options={},
            modules=[],
            results=[],
        )
        return 0, report

    monkeypatch.setattr("secaudit.cli._run_scan_once", fake_run_once)

    result = runner.invoke(app, ["--config", str(config_path)])

    assert result.exit_code == 0
    assert captured == {"target": "https://example.com", "profile": "quick"}


def test_version_command_prints_version() -> None:
    runner = CliRunner()

    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert "SecAudit" in result.output


def test_modules_command_lists_profiles_and_categories() -> None:
    runner = CliRunner()

    result = runner.invoke(app, ["modules"])

    assert result.exit_code == 0
    assert "Scan Profiles" in result.output
    assert "Core Checks" in result.output


def test_explain_command_renders_module_metadata() -> None:
    runner = CliRunner()

    result = runner.invoke(app, ["explain", "csp"])

    assert result.exit_code == 0
    assert "Module: csp" in result.output
    assert "Profiles" in result.output


def test_interactive_command_runs_guided_scan(tmp_path: Path, monkeypatch) -> None:
    runner = CliRunner()
    captured: dict[str, object] = {}
    config_path = tmp_path / "secaudit.toml"
    config_path.write_text(
        """
output = ["terminal", "json"]
json = "wizard.json"
check_www = true
verbose = true
fail_on = "medium"
user_agent = "Agent/1.0"
""".strip(),
        encoding="utf-8",
    )

    async def fake_run_once(settings):  # type: ignore[no-untyped-def]
        captured["target"] = settings.target
        captured["profile"] = settings.profile
        captured["outputs"] = settings.outputs
        captured["json_report"] = settings.json_report
        captured["check_www"] = settings.check_www
        captured["verbose"] = settings.verbose
        captured["fail_on"] = settings.fail_on
        captured["user_agent"] = settings.user_agent
        report = AuditReport(
            version="1.1.0",
            target=settings.target,
            host="example.com",
            generated_at="2026-04-25T00:00:00+00:00",
            duration_seconds=0.01,
            score=92,
            grade="A-",
            counts={"PASS": 0, "WARN": 0, "FAIL": 0, "INFO": 0},
            options={},
            modules=[],
            results=[],
        )
        return 0, report

    monkeypatch.setattr("secaudit.cli._run_scan_once", fake_run_once)

    result = runner.invoke(
        app,
        ["interactive", "https://example.com", "--config", str(config_path), "--no-banner", "--no-color"],
        input="2\n0\n",
    )

    assert result.exit_code == 0
    assert captured == {
        "target": "https://example.com",
        "profile": "standard",
        "outputs": ("terminal", "json"),
        "json_report": "wizard.json",
        "check_www": True,
        "verbose": True,
        "fail_on": "medium",
        "user_agent": "Agent/1.0",
    }


def test_interactive_manual_module_scan_supports_exact_module_selection(tmp_path: Path, monkeypatch) -> None:
    runner = CliRunner()
    captured: dict[str, object] = {}
    config_path = tmp_path / "missing.toml"

    async def fake_run_once(settings):  # type: ignore[no-untyped-def]
        captured["profile"] = settings.profile
        captured["only"] = settings.only
        captured["full"] = settings.full
        report = AuditReport(
            version="1.1.0",
            target=settings.target,
            host="example.com",
            generated_at="2026-04-25T00:00:00+00:00",
            duration_seconds=0.01,
            score=95,
            grade="A",
            counts={"PASS": 0, "WARN": 0, "FAIL": 0, "INFO": 0},
            options={},
            modules=[],
            results=[],
        )
        return 0, report

    monkeypatch.setattr("secaudit.cli._run_scan_once", fake_run_once)

    result = runner.invoke(
        app,
        ["interactive", "https://example.com", "--config", str(config_path), "--no-banner", "--no-color"],
        input="4\n1,6,8\n0\n",
    )

    assert result.exit_code == 0
    assert captured == {
        "profile": "deep",
        "only": ("dns", "api", "javascript"),
        "full": True,
    }


def test_interactive_menu_can_compare_reports(tmp_path: Path) -> None:
    runner = CliRunner()
    old_report = AuditReport(
        version="1.1.0",
        target="https://example.com",
        host="example.com",
        generated_at="2026-04-25T00:00:00+00:00",
        duration_seconds=0.10,
        score=90,
        grade="A-",
        counts={"PASS": 1, "WARN": 0, "FAIL": 0, "INFO": 0},
        options={},
        modules=[],
        results=[],
    )
    new_report = AuditReport(
        version="1.1.0",
        target="https://example.com",
        host="example.com",
        generated_at="2026-04-25T00:05:00+00:00",
        duration_seconds=0.10,
        score=80,
        grade="B-",
        counts={"PASS": 0, "WARN": 1, "FAIL": 0, "INFO": 0},
        options={},
        modules=[],
        results=[],
    )
    old_path = tmp_path / "old.json"
    new_path = tmp_path / "new.json"
    old_path.write_text(render_json_report(old_report), encoding="utf-8")
    new_path.write_text(render_json_report(new_report), encoding="utf-8")

    result = runner.invoke(
        app,
        ["interactive", "--no-banner", "--no-color"],
        input=f"7\n{old_path}\n{new_path}\nn\nn\n0\n",
    )

    assert result.exit_code == 0
    assert "Interactive Compare" in result.output


def test_interactive_quick_preset_runs_with_minimal_prompts(tmp_path: Path, monkeypatch) -> None:
    runner = CliRunner()
    captured: dict[str, object] = {}
    config_path = tmp_path / "secaudit.toml"
    config_path.write_text(
        """
target = "https://config.example"
profile = "standard"
output = ["terminal"]
""".strip(),
        encoding="utf-8",
    )

    async def fake_run_once(settings):  # type: ignore[no-untyped-def]
        captured["target"] = settings.target
        captured["profile"] = settings.profile
        captured["outputs"] = settings.outputs
        captured["no_banner"] = settings.no_banner
        report = AuditReport(
            version="1.1.0",
            target=settings.target,
            host="example.com",
            generated_at="2026-04-25T00:00:00+00:00",
            duration_seconds=0.01,
            score=98,
            grade="A+",
            counts={"PASS": 0, "WARN": 0, "FAIL": 0, "INFO": 0},
            options={},
            modules=[],
            results=[],
        )
        return 0, report

    monkeypatch.setattr("secaudit.cli._run_scan_once", fake_run_once)

    result = runner.invoke(
        app,
        ["interactive", "https://example.com", "--config", str(config_path), "--no-banner", "--no-color"],
        input="1\n0\n",
    )

    assert result.exit_code == 0
    assert captured == {
        "target": "https://example.com",
        "profile": "quick",
        "outputs": ("terminal",),
        "no_banner": True,
    }
