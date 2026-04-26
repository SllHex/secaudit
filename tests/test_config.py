from __future__ import annotations

from pathlib import Path

from secaudit.config import AppConfig, load_config, merge_scan_settings


def test_load_config_parses_flat_keys(tmp_path: Path) -> None:
    config_path = tmp_path / "secaudit.toml"
    config_path.write_text(
        """
target = "https://example.com"
profile = "deep"
only = ["tls", "headers"]
timeout = 15
output = ["terminal", "json"]
json = "latest.json"
banner = true
banner_variant = "shield"
""".strip(),
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config.target == "https://example.com"
    assert config.profile == "deep"
    assert config.only == ("tls", "headers")
    assert config.timeout == 15
    assert config.outputs == ("terminal", "json")
    assert config.json_report == "latest.json"
    assert config.no_banner is False
    assert config.banner_variant == "shield"


def test_load_config_parses_sections(tmp_path: Path) -> None:
    config_path = tmp_path / "secaudit.toml"
    config_path.write_text(
        """
[scan]
target = "https://example.com"
profile = "deep"
only = ["tls", "headers"]
timeout = 15

[output]
output = ["terminal", "json"]
json = "latest.json"
""".strip(),
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config.target == "https://example.com"
    assert config.profile == "deep"
    assert config.only == ("tls", "headers")
    assert config.timeout == 15
    assert config.outputs == ("terminal", "json")
    assert config.json_report == "latest.json"


def test_merge_scan_settings_cli_overrides_config() -> None:
    config = AppConfig(
        target="https://example.com",
        profile="quick",
        timeout=10,
        outputs=("terminal", "json"),
        json_report="from-config.json",
        banner_variant="enterprise",
    )

    settings = merge_scan_settings(
        target="https://override.example",
        profile="deep",
        only=(),
        skip=(),
        report_dir=None,
        outputs=None,
        fail_on=None,
        timeout=20,
        user_agent=None,
        json_report="cli.json",
        html_report=None,
        check_www=None,
        full=None,
        no_banner=None,
        no_color=None,
        quiet=None,
        verbose=None,
        banner_variant=None,
        ci=None,
        watch_minutes=None,
        config=config,
    )

    assert settings.target == "https://override.example"
    assert settings.profile == "deep"
    assert settings.timeout == 20
    assert settings.json_report == "cli.json"
    assert settings.banner_variant == "enterprise"


def test_merge_scan_settings_uses_output_preferences_for_reports() -> None:
    config = AppConfig(
        target="https://example.com",
        profile="standard",
        outputs=("terminal", "html"),
        report_dir="reports",
        html_report="site.html",
        json_report="site.json",
    )

    settings = merge_scan_settings(
        target=None,
        profile=None,
        only=(),
        skip=(),
        report_dir=None,
        outputs=None,
        fail_on=None,
        timeout=None,
        user_agent=None,
        json_report=None,
        html_report=None,
        check_www=None,
        full=None,
        no_banner=None,
        no_color=None,
        quiet=None,
        verbose=None,
        banner_variant=None,
        ci=None,
        watch_minutes=None,
        config=config,
    )

    assert settings.outputs == ("terminal", "html")
    assert settings.html_report == "reports/site.html"
    assert settings.json_report is None
