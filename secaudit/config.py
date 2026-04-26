"""Configuration loading and CLI precedence resolution for SecAudit."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import ConfigError
from .http import USER_AGENT
from .models import SeverityType
from .registry import parse_module_csv

try:  # pragma: no cover - import path depends on runtime
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]


DEFAULT_CONFIG_PATH = Path("secaudit.toml")

_VALID_BANNER_VARIANTS: frozenset[str] = frozenset({"matrix", "stealth", "ghost", "minimal"})
_DEFAULT_BANNER_VARIANT = "matrix"


@dataclass(slots=True)
class AppConfig:
    """Values loaded from secaudit.toml."""

    target: str | None = None
    profile: str | None = None
    only: tuple[str, ...] = ()
    skip: tuple[str, ...] = ()
    outputs: tuple[str, ...] = ()
    report_dir: str | None = None
    fail_on: SeverityType | None = None
    timeout: int | None = None
    user_agent: str | None = None
    json_report: str | None = None
    html_report: str | None = None
    check_www: bool | None = None
    full: bool | None = None
    no_banner: bool | None = None
    no_color: bool | None = None
    quiet: bool | None = None
    verbose: bool | None = None
    banner_variant: str | None = None


@dataclass(slots=True)
class ScanSettings:
    """Final resolved scan settings after merging CLI and config."""

    target: str
    profile: str
    only: tuple[str, ...]
    skip: tuple[str, ...]
    outputs: tuple[str, ...]
    report_dir: str | None
    fail_on: SeverityType | None
    timeout: int
    user_agent: str
    json_report: str | None
    html_report: str | None
    check_www: bool
    full: bool
    no_banner: bool
    no_color: bool
    quiet: bool
    verbose: bool
    banner_variant: str
    ci: bool
    watch_minutes: float | None


def _coerce_bool(value: Any, field_name: str) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    raise ConfigError(f"Expected a boolean for '{field_name}' in secaudit.toml.")


def _coerce_int(value: Any, field_name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, int) and value > 0:
        return value
    raise ConfigError(f"Expected a positive integer for '{field_name}' in secaudit.toml.")


def _coerce_string(value: Any, field_name: str) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value.strip() or None
    raise ConfigError(f"Expected a string for '{field_name}' in secaudit.toml.")


def _coerce_severity(value: Any, field_name: str) -> SeverityType | None:
    text = _coerce_string(value, field_name)
    if text is None:
        return None
    if text not in {"critical", "high", "medium", "low", "info"}:
        raise ConfigError(f"Unknown severity '{text}' for '{field_name}' in secaudit.toml.")
    return text  # type: ignore[return-value]


def _coerce_banner_variant(value: Any, field_name: str) -> str | None:
    text = _coerce_string(value, field_name)
    if text is None:
        return None
    if text not in _VALID_BANNER_VARIANTS:
        valid = ", ".join(sorted(_VALID_BANNER_VARIANTS))
        raise ConfigError(f"Unknown banner_variant '{text}' in secaudit.toml. Valid choices: {valid}.")
    return text


def _coerce_module_list(value: Any, field_name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return parse_module_csv(value)
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return tuple(parse_module_csv(",".join(value)))
    raise ConfigError(f"Expected a string or list of strings for '{field_name}' in secaudit.toml.")


def _coerce_output_list(value: Any, field_name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        value = [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        normalized: list[str] = []
        for item in value:
            lowered = item.strip().lower()
            if lowered not in {"terminal", "json", "html"}:
                raise ConfigError(f"Unknown output '{item}' for '{field_name}' in secaudit.toml.")
            if lowered not in normalized:
                normalized.append(lowered)
        return tuple(normalized)
    raise ConfigError(f"Expected a string or list of strings for '{field_name}' in secaudit.toml.")


def load_config(path: str | Path | None = None) -> AppConfig:
    """Load secaudit.toml if it exists; otherwise return defaults."""

    config_path = Path(path or DEFAULT_CONFIG_PATH)
    if not config_path.exists():
        return AppConfig()
    try:
        payload = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise ConfigError(f"Could not read {config_path}: {exc}") from exc

    if not isinstance(payload, dict):
        raise ConfigError("secaudit.toml must decode to a table/object.")
    scan = payload.get("scan")
    output = payload.get("output")
    if scan is not None and not isinstance(scan, dict):
        raise ConfigError("[scan] in secaudit.toml must be a table/object.")
    if output is not None and not isinstance(output, dict):
        if "scan" in payload:
            raise ConfigError("[output] in secaudit.toml must be a table/object.")
        output = None
    scan_section = scan if isinstance(scan, dict) else payload
    output_section = output if isinstance(output, dict) else payload

    banner_enabled = _coerce_bool(scan_section.get("banner"), "banner")
    no_banner = _coerce_bool(scan_section.get("no_banner"), "no_banner")
    if banner_enabled is not None and no_banner is not None and banner_enabled == no_banner:
        raise ConfigError("Use either 'banner' or 'no_banner' consistently in secaudit.toml, not contradictory values.")

    color_enabled = _coerce_bool(scan_section.get("color"), "color")
    no_color = _coerce_bool(scan_section.get("no_color"), "no_color")
    if color_enabled is not None and no_color is not None and color_enabled == no_color:
        raise ConfigError("Use either 'color' or 'no_color' consistently in secaudit.toml, not contradictory values.")

    return AppConfig(
        target=_coerce_string(scan_section.get("target"), "target"),
        profile=_coerce_string(scan_section.get("profile"), "profile"),
        only=_coerce_module_list(scan_section.get("only"), "only"),
        skip=_coerce_module_list(scan_section.get("skip"), "skip"),
        outputs=_coerce_output_list(output_section.get("output"), "output"),
        report_dir=_coerce_string(scan_section.get("report_dir"), "report_dir"),
        fail_on=_coerce_severity(scan_section.get("fail_on"), "fail_on"),
        timeout=_coerce_int(scan_section.get("timeout"), "timeout"),
        user_agent=_coerce_string(scan_section.get("user_agent"), "user_agent"),
        check_www=_coerce_bool(scan_section.get("check_www"), "check_www"),
        full=_coerce_bool(scan_section.get("full"), "full"),
        no_banner=no_banner if no_banner is not None else (None if banner_enabled is None else not banner_enabled),
        no_color=no_color if no_color is not None else (None if color_enabled is None else not color_enabled),
        quiet=_coerce_bool(scan_section.get("quiet"), "quiet"),
        verbose=_coerce_bool(scan_section.get("verbose"), "verbose"),
        banner_variant=_coerce_banner_variant(scan_section.get("banner_variant"), "banner_variant"),
        json_report=_coerce_string(output_section.get("json"), "json"),
        html_report=_coerce_string(output_section.get("html"), "html"),
    )


def render_default_config() -> str:
    """Return the default secaudit.toml template."""

    return f"""# SecAudit configuration
target = "https://example.com"
profile = "standard"
only = []
skip = []
output = ["terminal", "json", "html"]
report_dir = "reports"
fail_on = "high"
timeout = 10
user_agent = "{USER_AGENT}"
check_www = false
full = false
banner = true
banner_variant = "matrix"
color = true
quiet = false
verbose = false
json = "secaudit-report.json"
html = "secaudit-report.html"
"""


def resolve_report_path(report_dir: str | None, path_value: str | None) -> str | None:
    """Resolve an output path against the configured report directory."""

    if not path_value:
        return None
    path = Path(path_value)
    if path.is_absolute() or not report_dir:
        return str(path)
    return str(Path(report_dir) / path)


def merge_scan_settings(
    *,
    target: str | None,
    profile: str | None,
    only: tuple[str, ...],
    skip: tuple[str, ...],
    report_dir: str | None,
    outputs: tuple[str, ...] | None,
    fail_on: SeverityType | None,
    timeout: int | None,
    user_agent: str | None,
    json_report: str | None,
    html_report: str | None,
    check_www: bool | None,
    full: bool | None,
    no_banner: bool | None,
    no_color: bool | None,
    quiet: bool | None,
    verbose: bool | None,
    banner_variant: str | None,
    ci: bool | None,
    watch_minutes: float | None,
    config: AppConfig,
) -> ScanSettings:
    """Merge CLI values over config values, then apply defaults."""

    def pick(cli_value: Any, config_value: Any, default: Any) -> Any:
        if cli_value is not None and cli_value != ():
            return cli_value
        if config_value is not None and config_value != ():
            return config_value
        return default

    resolved_target = pick(target, config.target, None)
    if not resolved_target:
        raise ConfigError("No target URL was provided. Pass a URL or set 'target' in secaudit.toml.")

    resolved_profile = pick(profile, config.profile, "standard")
    resolved_only = pick(only, config.only, ())
    resolved_skip = pick(skip, config.skip, ())
    explicit_json = json_report is not None
    explicit_html = html_report is not None
    resolved_outputs = pick(outputs, config.outputs, ("terminal",))
    resolved_report_dir = pick(report_dir, config.report_dir, None)
    resolved_fail_on = pick(fail_on, config.fail_on, None)
    resolved_timeout = int(pick(timeout, config.timeout, 10))
    resolved_user_agent = str(pick(user_agent, config.user_agent, USER_AGENT))
    resolved_check_www = bool(pick(check_www, config.check_www, False))
    resolved_full = bool(pick(full, config.full, False))
    if resolved_full and profile is None:
        resolved_profile = "deep"
    resolved_no_banner = bool(pick(no_banner, config.no_banner, False))
    resolved_no_color = bool(pick(no_color, config.no_color, False))
    resolved_quiet = bool(pick(quiet, config.quiet, False))
    resolved_verbose = bool(pick(verbose, config.verbose, False))
    resolved_banner_variant = str(pick(banner_variant, config.banner_variant, _DEFAULT_BANNER_VARIANT))
    resolved_ci = bool(ci or False)
    resolved_json = resolve_report_path(
        resolved_report_dir,
        json_report if explicit_json else (config.json_report if "json" in resolved_outputs else None),
    )
    resolved_html = resolve_report_path(
        resolved_report_dir,
        html_report if explicit_html else (config.html_report if "html" in resolved_outputs else None),
    )
    if "json" in resolved_outputs and not resolved_json:
        resolved_json = resolve_report_path(resolved_report_dir, "secaudit-report.json")
    if "html" in resolved_outputs and not resolved_html:
        resolved_html = resolve_report_path(resolved_report_dir, "secaudit-report.html")

    return ScanSettings(
        target=resolved_target,
        profile=resolved_profile,
        only=resolved_only,
        skip=resolved_skip,
        outputs=resolved_outputs,
        report_dir=resolved_report_dir,
        fail_on=resolved_fail_on,
        timeout=resolved_timeout,
        user_agent=resolved_user_agent,
        json_report=resolved_json,
        html_report=resolved_html,
        check_www=resolved_check_www,
        full=resolved_full,
        no_banner=resolved_no_banner,
        no_color=resolved_no_color,
        quiet=resolved_quiet,
        verbose=resolved_verbose,
        banner_variant=resolved_banner_variant,
        ci=resolved_ci,
        watch_minutes=watch_minutes,
    )
