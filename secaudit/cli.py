"""Click-based command-line interface for SecAudit."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Callable

import click
from rich.box import HEAVY as _HEAVY_BOX
from rich.console import Group
from rich.panel import Panel
from rich.rule import Rule as _Rule
from rich.text import Text

from . import __version__
from .config import DEFAULT_CONFIG_PATH, ScanSettings, load_config, merge_scan_settings, render_default_config
from .context import AuditContext
from .diff import compare_reports
from .engine import execute_modules
from .errors import ConfigError, InvalidTargetError, ReportError, SecAuditError, UnknownModuleError
from .http import USER_AGENT
from .profiles import PROFILE_REGISTRY, PROFILES, get_profile
from .registry import MODULE_SPECS, get_module_spec, grouped_module_specs, normalize_module_name, parse_module_csv, resolve_module_plan
from .reporters import TerminalReporter, load_json_report, render_html_report, render_json_diff, render_json_report
from .scoring import exit_code_for_report
from .ui import (
    BANNER_VARIANTS,
    DEFAULT_BANNER_VARIANT,
    build_console,
    build_explain_table,
    build_main_menu_table,
    build_module_picker_table,
    build_modules_table,
    build_profile_choice_table,
    render_interactive_splash,
    render_settings_preview,
)


class DefaultScanGroup(click.Group):
    """Treat unknown first arguments and scan-like options as `scan`."""

    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        passthrough = {"-h", "--help", "--version"}
        if not args:
            args.insert(0, "scan")
        else:
            first = args[0]
            if first not in self.commands and first not in passthrough:
                args.insert(0, "scan")
        return super().parse_args(ctx, args)


def _write_output(path: str | Path, content: str) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")


def _parse_optional_modules(raw: str | None) -> tuple[str, ...]:
    return parse_module_csv(raw) if raw else ()


def _parse_module_selection(raw: str | None) -> tuple[str, ...]:
    if not raw or not raw.strip():
        return ()
    resolved: list[str] = []
    for token in raw.split(","):
        item = token.strip()
        if not item:
            continue
        if item.isdigit():
            index = int(item)
            if index < 1 or index > len(MODULE_SPECS):
                raise click.ClickException(f"Module selection '{item}' is out of range. Choose 1-{len(MODULE_SPECS)}.")
            slug = MODULE_SPECS[index - 1].slug
        else:
            slug = normalize_module_name(item)
        if slug not in resolved:
            resolved.append(slug)
    return tuple(resolved)


def _prompt_profile(default_profile: str) -> str:
    raw = click.prompt("Choose a profile (number or slug)", default=default_profile, show_default=True)
    if raw.isdigit():
        index = int(raw)
        if index < 1 or index > len(PROFILES):
            raise click.ClickException(f"Profile '{raw}' is out of range. Choose 1-{len(PROFILES)}.")
        return PROFILES[index - 1].slug
    return get_profile(raw).slug


def _render_interactive_config(settings: ScanSettings, outputs: list[str]) -> str:
    lines = [
        "# SecAudit configuration",
        f'target = "{settings.target}"',
        f'profile = "{settings.profile}"',
        f"only = {list(settings.only)!r}".replace("'", '"'),
        f"skip = {list(settings.skip)!r}".replace("'", '"'),
        f'output = {outputs!r}'.replace("'", '"'),
        f'report_dir = "{settings.report_dir or "reports"}"',
        f'fail_on = "{settings.fail_on}"' if settings.fail_on else "# fail_on = \"high\"",
        f"timeout = {settings.timeout}",
        f'user_agent = "{settings.user_agent}"',
        f"check_www = {'true' if settings.check_www else 'false'}",
        f"full = {'true' if settings.full else 'false'}",
        f"banner = {'false' if settings.no_banner else 'true'}",
        f'banner_variant = "{settings.banner_variant}"',
        f"color = {'false' if settings.no_color else 'true'}",
        f"quiet = {'true' if settings.quiet else 'false'}",
        f"verbose = {'true' if settings.verbose else 'false'}",
    ]
    if settings.json_report:
        lines.append(f'json = "{settings.json_report}"')
    if settings.html_report:
        lines.append(f'html = "{settings.html_report}"')
    return "\n".join(lines) + "\n"


def _show_modules_overview(console: Any) -> None:
    profile_lines = [
        Text.assemble(
            (f"  {profile.slug:<12}", "bold cyan"),
            (f"  {profile.title}  ", "white"),
            (profile.description, "bright_black"),
        )
        for profile in PROFILES
    ]
    console.print(_Rule(style="bright_green"))
    console.print(
        Panel(
            Group(*profile_lines),
            box=_HEAVY_BOX,
            title="[ SCAN PROFILES ]",
            title_align="left",
            border_style="bright_green",
            padding=(0, 0),
        )
    )
    for category, specs in grouped_module_specs().items():
        console.print(build_modules_table(category, specs))
    console.print(_Rule(style="bright_green"))


def _show_module_explanation(console: Any, module_name: str) -> None:
    spec = get_module_spec(module_name)
    summary = Group(
        Text.assemble(("  ", ""), (spec.title, "bold bright_white")),
        Text.assemble(("  ", ""), (spec.purpose or spec.description, "cyan")),
        Text.assemble(("  category  //  ", "bright_black"), (spec.category, "white")),
    )
    console.print(Panel(
        summary,
        box=_HEAVY_BOX,
        title=f"[ {spec.slug.upper()} ]",
        title_align="left",
        border_style="bright_green",
        padding=(0, 0),
    ))
    console.print(build_explain_table(spec))


def _infer_profile_from_modules(modules: tuple[str, ...]) -> str:
    quick = set(get_profile("quick").modules)
    standard = set(get_profile("standard").modules)
    selected = set(modules)
    if selected and selected.issubset(quick):
        return "quick"
    if selected and selected.issubset(standard):
        return "standard"
    return "deep"


def _interactive_collect_scan_settings(
    *,
    console: Any,
    supplied_target: str | None,
    config: Any,
    no_banner: bool,
    no_color: bool,
    manual_modules: bool = False,
    forced_profile: str | None = None,
) -> ScanSettings:
    if supplied_target:
        chosen_target = supplied_target
        console.print(Panel(
            Group(
                Text.assemble(("  [+] target  //  ", "bright_black"), (supplied_target, "bold bright_green")),
                Text("  [*] supplied directly — skipping prompt", style="dim"),
            ),
            box=_HEAVY_BOX, title="[ TARGET ]", title_align="left",
            border_style="bright_green", padding=(0, 0),
        ))
    elif config.target:
        chosen_target = config.target
        console.print(Panel(
            Group(
                Text.assemble(("  [+] target  //  ", "bright_black"), (config.target, "bold bright_green")),
                Text("  [*] loaded from config — use `secaudit scan <url>` to override", style="dim"),
            ),
            box=_HEAVY_BOX, title="[ TARGET ]", title_align="left",
            border_style="bright_green", padding=(0, 0),
        ))
    else:
        chosen_target = click.prompt("  target URL", default="https://example.com", show_default=True).strip()
    chosen_profile: str
    chosen_only: tuple[str, ...]
    chosen_skip: tuple[str, ...]

    if manual_modules:
        chosen_profile = "deep"
        console.print(build_module_picker_table(MODULE_SPECS))
        only_raw = click.prompt("Choose modules to run (numbers/slugs, comma-separated)", default="", show_default=False)
        chosen_only = _parse_module_selection(only_raw)
        if not chosen_only:
            raise click.ClickException("Manual module scan needs at least one selected module.")
        chosen_skip = ()
        inferred_profile = _infer_profile_from_modules(chosen_only)
        chosen_profile = inferred_profile
    else:
        if forced_profile:
            chosen_profile = forced_profile
            console.print(Panel(
                Group(
                    Text.assemble(("  [+] profile  //  ", "bright_black"), (forced_profile, "bold cyan")),
                    Text.assemble(("  [*] ", "bright_black"), (get_profile(forced_profile).description, "dim")),
                ),
                box=_HEAVY_BOX, title="[ PROFILE ]", title_align="left",
                border_style="bright_green", padding=(0, 0),
            ))
        else:
            console.print(build_profile_choice_table(PROFILES))
            default_profile = config.profile or "standard"
            chosen_profile = _prompt_profile(default_profile)
        chosen_only = ()
        chosen_skip = ()

    enable_full = chosen_profile == "deep"
    if manual_modules and chosen_profile != "deep":
        enable_full = False
    banner_variant = config.banner_variant or DEFAULT_BANNER_VARIANT

    return merge_scan_settings(
        target=chosen_target,
        profile=chosen_profile,
        only=chosen_only,
        skip=chosen_skip,
        report_dir=config.report_dir,
        outputs=tuple(config.outputs) if config.outputs else ("terminal",),
        fail_on=config.fail_on,
        timeout=config.timeout or 10,
        user_agent=config.user_agent or USER_AGENT,
        json_report=None,
        html_report=None,
        check_www=config.check_www if config.check_www is not None else False,
        full=enable_full,
        no_banner=(True if no_banner else bool(config.no_banner)),
        no_color=no_color,
        quiet=False,
        verbose=bool(config.verbose),
        banner_variant=banner_variant,
        ci=False,
        watch_minutes=None,
        config=config,
    )


def _interactive_compare(console: Any, *, no_color: bool) -> None:
    old_path = Path(click.prompt("Old JSON report path", type=str).strip())
    new_path = Path(click.prompt("New JSON report path", type=str).strip())
    try:
        old_report = load_json_report(old_path)
        new_report = load_json_report(new_path)
    except ReportError as exc:
        raise click.ClickException(str(exc)) from exc

    diff = compare_reports(old_report, new_report)
    json_path: str | None = None
    html_path: str | None = None
    if click.confirm("Save the diff as JSON?", default=False):
        json_path = click.prompt("Diff JSON path", default="secaudit-diff.json", show_default=True).strip()
        _write_output(json_path, render_json_diff(diff))
    if click.confirm("Save an HTML report for the newer scan?", default=False):
        html_path = click.prompt("HTML report path", default="secaudit-compare.html", show_default=True).strip()
        _write_output(html_path, render_html_report(new_report, diff=diff))
    reporter = TerminalReporter(show_banner=False, color=not no_color, quiet=False, verbose=False, ci=False)
    reporter.display_diff(diff, title="Interactive Compare")
    if json_path or html_path:
        console.print(f"Saved reports: json={json_path or '-'} html={html_path or '-'}")


def _interactive_write_config(console: Any, *, config_path: Path | None) -> None:
    destination = Path(click.prompt("Config path", default=str(config_path or DEFAULT_CONFIG_PATH), show_default=True).strip())
    if destination.exists() and not click.confirm(f"{destination} already exists. Overwrite it?", default=False):
        console.print("Config write skipped.")
        return
    _write_output(destination, render_default_config())
    console.print(f"Wrote {destination}")


def _interactive_launch_scan(console: Any, settings: ScanSettings, *, label: str) -> None:
    console.print(render_settings_preview(settings, selected_reports=list(settings.outputs)))
    console.print(Panel(
        Group(
            Text.assemble(("  [+] ", "bright_green"), (f"{label} armed — launching now.", "bold white")),
            Text.assemble(("  [*] ", "bright_black"), ("Use Forge Config to save this run for later.", "bright_black")),
        ),
        box=_HEAVY_BOX,
        title="[ LAUNCH ]",
        title_align="left",
        border_style="bright_green",
        padding=(0, 0),
    ))
    exit_code, _ = asyncio.run(_run_scan_once(settings))
    console.print(f"{label} finished with exit code {exit_code}.")


def _report_paths(settings: ScanSettings) -> dict[str, str]:
    paths: dict[str, str] = {}
    if settings.json_report:
        paths["json"] = settings.json_report
    if settings.html_report:
        paths["html"] = settings.html_report
    return paths


async def _run_scan_once(settings: ScanSettings) -> tuple[int, Any]:
    modules = list(resolve_module_plan(profile=settings.profile, only=settings.only, skip=settings.skip))
    terminal_enabled = "terminal" in settings.outputs or settings.quiet or settings.verbose or settings.ci
    context = AuditContext(
        raw_url=settings.target,
        timeout=settings.timeout,
        check_www=settings.check_www,
        test_rate_limit=settings.profile == "deep" or settings.full,
        full=settings.full or settings.profile == "deep",
        profile=settings.profile,
        user_agent=settings.user_agent,
        selected_modules=tuple(module.slug for module in modules),
    )
    reporter = TerminalReporter(
        show_banner=terminal_enabled and not settings.no_banner,
        color=not settings.no_color,
        quiet=(settings.quiet or not terminal_enabled),
        verbose=settings.verbose,
        ci=settings.ci,
        banner_variant=settings.banner_variant,
    )
    report = await execute_modules(modules, context, reporter=reporter)

    if settings.json_report:
        _write_output(settings.json_report, render_json_report(report))
    if settings.html_report:
        _write_output(settings.html_report, render_html_report(report))

    if terminal_enabled and not settings.quiet:
        reporter.display_report(report, profile=settings.profile, report_paths=_report_paths(settings))
    elif terminal_enabled:
        click.echo(f"{report.target} score={report.score} grade={report.grade} fail={report.counts.get('FAIL', 0)} warn={report.counts.get('WARN', 0)}")

    exit_code = exit_code_for_report(report, ci=settings.ci, fail_on=settings.fail_on)
    return exit_code, report


def _common_scan_options(function: Callable[..., Any]) -> Callable[..., Any]:
    options = [
        click.option("--profile", type=click.Choice(sorted(PROFILE_REGISTRY)), default=None, help="Scan profile to use."),
        click.option("--only", "only_raw", default=None, help="Comma-separated module allowlist."),
        click.option("--skip", "skip_raw", default=None, help="Comma-separated modules to exclude."),
        click.option("--timeout", type=int, default=None, help="Per-request timeout in seconds."),
        click.option("--user-agent", default=None, help="Override the SecAudit user-agent string."),
        click.option("--check-www", is_flag=True, default=None, help="Also validate the www host."),
        click.option("--full", is_flag=True, default=None, help="Compatibility flag that promotes the run to the deep profile."),
        click.option("--watch", type=float, default=None, metavar="MINUTES", help="Re-run the audit every N minutes and show diffs."),
        click.option("--no-banner", is_flag=True, default=None, help="Suppress the startup banner."),
        click.option("--no-color", is_flag=True, default=None, help="Disable Rich colors."),
        click.option("--quiet", is_flag=True, default=None, help="Reduce terminal output to a single summary line."),
        click.option("--verbose", is_flag=True, default=None, help="Print per-module finding details."),
        click.option("--ci", is_flag=True, default=None, help="Exit non-zero when FAIL findings are present."),
        click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low", "info"]), default=None, help="Exit non-zero when any finding at or above this severity exists."),
        click.option("--json", "json_path", type=click.Path(dir_okay=False), default=None, help="Write a JSON report to this path."),
        click.option("--html", "html_path", type=click.Path(dir_okay=False), default=None, help="Write a standalone HTML report to this path."),
        click.option("--banner-variant", type=click.Choice(list(BANNER_VARIANTS)), default=None, help="Select the terminal banner style."),
        click.option("--config", "config_path", type=click.Path(dir_okay=False, path_type=Path), default=None, help=f"Path to a config file. Defaults to {DEFAULT_CONFIG_PATH}."),
    ]
    for option in reversed(options):
        function = option(function)
    return function


def _resolve_settings(
    *,
    target: str | None,
    profile: str | None,
    only_raw: str | None,
    skip_raw: str | None,
    timeout: int | None,
    user_agent: str | None,
    check_www: bool | None,
    full: bool | None,
    watch: float | None,
    no_banner: bool | None,
    no_color: bool | None,
    quiet: bool | None,
    verbose: bool | None,
    ci: bool | None,
    fail_on: str | None,
    json_path: str | None,
    html_path: str | None,
    banner_variant: str | None,
    config_path: Path | None,
) -> ScanSettings:
    config = load_config(config_path)
    return merge_scan_settings(
        target=target,
        profile=profile,
        only=_parse_optional_modules(only_raw),
        skip=_parse_optional_modules(skip_raw),
        report_dir=None,
        outputs=None,
        fail_on=fail_on,  # type: ignore[arg-type]
        timeout=timeout,
        user_agent=user_agent,
        json_report=json_path,
        html_report=html_path,
        check_www=check_www,
        full=full,
        no_banner=no_banner,
        no_color=no_color,
        quiet=quiet,
        verbose=verbose,
        banner_variant=banner_variant,
        ci=ci,
        watch_minutes=watch,
        config=config,
    )


@click.group(cls=DefaultScanGroup, invoke_without_command=False, context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="SecAudit")
def app() -> None:
    """SecAudit: safe external security auditing for public-facing web applications."""


@app.command("scan")
@click.argument("target", required=False)
@_common_scan_options
def scan(
    target: str | None,
    profile: str | None,
    only_raw: str | None,
    skip_raw: str | None,
    timeout: int | None,
    user_agent: str | None,
    check_www: bool | None,
    full: bool | None,
    watch: float | None,
    no_banner: bool | None,
    no_color: bool | None,
    quiet: bool | None,
    verbose: bool | None,
    ci: bool | None,
    fail_on: str | None,
    json_path: str | None,
    html_path: str | None,
    banner_variant: str | None,
    config_path: Path | None,
) -> None:
    """Run a security audit against a target URL."""

    if watch is not None and watch <= 0:
        raise click.UsageError("--watch expects a positive minute value.")

    try:
        settings = _resolve_settings(
            target=target,
            profile=profile,
            only_raw=only_raw,
            skip_raw=skip_raw,
            timeout=timeout,
            user_agent=user_agent,
            check_www=check_www,
            full=full,
            watch=watch,
            no_banner=no_banner,
            no_color=no_color,
            quiet=quiet,
            verbose=verbose,
            ci=ci,
            fail_on=fail_on,
            json_path=json_path,
            html_path=html_path,
            banner_variant=banner_variant,
            config_path=config_path,
        )
    except (ConfigError, UnknownModuleError) as exc:
        raise click.ClickException(str(exc)) from exc

    async def runner() -> int:
        previous_report = None
        exit_code = 0
        while True:
            current_exit, report = await _run_scan_once(settings)
            exit_code = max(exit_code, current_exit)
            if previous_report is not None and not settings.quiet and "terminal" in settings.outputs:
                diff = compare_reports(previous_report, report)
                TerminalReporter(
                    show_banner=False,
                    color=not settings.no_color,
                    quiet=settings.quiet,
                    verbose=settings.verbose,
                    ci=settings.ci,
                    banner_variant=settings.banner_variant,
                ).display_diff(diff, title="Watch Diff")
            previous_report = report
            if settings.watch_minutes is None:
                return exit_code
            await asyncio.sleep(settings.watch_minutes * 60)

    try:
        raise SystemExit(asyncio.run(runner()))
    except (InvalidTargetError, SecAuditError) as exc:
        raise click.ClickException(str(exc)) from exc


@app.command("modules")
def modules_command() -> None:
    """List available modules grouped by category."""

    console = build_console(record=False)
    _show_modules_overview(console)


@app.command("explain")
@click.argument("module_name")
def explain(module_name: str) -> None:
    """Explain what a module checks and why it matters."""

    try:
        spec = get_module_spec(module_name)
    except UnknownModuleError as exc:
        raise click.ClickException(str(exc)) from exc

    console = build_console(record=False)
    _show_module_explanation(console, spec.slug)


@app.command("interactive")
@click.argument("target", required=False)
@click.option("--config", "config_path", type=click.Path(dir_okay=False, path_type=Path), default=None, help=f"Path to a config file. Defaults to {DEFAULT_CONFIG_PATH}.")
@click.option("--no-banner", is_flag=True, help="Hide the interactive splash and scan banner.")
@click.option("--no-color", is_flag=True, help="Disable Rich colors.")
def interactive_command(target: str | None, config_path: Path | None, no_banner: bool, no_color: bool) -> None:
    """Launch the interactive SecAudit control deck."""

    try:
        config = load_config(config_path)
    except ConfigError as exc:
        raise click.ClickException(str(exc)) from exc

    console = build_console(no_color=no_color, record=False)
    if not no_banner:
        console.print(render_interactive_splash())

    while True:
        console.print(build_main_menu_table())
        choice = click.prompt("Choose an action", default="1", show_default=True).strip().lower()

        try:
            if choice in {"1", "blitz", "quick"}:
                settings = _interactive_collect_scan_settings(
                    console=console,
                    supplied_target=target,
                    config=config,
                    no_banner=no_banner,
                    no_color=no_color,
                    manual_modules=False,
                    forced_profile="quick",
                )
                _interactive_launch_scan(console, settings, label="Blitz scan")

            elif choice in {"2", "ghost", "standard"}:
                settings = _interactive_collect_scan_settings(
                    console=console,
                    supplied_target=target,
                    config=config,
                    no_banner=no_banner,
                    no_color=no_color,
                    manual_modules=False,
                    forced_profile="standard",
                )
                _interactive_launch_scan(console, settings, label="Ghost scan")

            elif choice in {"3", "blacksite", "deep"}:
                settings = _interactive_collect_scan_settings(
                    console=console,
                    supplied_target=target,
                    config=config,
                    no_banner=no_banner,
                    no_color=no_color,
                    manual_modules=False,
                    forced_profile="deep",
                )
                _interactive_launch_scan(console, settings, label="Blacksite scan")

            elif choice in {"4", "manual", "operator", "loadout", "precision"}:
                settings = _interactive_collect_scan_settings(
                    console=console,
                    supplied_target=target,
                    config=config,
                    no_banner=no_banner,
                    no_color=no_color,
                    manual_modules=True,
                )
                _interactive_launch_scan(console, settings, label="Precision scan")

            elif choice in {"5", "modules", "atlas"}:
                _show_modules_overview(console)

            elif choice in {"6", "explain", "decrypt"}:
                module_name = click.prompt("Module slug or alias").strip()
                _show_module_explanation(console, module_name)

            elif choice in {"7", "compare", "diff"}:
                _interactive_compare(console, no_color=no_color)

            elif choice in {"8", "init", "config", "forge"}:
                _interactive_write_config(console, config_path=config_path)

            elif choice in {"9", "version"}:
                console.print(Panel(
                    Text.assemble(("  SEC//AUDIT  ", "bold bright_green"), (f"v{__version__}", "white")),
                    box=_HEAVY_BOX, title="[ VERSION ]", title_align="left",
                    border_style="bright_green", padding=(0, 0),
                ))

            elif choice in {"0", "q", "quit", "exit"}:
                console.print(Text("  [*] session closed.", style="dim green"))
                return
            else:
                console.print(f"Unknown menu option '{choice}'. Choose 0-9.")
        except click.ClickException as exc:
            console.print(f"[bold red]Error:[/bold red] {exc.format_message()}")
        except (InvalidTargetError, SecAuditError, ReportError, UnknownModuleError, ConfigError) as exc:
            console.print(f"[bold red]Error:[/bold red] {exc}")


@app.command("wizard", hidden=True)
@click.argument("target", required=False)
@click.option("--config", "config_path", type=click.Path(dir_okay=False, path_type=Path), default=None)
@click.option("--no-banner", is_flag=True)
@click.option("--no-color", is_flag=True)
def wizard_command(target: str | None, config_path: Path | None, no_banner: bool, no_color: bool) -> None:
    """Alias for the interactive control deck."""

    ctx = click.get_current_context()
    ctx.invoke(interactive_command, target=target, config_path=config_path, no_banner=no_banner, no_color=no_color)


@app.command("init")
@click.option("--path", "config_path", type=click.Path(dir_okay=False, path_type=Path), default=DEFAULT_CONFIG_PATH, show_default=True)
@click.option("--force", is_flag=True, help="Overwrite an existing config file.")
def init_command(config_path: Path, force: bool) -> None:
    """Create a starter secaudit.toml configuration file."""

    if config_path.exists() and not force:
        raise click.ClickException(f"{config_path} already exists. Re-run with --force to overwrite it.")
    _write_output(config_path, render_default_config())
    click.echo(f"Wrote {config_path}")


@app.command("compare")
@click.argument("old_json", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("new_json", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--json", "json_path", type=click.Path(dir_okay=False), default=None, help="Write the diff as JSON.")
@click.option("--html", "html_path", type=click.Path(dir_okay=False), default=None, help="Write an HTML report for the new scan with diff data.")
@click.option("--no-color", is_flag=True, help="Disable Rich colors.")
def compare_command(old_json: Path, new_json: Path, json_path: str | None, html_path: str | None, no_color: bool) -> None:
    """Compare two saved JSON reports."""

    try:
        old_report = load_json_report(old_json)
        new_report = load_json_report(new_json)
    except ReportError as exc:
        raise click.ClickException(str(exc)) from exc

    diff = compare_reports(old_report, new_report)
    if json_path:
        _write_output(json_path, render_json_diff(diff))
    if html_path:
        _write_output(html_path, render_html_report(new_report, diff=diff))
    reporter = TerminalReporter(show_banner=False, color=not no_color, quiet=False, verbose=False, ci=False)
    reporter.display_diff(diff)
    if json_path or html_path:
        reporter.console.print(f"Saved reports: json={json_path or '-'} html={html_path or '-'}")


@app.command("version")
def version_command() -> None:
    """Print the installed SecAudit version."""

    click.echo(f"SecAudit {__version__}")


main = app
