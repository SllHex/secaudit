"""Interactive menu UI for guided SecAudit runs."""

from __future__ import annotations

from pathlib import Path

from rich.box import HEAVY, HEAVY_HEAD
from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from .. import __version__
from ..config import ScanSettings
from ..profiles import ProfileSpec
from ..registry import ModuleSpec
from .banner import _LOGO


def render_interactive_splash() -> RenderableType:
    """Render the interactive-mode splash."""

    logo = Text(_LOGO, style="bold bright_green")
    sep  = Rule(style="dark_green")
    meta = Group(
        Text(f"  version  //  v{__version__}", style="bright_green"),
        Text( "  mode     //  interactive · control deck", style="green"),
        Text( "  [+] operator console online", style="bright_green"),
        Text( "  [+] zero-exploit · non-destructive · safe", style="green"),
        Text( "  [*] select an operation from the deck below", style="dim green"),
    )
    return Panel(
        Group(logo, Text(""), sep, Text(""), meta),
        box=HEAVY,
        border_style="bright_green",
        padding=(0, 1),
        title="[ SEC//AUDIT ]",
        title_align="left",
        subtitle="[ CONTROL DECK ]",
        subtitle_align="right",
    )


def build_main_menu_table() -> RenderableType:
    """Render the interactive main menu."""

    scan_rows = (
        ("1", "BLITZ    ", "quick   ", "Fastest path — DNS/TLS/Headers sweep."),
        ("2", "GHOST    ", "standard", "Full safe-web audit. Recommended default."),
        ("3", "BLACKSITE", "deep    ", "Complete surface review + rate-limit probe."),
        ("4", "LOADOUT  ", "custom  ", "Expert: hand-pick exact modules to run."),
    )
    tool_rows = (
        ("5", "ATLAS  ", "Browse all modules grouped by category."),
        ("6", "DECRYPT", "Explain a module — checks, risks, remediation."),
        ("7", "DIFF   ", "Compare two saved JSON reports and show drift."),
        ("8", "FORGE  ", "Write or regenerate a secaudit.toml config."),
        ("9", "VER    ", "Show installed SecAudit version."),
        ("0", "EXIT   ", "Leave the control deck."),
    )

    scan_tbl = Table(
        box=HEAVY_HEAD,
        header_style="bold bright_green",
        show_edge=True,
        padding=(0, 1),
        min_width=60,
    )
    scan_tbl.add_column("#", style="bold bright_green", width=3, no_wrap=True)
    scan_tbl.add_column("Operation", style="bold white", width=11, no_wrap=True)
    scan_tbl.add_column("Profile", style="cyan", width=10, no_wrap=True)
    scan_tbl.add_column("Description", style="bright_black")
    for num, name, profile, desc in scan_rows:
        scan_tbl.add_row(num, name, profile, desc)

    tool_tbl = Table(
        box=HEAVY_HEAD,
        header_style="bold bright_green",
        show_edge=True,
        padding=(0, 1),
        show_header=False,
        min_width=60,
    )
    tool_tbl.add_column("#", style="bold green", width=3, no_wrap=True)
    tool_tbl.add_column("Tool", style="white", width=23, no_wrap=True)
    tool_tbl.add_column("Description", style="bright_black")
    for num, name, desc in tool_rows:
        tool_tbl.add_row(num, name, desc)

    return Group(
        Rule(style="bright_green"),
        Text("  SCAN OPERATIONS", style="bold bright_green"),
        scan_tbl,
        Text("  TOOLS", style="bold green"),
        tool_tbl,
        Rule(style="bright_green"),
    )


def build_profile_choice_table(profiles: tuple[ProfileSpec, ...]) -> Table:
    """Render available scan profiles as a numbered selection."""

    table = Table(
        box=HEAVY_HEAD,
        header_style="bold bright_green",
        show_edge=True,
        padding=(0, 1),
    )
    table.add_column("#", style="bold bright_green", width=4)
    table.add_column("Profile", style="bold white", width=22)
    table.add_column("Modules", style="cyan")
    table.add_column("Description", style="bright_black")
    for i, profile in enumerate(profiles, 1):
        table.add_row(
            str(i),
            f"{profile.title} ({profile.slug})",
            ", ".join(profile.modules),
            profile.description,
        )
    return table


def build_module_picker_table(specs: tuple[ModuleSpec, ...]) -> Table:
    """Render numbered module picker for allow/skip selection."""

    table = Table(
        box=HEAVY_HEAD,
        header_style="bold bright_green",
        show_edge=True,
        padding=(0, 1),
    )
    table.add_column("#", style="bold bright_green", width=4)
    table.add_column("Slug", style="bold cyan", width=18)
    table.add_column("Title", style="white", width=20)
    table.add_column("Category", style="bright_black")
    for i, spec in enumerate(specs, 1):
        table.add_row(str(i), spec.slug, spec.title, spec.category)
    return table


def render_settings_preview(settings: ScanSettings, *, selected_reports: list[str]) -> RenderableType:
    """Render a final preview panel before the audit starts."""

    rows: list[Text] = [
        Text.assemble(("  target   //  ", "bright_black"), (settings.target, "bold bright_green")),
        Text.assemble(("  profile  //  ", "bright_black"), (settings.profile, "cyan")),
        Text.assemble(
            ("  modules  //  ", "bright_black"),
            (", ".join(settings.only) if settings.only else "profile default", "white"),
        ),
        Text.assemble(
            ("  skip     //  ", "bright_black"),
            (", ".join(settings.skip) if settings.skip else "-", "white"),
        ),
        Text.assemble(
            ("  output   //  ", "bright_black"),
            (", ".join(selected_reports) if selected_reports else "terminal", "white"),
        ),
        Text.assemble(("  timeout  //  ", "bright_black"), (f"{settings.timeout}s", "white")),
    ]
    if settings.json_report:
        rows.append(Text.assemble(("  json     //  ", "bright_black"), (str(Path(settings.json_report)), "dim")))
    if settings.html_report:
        rows.append(Text.assemble(("  html     //  ", "bright_black"), (str(Path(settings.html_report)), "dim")))
    if settings.fail_on:
        rows.append(Text.assemble(("  fail-on  //  ", "bright_black"), (settings.fail_on, "yellow")))

    return Panel(
        Group(*rows),
        box=HEAVY,
        title="[ RUN PREVIEW ]",
        title_align="left",
        border_style="bright_green",
        padding=(0, 0),
    )
