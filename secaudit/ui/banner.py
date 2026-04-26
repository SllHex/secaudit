"""Terminal banner variants for SecAudit."""

from __future__ import annotations

from rich.box import HEAVY, MINIMAL_HEAVY_HEAD, SIMPLE_HEAVY
from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from .. import __version__

BANNER_VARIANTS = ("matrix", "stealth", "ghost", "minimal")
DEFAULT_BANNER_VARIANT = "matrix"

# ANSI Shadow font — SECAUDIT (verified 6 rows × 62 cols)
_LOGO = (
    "███████╗███████╗ ██████╗ █████╗ ██╗   ██╗██████╗ ██╗████████╗\n"
    "██╔════╝██╔════╝██╔════╝██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝\n"
    "███████╗█████╗  ██║     ███████║██║   ██║██║  ██║██║   ██║   \n"
    "╚════██║██╔══╝  ██║     ██╔══██║██║   ██║██║  ██║██║   ██║   \n"
    "███████║███████╗╚██████╗██║  ██║╚██████╔╝██████╔╝██║   ██║   \n"
    "╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝╚═╝   ╚═╝   "
)

_TAGLINES = {
    "matrix":  "safe · external · non-destructive  //  web security audit",
    "stealth": "low-noise external posture scanner",
    "ghost":   "external · passive · safe",
    "minimal": "web security audit",
}


def _matrix_banner(host: str, tagline: str) -> RenderableType:
    logo = Text(_LOGO, style="bold bright_green")
    sep  = Rule(style="dark_green")
    meta = Group(
        Text(f"  target   //  {host}", style="bright_green"),
        Text( "  mode     //  external · passive · non-destructive", style="green"),
        Text(f"  version  //  v{__version__}   │   github.com/SllHex", style="dim green"),
    )
    return Panel(
        Group(logo, Text(""), sep, Text(""), meta),
        box=HEAVY,
        border_style="bright_green",
        padding=(0, 1),
        subtitle=f"[ {tagline} ]",
        subtitle_align="right",
    )


def _stealth_banner(host: str, tagline: str) -> RenderableType:
    mark = Text.assemble(
        ("┌─", "bright_black"),
        (" SEC//AUDIT ", "bold bright_white"),
        ("─┐", "bright_black"),
    )
    meta = Group(
        Text.assemble(("v", "bright_black"), (__version__, "white"), ("  //  ", "bright_black"), (tagline, "cyan")),
        Text.assemble(("target  ", "bright_black"), (host, "bold white")),
    )
    grid = Table.grid(expand=False, padding=(0, 2))
    grid.add_column()
    grid.add_column()
    grid.add_row(mark, meta)
    return Panel(grid, box=SIMPLE_HEAVY, border_style="bright_cyan", padding=(0, 1))


def _ghost_banner(host: str, tagline: str) -> RenderableType:
    lines = [
        Text.assemble(("root@secaudit", "bright_green"), (":~# ", "bright_black"), (f"./scan {host} --safe", "white")),
        Text("", style=""),
        Text.assemble(("  [*] ", "bright_black"), (tagline, "green"), (f"  v{__version__}", "dim")),
    ]
    return Panel(
        Group(*lines),
        box=HEAVY,
        border_style="green",
        padding=(0, 1),
        title="[ SEC//AUDIT ]",
        title_align="left",
    )


def _minimal_banner(host: str, tagline: str) -> RenderableType:
    return Panel(
        Text.assemble(
            ("SEC//AUDIT ", "bold bright_green"),
            (f"v{__version__}  ", "bright_black"),
            ("//  ", "bright_black"),
            (host, "bold white"),
            (f"  ·  {tagline}", "dim"),
        ),
        box=SIMPLE_HEAVY,
        border_style="bright_black",
        padding=(0, 1),
    )


def render_banner(
    host: str,
    *,
    variant: str = DEFAULT_BANNER_VARIANT,
    tagline: str = "",
) -> RenderableType:
    """Render the selected terminal banner variant."""

    variant = variant.lower()
    resolved_tagline = tagline or _TAGLINES.get(variant, _TAGLINES["matrix"])
    if variant == "stealth":
        return _stealth_banner(host, resolved_tagline)
    if variant == "ghost":
        return _ghost_banner(host, resolved_tagline)
    if variant == "minimal":
        return _minimal_banner(host, resolved_tagline)
    return _matrix_banner(host, resolved_tagline)
