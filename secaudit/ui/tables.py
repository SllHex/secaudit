"""Reusable Rich table builders for SecAudit CLI output."""

from __future__ import annotations

from rich.box import HEAVY_HEAD, MINIMAL_HEAVY_HEAD
from rich.table import Table
from rich.text import Text

from ..models import CheckResult
from ..registry import ModuleSpec

# Severity → Rich style
SEV_STYLE: dict[str, str] = {
    "critical": "bold red",
    "high":     "bold red",
    "medium":   "bold yellow",
    "low":      "cyan",
    "info":     "bright_black",
}

# Status → Rich style
STATUS_STYLE: dict[str, str] = {
    "PASS": "bold bright_green",
    "WARN": "bold yellow",
    "FAIL": "bold red",
    "INFO": "cyan",
}

# Status → hacker-style icon prefix
STATUS_ICON: dict[str, str] = {
    "PASS": "[+]",
    "WARN": "[-]",
    "FAIL": "[!]",
    "INFO": "[*]",
}


def _status_text(status: str) -> Text:
    icon = STATUS_ICON.get(status, "[?]")
    return Text(f"{icon} {status}", style=STATUS_STYLE.get(status, "white"))


def _sev_text(severity: str) -> Text:
    return Text(severity.upper(), style=SEV_STYLE.get(severity, "white"))


def build_modules_table(category: str, specs: list[ModuleSpec]) -> Table:
    """Render a grouped modules overview table."""

    table = Table(
        title=f"  // {category.upper()}",
        title_style="bold bright_green",
        header_style="bold bright_green",
        box=HEAVY_HEAD,
        show_edge=True,
        padding=(0, 1),
    )
    table.add_column("slug", style="bold cyan", width=18, no_wrap=True)
    table.add_column("title", style="white", width=20)
    table.add_column("profiles", style="bright_black", width=26)
    table.add_column("description", style="bright_black")
    for spec in specs:
        table.add_row(spec.slug, spec.title, ", ".join(spec.included_in), spec.description)
    return table


def build_explain_table(spec: ModuleSpec) -> Table:
    """Render a detailed explain table for a single module."""

    table = Table(
        title=f"  // {spec.title.upper()}  ({spec.slug})",
        title_style="bold bright_green",
        header_style="bold bright_green",
        box=MINIMAL_HEAVY_HEAD,
        show_edge=True,
        padding=(0, 1),
    )
    table.add_column("field", style="bold cyan", width=20, no_wrap=True)
    table.add_column("value", style="white")
    table.add_row("category",        spec.category)
    table.add_row("aliases",         ", ".join(spec.aliases) or "-")
    table.add_row("profiles",        ", ".join(spec.included_in))
    table.add_row("purpose",         spec.purpose or spec.description)
    table.add_row("risks",           ", ".join(spec.risks) or "General misconfiguration detection")
    table.add_row("common findings", ", ".join(spec.common_findings) or "Depends on target posture")
    table.add_row(
        "remediation",
        spec.remediation or spec.guidance or "Review findings and tighten the affected configuration.",
    )
    return table


def build_top_issues_table(issues: list[CheckResult]) -> Table:
    """Render the top issues table."""

    table = Table(
        title="  // TOP ISSUES",
        title_style="bold bright_green",
        header_style="bold bright_green",
        box=HEAVY_HEAD,
        show_edge=True,
        padding=(0, 1),
    )
    table.add_column("sev",    width=12, no_wrap=True)
    table.add_column("module", style="cyan", width=14, no_wrap=True)
    table.add_column("check",  style="bright_black", width=32, no_wrap=True)
    table.add_column("summary", style="white")

    if not issues:
        table.add_row(
            Text("[+] CLEAN", style="bold bright_green"),
            "-", "-",
            "No FAIL or WARN findings recorded.",
        )
        return table

    for issue in issues:
        icon = STATUS_ICON.get(issue.status, "[?]")
        sev_cell = Text(
            f"{icon} {issue.severity.upper()}",
            style=SEV_STYLE.get(issue.severity, "white"),
        )
        table.add_row(sev_cell, issue.module, issue.name, issue.summary)
    return table
