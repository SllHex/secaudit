"""Rich-powered terminal output for SecAudit."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich.box import HEAVY, HEAVY_HEAD, MINIMAL_HEAVY_HEAD
from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.rule import Rule
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from ..context import AuditContext
from ..models import AuditDiff, AuditModule, AuditReport, CheckResult, ModuleRun
from ..scoring import count_severity_levels, top_issues
from ..ui import build_console, build_top_issues_table, render_banner

# ── Status display maps ──────────────────────────────────────────────────────

STATUS_STYLE: dict[str, str] = {
    "PASS": "bold bright_green",
    "WARN": "bold yellow",
    "FAIL": "bold red",
    "INFO": "cyan",
}

STATUS_ICON: dict[str, str] = {
    "PASS": "[+]",
    "WARN": "[-]",
    "FAIL": "[!]",
    "INFO": "[*]",
}

SEV_STYLE: dict[str, str] = {
    "critical": "bold red",
    "high":     "bold red",
    "medium":   "bold yellow",
    "low":      "cyan",
    "info":     "bright_black",
}

# Grade → color (A = green, F = red)
GRADE_STYLE: dict[str, str] = {
    "A+": "bold bright_green", "A":  "bold bright_green", "A-": "bold green",
    "B+": "bold green",        "B":  "bold cyan",          "B-": "bold cyan",
    "C+": "bold yellow",       "C":  "bold yellow",        "C-": "bold yellow",
    "D":  "bold red",          "F":  "bold red",
}


# ── Internal helpers ─────────────────────────────────────────────────────────

@dataclass(slots=True)
class _ModuleState:
    slug: str
    name: str
    status: str = "pending"
    counts: dict[str, int] | None = None
    duration_seconds: float = 0.0


def _counts_text(counts: dict[str, int]) -> Text:
    total   = sum(counts.values())
    passed  = counts.get("PASS", 0)
    fails   = counts.get("FAIL", 0)
    warns   = counts.get("WARN", 0)
    t = Text()
    base_style = "bright_green" if not fails and not warns else "white"
    t.append(f"{passed}/{total}", style=base_style)
    if warns:
        t.append(f"  {warns} warn", style="yellow")
    if fails:
        t.append(f"  {fails} fail", style="bold red")
    return t


def _score_style(score: int) -> str:
    if score >= 90:
        return "bold bright_green"
    if score >= 75:
        return "bold green"
    if score >= 60:
        return "bold yellow"
    return "bold red"


# ── Plain-text export ────────────────────────────────────────────────────────

def render_text_report(report: AuditReport) -> str:
    """Render a plain-text report for disk export."""

    lines = [
        f"SecAudit v{report.version} · {report.target}",
        f"Score: {report.score}/100 · Grade: {report.grade}",
        f"PASS: {report.counts['PASS']}  WARN: {report.counts['WARN']}  FAIL: {report.counts['FAIL']}  INFO: {report.counts['INFO']}",
        f"Time: {report.duration_seconds:.2f}s",
        "",
    ]
    for module in report.modules:
        lines.append(f"[{module.status:<4}] {module.name} ({module.duration_seconds:.2f}s)")
        for result in module.results:
            lines.append(f"  [{result.status:<4}] {result.name} — {result.summary}")
            if result.details:
                lines.append(f"           {result.details}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# ── Reporter ─────────────────────────────────────────────────────────────────

class TerminalReporter:
    """Rich-powered live progress and final summary renderer."""

    def __init__(
        self,
        *,
        show_banner: bool = True,
        color: bool = True,
        quiet: bool = False,
        verbose: bool = False,
        ci: bool = False,
        banner_variant: str = "matrix",
    ) -> None:
        self.console = build_console(no_color=not color, record=True)
        self.show_banner    = show_banner
        self.quiet          = quiet
        self.verbose        = verbose
        self.ci             = ci
        self.banner_variant = banner_variant
        self._states: dict[str, _ModuleState] = {}
        self._live: Live | None = None

    # ── Lifecycle ────────────────────────────────────────────────────────────

    def start(self, context: AuditContext, modules: list[AuditModule]) -> None:
        if self.show_banner and not self.quiet and not self.ci:
            self.console.print(
                render_banner(context.host or context.base_url, variant=self.banner_variant)
            )
        self._states = {m.slug: _ModuleState(slug=m.slug, name=m.name) for m in modules}
        if not self.quiet and not self.ci:
            self._live = Live(
                self._render_progress(),
                console=self.console,
                refresh_per_second=10,
                transient=False,
            )
            self._live.start()

    def on_module_start(self, module: AuditModule) -> None:
        self._states[module.slug].status = "running"
        self._refresh()

    def on_module_finish(self, module_run: ModuleRun) -> None:
        state = self._states[module_run.slug]
        state.status           = module_run.status
        state.counts           = module_run.counts
        state.duration_seconds = module_run.duration_seconds
        self._refresh()

    def finish(self) -> None:
        if self._live is not None:
            self._live.stop()
            self._live = None

    # ── Final report ─────────────────────────────────────────────────────────

    def display_report(
        self,
        report: AuditReport,
        *,
        profile: str,
        report_paths: dict[str, str] | None = None,
    ) -> None:
        severity_counts = count_severity_levels(report.results)

        # CI one-liner mode
        if self.ci:
            self.console.print(
                f"target={report.target} profile={profile} score={report.score} grade={report.grade} "
                f"pass={severity_counts['passed']} critical={severity_counts['critical']} "
                f"high={severity_counts['high']} medium={severity_counts['medium']} "
                f"low={severity_counts['low']} info={severity_counts['info']}"
            )
            for issue in top_issues(report.results):
                self.console.print(f"{issue.severity.upper()} {issue.module}:{issue.name} {issue.summary}")
            if report_paths:
                for label, path in report_paths.items():
                    self.console.print(f"{label}={Path(path)}")
            return

        high_count = severity_counts["critical"] + severity_counts["high"]
        grade_style = GRADE_STYLE.get(report.grade, "bold white")

        rows: list[Any] = [
            Text.assemble(("  target   //  ", "bright_black"), (report.target, "bold bright_green")),
            Text.assemble(("  profile  //  ", "bright_black"), (profile, "cyan")),
            Text.assemble(
                ("  score    //  ", "bright_black"),
                (str(report.score), _score_style(report.score)),
                (" / 100  ", "bright_black"),
                ("grade ", "bright_black"),
                (report.grade, grade_style),
            ),
            Text.assemble(
                ("  checks   //  ", "bright_black"),
                (f"[+] {severity_counts['passed']} pass", "bright_green"),
                ("   ", ""),
                (f"[!] {high_count} high", "bold red" if high_count else "bright_black"),
                ("   ", ""),
                (f"[-] {severity_counts['medium']} med", "yellow" if severity_counts["medium"] else "bright_black"),
                ("   ", ""),
                (f"[*] {severity_counts['info']} info", "bright_black"),
            ),
            Text.assemble(("  time     //  ", "bright_black"), (f"{report.duration_seconds:.2f}s", "dim")),
        ]
        if report_paths:
            for label, path in report_paths.items():
                rows.append(
                    Text.assemble((f"  {label:<8} //  ", "bright_black"), (str(Path(path)), "dim"))
                )

        self.console.print(Rule(style="bright_green"))
        self.console.print(Panel(
            Group(*rows),
            box=HEAVY,
            title="[ AUDIT COMPLETE ]",
            title_align="left",
            border_style="bright_green",
            padding=(0, 0),
        ))
        self.console.print(build_top_issues_table(top_issues(report.results)))
        self.console.print(self._render_module_summary(report.modules))
        if self.verbose:
            for module in report.modules:
                self.console.print(self._render_module_detail(module))
        self.console.print(Rule(style="bright_green"))

    # ── Diff display ─────────────────────────────────────────────────────────

    def display_diff(self, diff: AuditDiff, title: str = "DIFF") -> None:
        delta      = diff.score_after - diff.score_before
        delta_str  = f"+{delta}" if delta >= 0 else str(delta)
        delta_style = "bright_green" if delta >= 0 else "bold red"

        self.console.print(Panel(
            Group(
                Text.assemble(
                    ("  score   //  ", "bright_black"),
                    (str(diff.score_before), "white"), (" → ", "bright_black"),
                    (str(diff.score_after), "bright_green" if delta >= 0 else "bold red"),
                    (f"  ({delta_str})", delta_style),
                ),
                Text.assemble(
                    ("  grade   //  ", "bright_black"),
                    (diff.grade_before, "white"), (" → ", "bright_black"),
                    (diff.grade_after, GRADE_STYLE.get(diff.grade_after, "white")),
                ),
                Text.assemble(
                    ("  changes //  ", "bright_black"),
                    (f"[!] {len(diff.changed)} changed", "yellow" if diff.changed else "bright_black"),
                    ("   ", ""),
                    (f"[+] {len(diff.added)} added", "bright_green" if diff.added else "bright_black"),
                    ("   ", ""),
                    (f"[-] {len(diff.removed)} removed", "red" if diff.removed else "bright_black"),
                ),
            ),
            box=HEAVY,
            title=f"[ {title.upper()} ]",
            title_align="left",
            border_style="bright_green",
            padding=(0, 0),
        ))

        if not (diff.changed or diff.added or diff.removed):
            return

        table = Table(
            title="  // CHANGES",
            title_style="bold bright_green",
            header_style="bold bright_green",
            box=HEAVY_HEAD,
            show_edge=True,
            padding=(0, 1),
        )
        table.add_column("type",   width=12, no_wrap=True)
        table.add_column("module", style="cyan", width=14, no_wrap=True)
        table.add_column("check",  style="bright_black", width=32, no_wrap=True)
        table.add_column("detail", style="white")
        for ch in diff.changed[:20]:
            table.add_row(
                Text("[-] changed", style="yellow"),
                ch.module, ch.name,
                f"{ch.old_status}/{ch.old_severity} → {ch.new_status}/{ch.new_severity}",
            )
        for r in diff.added[:10]:
            table.add_row(Text("[+] added",   style="bright_green"), r.module, r.name,
                          f"{r.status}/{r.severity} · {r.summary}")
        for r in diff.removed[:10]:
            table.add_row(Text("[!] removed", style="red"),          r.module, r.name,
                          f"{r.status}/{r.severity} · {r.summary}")
        self.console.print(table)

    # ── Export ───────────────────────────────────────────────────────────────

    def export_text(self) -> str:
        return self.console.export_text(clear=False)

    # ── Internal renderers ───────────────────────────────────────────────────

    def _refresh(self) -> None:
        if self._live is not None:
            self._live.update(self._render_progress())

    def _render_progress(self) -> Table:
        table = Table(
            title="  // SCANNING",
            title_style="bold bright_green",
            header_style="bold bright_green",
            box=HEAVY_HEAD,
            show_edge=True,
            padding=(0, 1),
        )
        table.add_column("module",  style="white", width=20, no_wrap=True)
        table.add_column("status",  width=22, no_wrap=True)
        table.add_column("checks")

        for state in self._states.values():
            if state.status == "pending":
                status_cell: Any = Text("[ ] queued", style="bright_black")
                checks_cell: Any = Text("─", style="bright_black")
            elif state.status == "running":
                status_cell = Spinner("dots", text=" scanning...", style="yellow")
                checks_cell = Text("...", style="bright_black")
            else:
                icon = STATUS_ICON.get(state.status, "[?]")
                status_cell = Text(
                    f"{icon} done  {state.duration_seconds:.1f}s",
                    style=STATUS_STYLE.get(state.status, "white"),
                )
                checks_cell = _counts_text(state.counts or {"PASS": 0, "WARN": 0, "FAIL": 0, "INFO": 0})
            table.add_row(state.name, status_cell, checks_cell)
        return table

    def _render_module_summary(self, modules: list[ModuleRun]) -> Table:
        table = Table(
            title="  // MODULE SUMMARY",
            title_style="bold bright_green",
            header_style="bold bright_green",
            box=HEAVY_HEAD,
            show_edge=True,
            padding=(0, 1),
        )
        table.add_column("module", style="white", width=20, no_wrap=True)
        table.add_column("status",  width=14, no_wrap=True)
        table.add_column("checks")
        table.add_column("time", justify="right", style="bright_black", width=8, no_wrap=True)
        for module in modules:
            icon = STATUS_ICON.get(module.status, "[?]")
            table.add_row(
                module.name,
                Text(f"{icon} {module.status}", style=STATUS_STYLE.get(module.status, "white")),
                _counts_text(module.counts),
                f"{module.duration_seconds:.2f}s",
            )
        return table

    def _render_module_detail(self, module: ModuleRun) -> Panel:
        table = Table(
            header_style="bold bright_green",
            box=MINIMAL_HEAVY_HEAD,
            show_edge=False,
            padding=(0, 1),
        )
        table.add_column("status", width=10, no_wrap=True)
        table.add_column("check",  style="cyan", width=36, no_wrap=True)
        table.add_column("sev",    style="bright_black", width=8, no_wrap=True)
        table.add_column("detail", style="white")
        for result in module.results:
            icon = STATUS_ICON.get(result.status, "[?]")
            detail = result.summary if not result.details else f"{result.summary}\n{result.details}"
            table.add_row(
                Text(f"{icon} {result.status}", style=STATUS_STYLE.get(result.status, "white")),
                result.name,
                result.severity,
                detail,
            )
        return Panel(
            table,
            box=HEAVY,
            title=f"[ {module.name.upper()} ]",
            title_align="left",
            border_style="bright_green",
        )
