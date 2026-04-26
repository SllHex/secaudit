"""Console construction helpers."""

from __future__ import annotations

from rich.console import Console


def build_console(*, no_color: bool = False, record: bool = True) -> Console:
    """Build a consistent Rich console for SecAudit."""

    return Console(record=record, no_color=no_color, soft_wrap=True)
