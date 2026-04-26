"""Audit execution engine and aggregate helpers."""

from __future__ import annotations

import asyncio
import time
import traceback
from typing import Any

from . import __version__
from .context import AuditContext
from .http import USER_AGENT, HttpClient, isoformat_utc
from .models import AuditModule, AuditReport, CheckResult, ModuleRun, StatusType
from .scoring import grade_for_score, score_results


def count_statuses(results: list[CheckResult]) -> dict[str, int]:
    """Count PASS/WARN/FAIL/INFO results."""

    counts = {"PASS": 0, "WARN": 0, "FAIL": 0, "INFO": 0}
    for item in results:
        counts[item.status] = counts.get(item.status, 0) + 1
    return counts


def derive_module_status(results: list[CheckResult]) -> StatusType:
    """Summarize a module status from its findings."""

    if any(item.status == "FAIL" for item in results):
        return "FAIL"
    if any(item.status == "WARN" for item in results):
        return "WARN"
    if any(item.status == "INFO" for item in results) and not any(item.status == "PASS" for item in results):
        return "INFO"
    return "PASS"


async def _run_module(
    module: AuditModule,
    client: HttpClient,
    context: AuditContext,
    reporter: Any | None,
) -> ModuleRun:
    """Run a single module, reporting lifecycle events and catching crashes."""

    module_started = time.perf_counter()
    if reporter is not None:
        reporter.on_module_start(module)
    try:
        results = await module.run(client, context)
    except Exception as exc:  # noqa: BLE001
        results = [
            CheckResult(
                name=f"{module.slug}-module-crash",
                status="FAIL",
                severity="critical",
                summary=f"Module {module.name} crashed during execution.",
                details="".join(traceback.format_exception_only(type(exc), exc)).strip(),
                module=module.slug,
            )
        ]
    for result in results:
        if not result.module:
            result.module = module.slug
    duration = time.perf_counter() - module_started
    module_run = ModuleRun(
        slug=module.slug,
        name=module.name,
        description=module.description,
        status=derive_module_status(results),
        duration_seconds=duration,
        counts=count_statuses(results),
        results=results,
    )
    if reporter is not None:
        reporter.on_module_finish(module_run)
    return module_run


async def execute_modules(
    modules: list[AuditModule],
    context: AuditContext,
    reporter: Any | None = None,
) -> AuditReport:
    """Run all modules concurrently and build a full report."""

    run_started = time.perf_counter()

    async with HttpClient(timeout=context.timeout, user_agent=context.user_agent or USER_AGENT) as client:
        if reporter is not None:
            reporter.start(context, modules)

        module_runs: list[ModuleRun] = list(
            await asyncio.gather(*[_run_module(module, client, context, reporter) for module in modules])
        )

        if reporter is not None:
            reporter.finish()

    all_results = [result for module in module_runs for result in module.results]
    total_duration = time.perf_counter() - run_started
    score = score_results(all_results)
    return AuditReport(
        version=__version__,
        target=context.base_url,
        host=context.host,
        generated_at=isoformat_utc(),
        duration_seconds=total_duration,
        score=score,
        grade=grade_for_score(score),
        counts=count_statuses(all_results),
        options=context.options_dict(),
        modules=module_runs,
        results=all_results,
    )
