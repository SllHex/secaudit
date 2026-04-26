"""Backward-compatible compatibility layer for older SecAudit imports."""

from __future__ import annotations

from . import __version__
from .context import (
    CSRF_COOKIE_NAME,
    DEFAULT_TIMEOUT,
    EXPECTED_ERROR_STATUSES,
    TURNSTILE_HOST,
    AuditContext,
    normalize_whitespace,
    parse_cookie_headers,
)
from .diff import compare_reports
from .engine import count_statuses, derive_module_status, execute_modules
from .http import USER_AGENT, HttpClient, isoformat_utc, parse_certificate_expiry, utc_now
from .models import (
    STATUS_ORDER,
    SEVERITY_ORDER,
    AuditDiff,
    AuditModule,
    AuditReport,
    CheckResult,
    HttpResponse,
    ModuleRun,
    ResultChange,
    SeverityType,
    StatusType,
    TLSDetails,
)
from .scoring import count_severity_levels, exit_code_for_report, grade_for_score, issue_sort_key, score_results, top_issues

APP_VERSION = __version__

__all__ = [
    "APP_VERSION",
    "AuditContext",
    "AuditDiff",
    "AuditModule",
    "AuditReport",
    "CSRF_COOKIE_NAME",
    "CheckResult",
    "DEFAULT_TIMEOUT",
    "EXPECTED_ERROR_STATUSES",
    "HttpClient",
    "HttpResponse",
    "ModuleRun",
    "ResultChange",
    "SEVERITY_ORDER",
    "STATUS_ORDER",
    "SeverityType",
    "StatusType",
    "TLSDetails",
    "TURNSTILE_HOST",
    "USER_AGENT",
    "compare_reports",
    "count_severity_levels",
    "count_statuses",
    "derive_module_status",
    "execute_modules",
    "exit_code_for_report",
    "grade_for_score",
    "isoformat_utc",
    "issue_sort_key",
    "normalize_whitespace",
    "parse_certificate_expiry",
    "parse_cookie_headers",
    "score_results",
    "top_issues",
    "utc_now",
]
