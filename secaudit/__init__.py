"""SecAudit package metadata and public exports."""

__version__ = "1.1.0"

from .context import AuditContext
from .errors import ConfigError, InvalidTargetError, ReportError, SecAuditError, UnknownModuleError
from .http import HttpClient
from .models import AuditModule, AuditReport, CheckResult

__all__ = [
    "AuditContext",
    "AuditModule",
    "AuditReport",
    "CheckResult",
    "ConfigError",
    "HttpClient",
    "InvalidTargetError",
    "ReportError",
    "SecAuditError",
    "UnknownModuleError",
]
