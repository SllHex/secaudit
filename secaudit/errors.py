"""Custom exceptions for SecAudit."""

from __future__ import annotations


class SecAuditError(Exception):
    """Base exception for user-facing SecAudit errors."""


class InvalidTargetError(SecAuditError):
    """Raised when a target URL is malformed or unsupported."""


class UnknownModuleError(SecAuditError):
    """Raised when a requested module slug or alias is unknown."""


class ReportError(SecAuditError):
    """Raised when a report cannot be rendered, parsed, or written."""


class ConfigError(SecAuditError):
    """Raised when the SecAudit configuration file is invalid."""
