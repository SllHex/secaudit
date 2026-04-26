"""Core dataclasses and shared type definitions for SecAudit."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Literal


StatusType = Literal["PASS", "WARN", "FAIL", "INFO"]
SeverityType = Literal["critical", "high", "medium", "low", "info"]

STATUS_ORDER = {"FAIL": 0, "WARN": 1, "INFO": 2, "PASS": 3}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(slots=True)
class HttpResponse:
    """A normalized HTTP response snapshot used by audit modules."""

    url: str
    status: int | None
    headers: dict[str, str]
    body: str
    error: str = ""
    header_values: dict[str, list[str]] = field(default_factory=dict)


@dataclass(slots=True)
class TLSDetails:
    """A normalized TLS handshake result."""

    cert: dict[str, Any]
    tls_version: str
    cipher_name: str
    cipher_bits: int


@dataclass(slots=True)
class CheckResult:
    """A single audit finding."""

    name: str
    status: StatusType
    severity: SeverityType
    summary: str
    details: str = ""
    module: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize the finding into JSON-safe primitives."""

        return {
            "name": self.name,
            "status": self.status,
            "severity": self.severity,
            "summary": self.summary,
            "details": self.details,
            "module": self.module,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "CheckResult":
        """Rebuild a finding from JSON data."""

        return cls(
            name=str(payload.get("name", "")),
            status=str(payload.get("status", "INFO")).upper(),  # type: ignore[arg-type]
            severity=str(payload.get("severity", "info")).lower(),  # type: ignore[arg-type]
            summary=str(payload.get("summary", "")),
            details=str(payload.get("details", "")),
            module=str(payload.get("module", "")),
        )


@dataclass(slots=True)
class ModuleRun:
    """Execution summary for a single audit module."""

    slug: str
    name: str
    description: str
    status: StatusType
    duration_seconds: float
    counts: dict[str, int]
    results: list[CheckResult]

    def to_dict(self) -> dict[str, Any]:
        """Serialize the module run."""

        return {
            "slug": self.slug,
            "name": self.name,
            "description": self.description,
            "status": self.status,
            "duration_seconds": round(self.duration_seconds, 4),
            "counts": dict(self.counts),
            "results": [result.to_dict() for result in self.results],
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ModuleRun":
        """Rebuild a module run from JSON data."""

        results = [CheckResult.from_dict(item) for item in payload.get("results", [])]
        return cls(
            slug=str(payload.get("slug", "")),
            name=str(payload.get("name", "")),
            description=str(payload.get("description", "")),
            status=str(payload.get("status", "INFO")).upper(),  # type: ignore[arg-type]
            duration_seconds=float(payload.get("duration_seconds", 0.0)),
            counts={key: int(value) for key, value in dict(payload.get("counts", {})).items()},
            results=results,
        )


@dataclass(slots=True)
class AuditReport:
    """A full audit run and its derived summary metrics."""

    version: str
    target: str
    host: str
    generated_at: str
    duration_seconds: float
    score: int
    grade: str
    counts: dict[str, int]
    options: dict[str, Any]
    modules: list[ModuleRun]
    results: list[CheckResult]

    def to_dict(self) -> dict[str, Any]:
        """Serialize the report."""

        return {
            "version": self.version,
            "target": self.target,
            "host": self.host,
            "generated_at": self.generated_at,
            "duration_seconds": round(self.duration_seconds, 4),
            "score": self.score,
            "grade": self.grade,
            "counts": dict(self.counts),
            "options": dict(self.options),
            "modules": [module.to_dict() for module in self.modules],
            "results": [result.to_dict() for result in self.results],
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AuditReport":
        """Rebuild a report from JSON data."""

        modules = [ModuleRun.from_dict(item) for item in payload.get("modules", [])]
        results = [CheckResult.from_dict(item) for item in payload.get("results", [])]
        return cls(
            version=str(payload.get("version", "0.0.0")),
            target=str(payload.get("target", "")),
            host=str(payload.get("host", "")),
            generated_at=str(payload.get("generated_at", "")),
            duration_seconds=float(payload.get("duration_seconds", 0.0)),
            score=int(payload.get("score", 0)),
            grade=str(payload.get("grade", "F")),
            counts={key: int(value) for key, value in dict(payload.get("counts", {})).items()},
            options=dict(payload.get("options", {})),
            modules=modules,
            results=results,
        )


@dataclass(slots=True)
class ResultChange:
    """A diff entry describing how a finding changed between two runs."""

    module: str
    name: str
    old_status: StatusType
    new_status: StatusType
    old_severity: SeverityType
    new_severity: SeverityType
    old_summary: str
    new_summary: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize the change."""

        return {
            "module": self.module,
            "name": self.name,
            "old_status": self.old_status,
            "new_status": self.new_status,
            "old_severity": self.old_severity,
            "new_severity": self.new_severity,
            "old_summary": self.old_summary,
            "new_summary": self.new_summary,
        }


@dataclass(slots=True)
class AuditDiff:
    """A diff between two audit reports."""

    target: str
    score_before: int
    score_after: int
    grade_before: str
    grade_after: str
    counts_before: dict[str, int]
    counts_after: dict[str, int]
    added: list[CheckResult]
    removed: list[CheckResult]
    changed: list[ResultChange]

    def to_dict(self) -> dict[str, Any]:
        """Serialize the diff."""

        return {
            "target": self.target,
            "score_before": self.score_before,
            "score_after": self.score_after,
            "grade_before": self.grade_before,
            "grade_after": self.grade_after,
            "counts_before": dict(self.counts_before),
            "counts_after": dict(self.counts_after),
            "added": [item.to_dict() for item in self.added],
            "removed": [item.to_dict() for item in self.removed],
            "changed": [item.to_dict() for item in self.changed],
        }


class AuditModule(ABC):
    """Base class for plugin-like audit modules."""

    slug: str = "base"
    name: str = "Base"
    description: str = "Abstract audit module."

    @abstractmethod
    async def run(self, client: Any, context: Any) -> list[CheckResult]:
        """Run the module against the target and return findings."""
