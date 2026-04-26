from __future__ import annotations

import pytest

from secaudit.context import AuditContext
from secaudit.errors import InvalidTargetError


def test_audit_context_canonicalizes_to_https() -> None:
    context = AuditContext(raw_url="http://example.com")

    assert context.input_url == "http://example.com"
    assert context.base_url == "https://example.com"
    assert context.origin == "https://example.com"
    assert context.insecure_url("/") == "http://example.com/"


def test_audit_context_rejects_invalid_target() -> None:
    with pytest.raises(InvalidTargetError):
        AuditContext(raw_url="example.com")
