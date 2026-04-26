"""Audit module registry for SecAudit."""

from __future__ import annotations

from .api import APIModule
from .cookies import CookiesModule
from .csp import CSPModule
from .dns import DNSModule
from .email_dns import EmailDNSModule
from .headers import HeadersModule
from .javascript import JavaScriptModule
from .proxy_cache import ProxyCacheModule
from .static import StaticModule
from .tls import TLSModule

MODULES = [
    DNSModule(),
    TLSModule(),
    HeadersModule(),
    CSPModule(),
    CookiesModule(),
    APIModule(),
    StaticModule(),
    JavaScriptModule(),
    EmailDNSModule(),
    ProxyCacheModule(),
]

MODULE_REGISTRY = {module.slug: module for module in MODULES}


def resolve_modules(selection: str | None = None) -> list:
    """Backward-compatible module resolution from a comma-separated selection."""

    if not selection:
        return list(MODULES)
    from ..registry import parse_module_csv

    return [MODULE_REGISTRY[slug] for slug in parse_module_csv(selection)]

__all__ = [
    "MODULES",
    "MODULE_REGISTRY",
    "resolve_modules",
]
