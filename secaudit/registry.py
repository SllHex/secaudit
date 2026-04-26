"""Module registry and contributor-facing metadata."""

from __future__ import annotations

from dataclasses import dataclass, field

from .errors import UnknownModuleError
from .models import AuditModule
from .modules.api import APIModule
from .modules.cookies import CookiesModule
from .modules.csp import CSPModule
from .modules.dns import DNSModule
from .modules.email_dns import EmailDNSModule
from .modules.headers import HeadersModule
from .modules.javascript import JavaScriptModule
from .modules.proxy_cache import ProxyCacheModule
from .modules.static import StaticModule
from .modules.tls import TLSModule
from .profiles import PROFILE_REGISTRY, get_profile


@dataclass(frozen=True, slots=True)
class ModuleSpec:
    """Describes a published audit module and its CLI metadata."""

    slug: str
    title: str
    category: str
    module: AuditModule
    aliases: tuple[str, ...] = ()
    purpose: str = ""
    risks: tuple[str, ...] = ()
    guidance: str = ""
    remediation: str = ""
    common_findings: tuple[str, ...] = ()
    included_in: tuple[str, ...] = field(default_factory=tuple)

    @property
    def name(self) -> str:
        return self.module.name

    @property
    def description(self) -> str:
        return self.module.description


MODULE_SPECS: tuple[ModuleSpec, ...] = (
    ModuleSpec(
        slug="dns",
        title="DNS",
        category="Core Checks",
        module=DNSModule(),
        purpose="Validates apex reachability, IPv6 availability, and the optional www host.",
        risks=("DNS drift", "broken aliases", "IPv6 blind spots"),
        guidance="Use this early to confirm the target resolves cleanly before running deeper HTTP checks.",
        remediation="Fix broken A/AAAA/CNAME records, verify authoritative DNS, and align public hostnames with the intended surface.",
        common_findings=("missing www alias", "no IPv6", "hostname does not resolve"),
        included_in=("quick", "standard", "deep"),
    ),
    ModuleSpec(
        slug="tls",
        title="TLS / Certificate",
        category="Core Checks",
        module=TLSModule(),
        aliases=("https",),
        purpose="Validates HTTPS, redirects, certificate health, cipher quality, and legacy TLS exposure.",
        risks=("outdated TLS", "bad redirects", "weak certificates"),
        guidance="Treat TLS findings as high-priority because they affect every request to the application.",
        remediation="Enforce HTTPS redirects, disable legacy TLS versions, renew weak/expired certificates, and prefer modern ciphers.",
        common_findings=("legacy TLS enabled", "bad redirect chain", "certificate expiry issues"),
        included_in=("quick", "standard", "deep"),
    ),
    ModuleSpec(
        slug="headers",
        title="Security Headers",
        category="Web App Checks",
        module=HeadersModule(),
        aliases=("security_headers",),
        purpose="Checks response header hardening such as HSTS, XFO, COOP, and CORP.",
        risks=("missing browser defenses", "unsafe caching behavior"),
        guidance="Use this to verify browser-side security posture and error-page consistency.",
        remediation="Add missing headers at the edge or application layer and ensure error responses inherit the same baseline protection.",
        common_findings=("missing HSTS", "missing nosniff", "404 responses missing headers"),
        included_in=("quick", "standard", "deep"),
    ),
    ModuleSpec(
        slug="csp",
        title="Content Security Policy",
        category="Web App Checks",
        module=CSPModule(),
        purpose="Analyzes CSP quality, HTML markers, and external script exposure.",
        risks=("XSS blast radius", "weak content policy"),
        guidance="Pair this with the JavaScript module when tightening frontend hardening and third-party script policy.",
        remediation="Tighten script/style sources, remove unsafe-* allowances where feasible, and reduce inline/script attribute usage.",
        common_findings=("unsafe-inline present", "unsafe-eval present", "missing frame-ancestors"),
        included_in=("standard", "deep"),
    ),
    ModuleSpec(
        slug="cookies",
        title="Cookies",
        category="Web App Checks",
        module=CookiesModule(),
        purpose="Checks cookie flags on security-sensitive cookies.",
        risks=("session exposure", "weak CSRF boundaries"),
        guidance="Useful for validating session/CSRF cookie flags after auth or form changes.",
        remediation="Set Secure, HttpOnly, SameSite, and constrained Path/Domain values on security-sensitive cookies.",
        common_findings=("missing SameSite", "missing HttpOnly", "insecure cookie transport"),
        included_in=("standard", "deep"),
    ),
    ModuleSpec(
        slug="api",
        title="API / CSRF",
        category="API Checks",
        module=APIModule(),
        aliases=("cors", "csrf"),
        purpose="Exercises defensive API behavior around CORS, CSRF, anti-bot gates, and rate limiting.",
        risks=("cross-site abuse", "unauthenticated form submission", "weak preflight policy"),
        guidance="Run this after contact form or public API changes to catch cross-origin and CSRF regressions.",
        remediation="Require same-origin requests, validate CSRF material, lock preflight behavior down, and enforce anti-bot/rate-limit gates.",
        common_findings=("cross-origin POST allowed", "missing CSRF rejection", "weak preflight policy"),
        included_in=("standard", "deep"),
    ),
    ModuleSpec(
        slug="static",
        title="Static Surface",
        category="Web App Checks",
        module=StaticModule(),
        purpose="Checks for static file exposure, traversal escapes, and asset hygiene.",
        risks=("source exposure", "directory traversal", "public secrets"),
        guidance="A strong default module for production builds because it catches accidental public files quickly.",
        remediation="Restrict public roots, disable listings, block traversal, and keep internal files outside the served tree.",
        common_findings=("source file exposure", "directory traversal", "directory listing"),
        included_in=("standard", "deep"),
    ),
    ModuleSpec(
        slug="javascript",
        title="JavaScript Inspection",
        category="Advanced Checks",
        module=JavaScriptModule(),
        aliases=("js",),
        purpose="Inspects client-side bundles for source maps, dangerous sinks, hardcoded endpoints, and leaks.",
        risks=("frontend secret leaks", "unsafe DOM sinks", "insecure endpoints"),
        guidance="Best used in deep scans or before release when frontend bundles and asset pipelines change.",
        remediation="Strip source maps from production when not needed, review unsafe sinks, and remove insecure hardcoded endpoints from bundles.",
        common_findings=("public source maps", "eval/new Function usage", "hardcoded insecure URLs"),
        included_in=("deep",),
    ),
    ModuleSpec(
        slug="email_dns",
        title="Email / DNS",
        category="DNS / Email Checks",
        module=EmailDNSModule(),
        aliases=("email", "mail"),
        purpose="Checks MX, SPF, DMARC, CAA, and security.txt disclosure guidance.",
        risks=("mail spoofing", "missing disclosure path", "weak certificate issuance policy"),
        guidance="Most relevant for domains that send or receive mail or publish a security contact path.",
        remediation="Publish SPF/DMARC where mail is used, add CAA where appropriate, and expose a valid security.txt contact channel.",
        common_findings=("missing SPF", "missing DMARC", "missing security.txt"),
        included_in=("deep",),
    ),
    ModuleSpec(
        slug="proxy_cache",
        title="Proxy / Cache",
        category="Advanced Checks",
        module=ProxyCacheModule(),
        aliases=("proxy", "cache"),
        purpose="Looks for TRACE, reflection, and poisoning indicators at the proxy/cache layer.",
        risks=("host header abuse", "cache poisoning", "proxy confusion"),
        guidance="Run this when the application sits behind CDNs, reverse proxies, or custom edge routing.",
        remediation="Harden proxy normalization, reject unsafe override headers, disable TRACE, and review cache-key behavior.",
        common_findings=("TRACE enabled", "host reflection", "cache poisoning indicators"),
        included_in=("deep",),
    ),
)

MODULE_REGISTRY = {spec.slug: spec.module for spec in MODULE_SPECS}
MODULE_SPEC_REGISTRY = {spec.slug: spec for spec in MODULE_SPECS}
MODULE_ALIASES = {
    alias: spec.slug
    for spec in MODULE_SPECS
    for alias in (spec.slug, *spec.aliases)
}


def normalize_module_name(name: str) -> str:
    """Resolve a module slug or alias to its canonical slug."""

    slug = MODULE_ALIASES.get(name.strip().lower())
    if not slug:
        available = ", ".join(sorted(MODULE_REGISTRY))
        raise UnknownModuleError(f"Unknown module '{name}'. Available modules: {available}")
    return slug


def parse_module_csv(raw: str | None) -> tuple[str, ...]:
    """Parse a comma-separated module selection into canonical slugs."""

    if not raw:
        return ()
    resolved: list[str] = []
    for part in raw.split(","):
        if not part.strip():
            continue
        slug = normalize_module_name(part)
        if slug not in resolved:
            resolved.append(slug)
    return tuple(resolved)


def resolve_modules(selection: str | None = None) -> list[AuditModule]:
    """Backward-compatible module resolution from a comma-separated selection."""

    if not selection:
        return [spec.module for spec in MODULE_SPECS]
    return [MODULE_SPEC_REGISTRY[slug].module for slug in parse_module_csv(selection)]


def resolve_module_plan(
    *,
    profile: str = "standard",
    only: tuple[str, ...] = (),
    skip: tuple[str, ...] = (),
) -> tuple[AuditModule, ...]:
    """Resolve the final ordered module plan from a profile plus only/skip selectors."""

    if profile not in PROFILE_REGISTRY:
        available = ", ".join(sorted(PROFILE_REGISTRY))
        raise UnknownModuleError(f"Unknown profile '{profile}'. Available profiles: {available}")
    base = list(only or get_profile(profile).modules)
    if skip:
        blocked = set(skip)
        base = [slug for slug in base if slug not in blocked]
    return tuple(MODULE_SPEC_REGISTRY[slug].module for slug in base)


def get_module_spec(name: str) -> ModuleSpec:
    """Return metadata for a canonical slug or alias."""

    return MODULE_SPEC_REGISTRY[normalize_module_name(name)]


def grouped_module_specs() -> dict[str, list[ModuleSpec]]:
    """Return module specs grouped by category."""

    groups: dict[str, list[ModuleSpec]] = {}
    for spec in MODULE_SPECS:
        groups.setdefault(spec.category, []).append(spec)
    return groups
