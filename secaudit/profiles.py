"""Scan profile definitions for SecAudit."""

from __future__ import annotations

from dataclasses import dataclass

from .errors import UnknownModuleError


@dataclass(frozen=True, slots=True)
class ProfileSpec:
    """Describes a named scan profile."""

    slug: str
    title: str
    description: str
    modules: tuple[str, ...]


PROFILES: tuple[ProfileSpec, ...] = (
    ProfileSpec(
        slug="quick",
        title="Quick",
        description="Fast baseline checks for transport security and core headers.",
        modules=("dns", "tls", "headers"),
    ),
    ProfileSpec(
        slug="standard",
        title="Standard",
        description="Recommended default profile for recurring external posture checks.",
        modules=("dns", "tls", "headers", "csp", "cookies", "api", "static"),
    ),
    ProfileSpec(
        slug="deep",
        title="Deep",
        description="Expanded safe audit with client-side, email/DNS, and edge/proxy checks.",
        modules=("dns", "tls", "headers", "csp", "cookies", "api", "static", "javascript", "email_dns", "proxy_cache"),
    ),
)

PROFILE_REGISTRY = {profile.slug: profile for profile in PROFILES}


def get_profile(name: str) -> ProfileSpec:
    """Return a profile by slug."""

    profile = PROFILE_REGISTRY.get(name.strip().lower())
    if not profile:
        available = ", ".join(sorted(PROFILE_REGISTRY))
        raise UnknownModuleError(f"Unknown profile '{name}'. Available profiles: {available}")
    return profile
