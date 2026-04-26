"""Audit context normalization and shared run state."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from typing import Any
from urllib.parse import urljoin, urlparse

from .errors import InvalidTargetError

DEFAULT_TIMEOUT = 10
TURNSTILE_HOST = "https://challenges.cloudflare.com"
CSRF_COOKIE_NAME = "contact_csrf"
EXPECTED_ERROR_STATUSES = {403, 404}


def normalize_whitespace(value: str) -> str:
    """Collapse internal whitespace to produce compact evidence strings."""

    return " ".join(value.split())


def parse_cookie_headers(raw_values: str | list[str]) -> SimpleCookie:
    """Parse one or more Set-Cookie header values into a cookie jar."""

    values = [raw_values] if isinstance(raw_values, str) else list(raw_values)
    cookie = SimpleCookie()
    for raw_value in values:
        if not raw_value:
            continue
        try:
            cookie.load(raw_value)
        except Exception:  # noqa: BLE001
            continue
    return cookie


def _format_netloc(host: str, port: int | None) -> str:
    """Format a hostname and optional port into a URL netloc."""

    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{host}:{port}" if port is not None else host


def _normalize_port_for_scheme(input_scheme: str, port: int | None, *, secure: bool) -> int | None:
    """Map a user-supplied port to the secure or insecure audit surface."""

    if port is None:
        return None
    if secure and input_scheme == "http" and port == 80:
        return None
    if not secure and input_scheme == "https" and port == 443:
        return None
    if secure and input_scheme == "https" and port == 443:
        return None
    if not secure and input_scheme == "http" and port == 80:
        return None
    return port


@dataclass(slots=True)
class AuditContext:
    """Runtime configuration and shared state for a single audit run."""

    raw_url: str
    timeout: int = DEFAULT_TIMEOUT
    check_www: bool = False
    test_rate_limit: bool = False
    full: bool = False
    profile: str = "standard"
    user_agent: str = ""
    selected_modules: tuple[str, ...] = ()
    input_url: str = field(init=False)
    input_scheme: str = field(init=False)
    base_url: str = field(init=False)
    origin: str = field(init=False)
    host: str = field(init=False)
    port: int = field(init=False)
    scheme: str = field(init=False)
    netloc: str = field(init=False)
    http_netloc: str = field(init=False)
    homepage: Any | None = field(default=None, init=False)
    http_root: Any | None = field(default=None, init=False)
    _hp_lock: Any = field(default=None, init=False, repr=False, compare=False, hash=False)
    _hr_lock: Any = field(default=None, init=False, repr=False, compare=False, hash=False)

    def __post_init__(self) -> None:
        """Normalize the target URL into the secure audit surface."""

        parsed = urlparse(self.raw_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise InvalidTargetError("Use a full URL such as https://example.com")
        self.input_url = f"{parsed.scheme}://{parsed.netloc}"
        self.input_scheme = parsed.scheme
        self.host = parsed.hostname or ""
        if not self.host:
            raise InvalidTargetError("Could not determine a hostname from the supplied URL.")
        secure_port = _normalize_port_for_scheme(parsed.scheme, parsed.port, secure=True)
        insecure_port = _normalize_port_for_scheme(parsed.scheme, parsed.port, secure=False)
        self.netloc = _format_netloc(self.host, secure_port)
        self.http_netloc = _format_netloc(self.host, insecure_port)
        self.base_url = f"https://{self.netloc}"
        self.origin = self.base_url
        self.port = secure_port or 443
        self.scheme = "https"
        self._hp_lock = asyncio.Lock()
        self._hr_lock = asyncio.Lock()

    def url(self, path: str = "/") -> str:
        """Build a URL relative to the canonical base URL."""

        return urljoin(self.base_url, path)

    def insecure_url(self, path: str = "/") -> str:
        """Build an HTTP URL using the same network location."""

        clean_path = path if path.startswith("/") else f"/{path}"
        return urljoin(f"http://{self.http_netloc}", clean_path)

    async def get_homepage(self, client: Any) -> Any:
        """Fetch and memoize the homepage response (async-safe for parallel modules)."""

        async with self._hp_lock:
            if self.homepage is None:
                self.homepage = await client.request(self.url("/"))
        return self.homepage

    async def get_http_root(self, client: Any) -> Any:
        """Fetch and memoize the insecure root response (async-safe for parallel modules)."""

        async with self._hr_lock:
            if self.http_root is None:
                self.http_root = await client.request(self.insecure_url("/"))
        return self.http_root

    def extract_form_session(self) -> tuple[str, str]:
        """Extract CSRF material from the memoized homepage."""

        if self.homepage is None:
            return "", ""
        body = self.homepage.body
        token = ""
        match = re.search(
            r'<meta\s+name="contact-csrf-token"\s+content="([^"]*)"',
            body,
            re.IGNORECASE,
        )
        if match:
            token = match.group(1).strip()
        cookies = parse_cookie_headers(self.homepage.header_values.get("set-cookie", []))
        morsel = cookies.get(CSRF_COOKIE_NAME)
        csrf_cookie = morsel.value if morsel is not None else ""
        return token, csrf_cookie

    def options_dict(self) -> dict[str, Any]:
        """Serialize runtime options for reporting."""

        return {
            "timeout": self.timeout,
            "check_www": self.check_www,
            "test_rate_limit": self.test_rate_limit,
            "full": self.full,
            "profile": self.profile,
            "selected_modules": list(self.selected_modules),
            "input_url": self.input_url,
            "audit_url": self.base_url,
            "user_agent": self.user_agent,
        }
