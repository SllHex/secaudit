"""Async HTTP and TLS helpers used by audit modules."""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, cast

import aiohttp

from . import __version__
from .context import DEFAULT_TIMEOUT
from .models import HttpResponse, TLSDetails

USER_AGENT = f"secaudit/{__version__}"


def utc_now() -> datetime:
    """Return the current UTC time."""

    return datetime.now(timezone.utc)


def isoformat_utc(moment: datetime | None = None) -> str:
    """Serialize a UTC-aware timestamp to ISO-8601."""

    return (moment or utc_now()).astimezone(timezone.utc).isoformat()


def parse_certificate_expiry(not_after: str) -> int:
    """Return days until certificate expiry, or -9999 on parse failure."""

    try:
        expires_at = parsedate_to_datetime(not_after)
    except Exception:  # noqa: BLE001
        return -9999
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return int((expires_at - utc_now()).total_seconds() // 86400)


def _blocking_fetch_tls_details(host: str, port: int, timeout: int) -> TLSDetails:
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as raw_sock:
        with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            cert = tls_sock.getpeercert()
            cipher = tls_sock.cipher() or ("unknown", "", 0)
            return TLSDetails(
                cert=cast(dict[str, Any], cert or {}),
                tls_version=tls_sock.version() or "unknown",
                cipher_name=str(cipher[0]),
                cipher_bits=int(cipher[2]),
            )


def _blocking_probe_tls_version(host: str, port: int, version_name: str, timeout: int) -> tuple[bool, str]:
    if not hasattr(ssl, "TLSVersion"):
        return False, "TLSVersion probing is not supported by this Python build."

    version = getattr(ssl.TLSVersion, version_name, None)
    if version is None:
        return False, f"{version_name} is not available in this Python/OpenSSL build."

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.minimum_version = version
        context.maximum_version = version
    except ValueError as exc:
        return False, str(exc)

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                return True, tls_sock.version() or version_name
    except ssl.SSLError as exc:
        return False, str(exc)
    except OSError as exc:
        return False, str(exc)


class HttpClient:
    """Async HTTP client with TLS and DNS helpers for audit modules."""

    def __init__(self, timeout: int = DEFAULT_TIMEOUT, user_agent: str = USER_AGENT) -> None:
        self.timeout = timeout
        self.user_agent = user_agent or USER_AGENT
        self._session: aiohttp.ClientSession | None = None

    async def __aenter__(self) -> "HttpClient":
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self._session = aiohttp.ClientSession(
            timeout=timeout,
            cookie_jar=aiohttp.DummyCookieJar(),
            headers={"User-Agent": self.user_agent},
        )
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

    async def request(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        allow_redirects: bool = False,
    ) -> HttpResponse:
        """Perform an HTTP request and normalize the response."""

        if self._session is None:
            raise RuntimeError("HttpClient must be used as an async context manager.")
        request_headers = dict(headers or {})
        try:
            async with self._session.request(
                method,
                url,
                headers=request_headers,
                data=body,
                allow_redirects=allow_redirects,
            ) as response:
                text = await response.text(errors="replace")
                header_values: dict[str, list[str]] = {}
                for header_name in response.headers.keys():
                    lower_name = header_name.lower()
                    header_values[lower_name] = response.headers.getall(header_name, [])
                header_map = {key: values[-1] for key, values in header_values.items()}
                return HttpResponse(
                    url=str(response.url),
                    status=response.status,
                    headers=header_map,
                    body=text,
                    header_values=header_values,
                )
        except Exception as exc:  # noqa: BLE001
            return HttpResponse(url=url, status=None, headers={}, body="", error=str(exc))

    async def resolve_host(self, host: str) -> tuple[set[str], set[str]]:
        """Resolve A and AAAA records for a hostname."""

        ipv4: set[str] = set()
        ipv6: set[str] = set()
        loop = asyncio.get_running_loop()
        try:
            records = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror:
            return ipv4, ipv6
        for family, _, _, _, sockaddr in records:
            if family == socket.AF_INET:
                ipv4.add(sockaddr[0])
            elif family == socket.AF_INET6:
                ipv6.add(sockaddr[0])
        return ipv4, ipv6

    async def fetch_tls_details(self, host: str, port: int = 443) -> TLSDetails:
        """Perform a verified TLS handshake and return the peer details."""

        return await asyncio.to_thread(_blocking_fetch_tls_details, host, port, self.timeout)

    async def probe_tls_version(self, host: str, version_name: str, port: int = 443) -> tuple[bool, str]:
        """Probe support for a specific TLS version."""

        return await asyncio.to_thread(_blocking_probe_tls_version, host, port, version_name, self.timeout)
