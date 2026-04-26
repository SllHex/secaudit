"""JavaScript and client-side surface checks."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import cast
from urllib.parse import urljoin, urlparse

from ..core import AuditContext, AuditModule, CheckResult, HttpClient, SeverityType, StatusType, TURNSTILE_HOST


SCRIPT_TAG_RE = re.compile(r"<script\b([^>]*?)\bsrc=[\"']([^\"']+)[\"']([^>]*)>", re.IGNORECASE)
INLINE_HANDLER_RE = re.compile(r"<[a-z][^>]+\son[a-z]+\s*=", re.IGNORECASE)
SOURCE_MAP_RE = re.compile(r"//#\s*sourceMappingURL=([^\s]+)")

SINK_PATTERNS = {
    "js-dangerous-sink-eval": (re.compile(r"\beval\s*\("), "FAIL", "high", "JavaScript bundle references eval()."),
    "js-dangerous-sink-new-function": (re.compile(r"\bnew\s+Function\s*\("), "FAIL", "high", "JavaScript bundle references new Function()."),
    "js-dangerous-sink-document-write": (re.compile(r"\bdocument\.write\s*\("), "WARN", "medium", "JavaScript bundle references document.write()."),
    "js-dangerous-sink-innerhtml": (re.compile(r"\b(?:innerHTML|outerHTML)\b"), "WARN", "medium", "JavaScript bundle references innerHTML/outerHTML sinks."),
}

SECRET_PATTERNS = {
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "GitHub token": re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "Slack token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "Stripe live key": re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b"),
    "Private key block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
}

INSECURE_URL_RE = re.compile(r"""(?P<url>(?:http://|ws://)[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+)""")
HTTPS_URL_RE = re.compile(r"""https://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+""")
POSTMESSAGE_WILDCARD_RE = re.compile(r"""\bpostMessage\s*\([^,]+,\s*["']\*["']""")
SAFE_NAMESPACE_URLS = {
    "http://www.w3.org/2000/svg",
    "http://www.w3.org/1999/xhtml",
    "http://www.w3.org/1999/xlink",
    "http://www.w3.org/2000/xmlns/",
}


def _is_same_origin(target: str, base_url: str, host: str) -> bool:
    parsed = urlparse(urljoin(base_url, target))
    base = urlparse(base_url)
    target_port = parsed.port or (443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else None)
    base_port = base.port or (443 if base.scheme == "https" else 80 if base.scheme == "http" else None)
    return (
        parsed.hostname == host
        and parsed.scheme in {"http", "https"}
        and parsed.scheme == base.scheme
        and target_port == base_port
    )


class JavaScriptModule(AuditModule):
    """Inspect JavaScript bundles and client-side leaks."""

    slug = "javascript"
    name = "JavaScript"
    description = "Client-side bundle checks for source maps, dangerous sinks, secret patterns, and insecure hardcoded endpoints."

    async def run(self, client: HttpClient, context: AuditContext) -> list[CheckResult]:
        homepage = await context.get_homepage(client)
        if homepage.status != 200:
            return [
                CheckResult(
                    name="js-skip",
                    status="INFO",
                    severity="info",
                    summary="Skipped JavaScript inspection because the homepage did not load cleanly.",
                    details=f"status={homepage.status!r}",
                    module=self.slug,
                )
            ]

        results: list[CheckResult] = []
        external_without_sri: list[str] = []
        local_scripts: list[str] = []
        app_scripts: list[str] = []

        for match in SCRIPT_TAG_RE.finditer(homepage.body):
            tag = match.group(0)
            src = match.group(2).strip()
            resolved = urljoin(context.base_url, src)
            if _is_same_origin(src, context.base_url, context.host):
                if resolved not in local_scripts:
                    local_scripts.append(resolved)
                if "/vendor/" not in urlparse(resolved).path and resolved not in app_scripts:
                    app_scripts.append(resolved)
            else:
                lower_tag = tag.lower()
                if TURNSTILE_HOST not in resolved and "integrity=" not in lower_tag:
                    external_without_sri.append(resolved)

        if external_without_sri:
            results.append(
                CheckResult(
                    name="js-external-script-sri",
                    status="WARN",
                    severity="medium",
                    summary="External scripts are referenced without Subresource Integrity.",
                    details=", ".join(sorted(external_without_sri)),
                    module=self.slug,
                )
            )
        else:
            results.append(
                CheckResult(
                    name="js-external-script-sri",
                    status="PASS",
                    severity="info",
                    summary="No unexpected external scripts without SRI were detected.",
                    module=self.slug,
                )
            )

        inline_handlers = INLINE_HANDLER_RE.findall(homepage.body)
        if inline_handlers:
            results.append(
                CheckResult(
                    name="js-inline-event-handlers",
                    status="WARN",
                    severity="medium",
                    summary="Inline HTML event handlers were detected.",
                    details=f"count={len(inline_handlers)}",
                    module=self.slug,
                )
            )
        else:
            results.append(
                CheckResult(
                    name="js-inline-event-handlers",
                    status="PASS",
                    severity="info",
                    summary="No inline HTML event handlers were detected on the homepage.",
                    module=self.slug,
                )
            )

        if not local_scripts:
            results.append(
                CheckResult(
                    name="js-local-assets",
                    status="INFO",
                    severity="info",
                    summary="No same-origin JavaScript assets were linked from the homepage.",
                    module=self.slug,
                )
            )
            return results

        results.append(
            CheckResult(
                name="js-local-assets",
                status="PASS",
                severity="info",
                summary="Same-origin JavaScript assets were discovered.",
                details=f"total={len(local_scripts)} app={len(app_scripts)}",
                module=self.slug,
            )
        )

        exposed_maps: list[str] = []
        broken_assets: list[str] = []
        sink_hits: dict[str, list[str]] = defaultdict(list)
        secret_hits: list[str] = []
        insecure_urls: list[str] = []
        third_party_origins: set[str] = set()
        wildcard_postmessages: list[str] = []

        for script_url in local_scripts:
            response = await client.request(script_url)
            if response.status != 200:
                broken_assets.append(f"{script_url} status={response.status!r}")
                continue

            for map_candidate in self._map_candidates(script_url, response.body):
                probe = await client.request(map_candidate)
                if probe.status == 200:
                    exposed_maps.append(map_candidate)

            if script_url not in app_scripts:
                continue

            body = response.body
            for result_name, (pattern, _status, _severity, _summary) in SINK_PATTERNS.items():
                if pattern.search(body):
                    sink_hits[result_name].append(script_url)

            if POSTMESSAGE_WILDCARD_RE.search(body):
                wildcard_postmessages.append(script_url)

            for label, pattern in SECRET_PATTERNS.items():
                if pattern.search(body):
                    secret_hits.append(f"{label} in {script_url}")

            for match in INSECURE_URL_RE.finditer(body):
                candidate = match.group("url").rstrip('\'"),;')
                if candidate in SAFE_NAMESPACE_URLS:
                    continue
                insecure_urls.append(candidate)

            for match in HTTPS_URL_RE.finditer(body):
                parsed = urlparse(match.group(0))
                origin = f"{parsed.scheme}://{parsed.netloc}"
                if parsed.hostname not in {context.host, None} and not origin.startswith(TURNSTILE_HOST):
                    third_party_origins.add(origin)

        if broken_assets:
            results.append(
                CheckResult(
                    name="js-broken-assets",
                    status="WARN",
                    severity="medium",
                    summary="Referenced same-origin JavaScript assets failed to load cleanly.",
                    details=", ".join(broken_assets[:8]),
                    module=self.slug,
                )
            )
        else:
            results.append(
                CheckResult(
                    name="js-broken-assets",
                    status="PASS",
                    severity="info",
                    summary="Referenced same-origin JavaScript assets loaded cleanly.",
                    module=self.slug,
                )
            )

        if exposed_maps:
            results.append(
                CheckResult(
                    name="js-source-maps",
                    status="FAIL",
                    severity="high",
                    summary="Public source maps are exposed for JavaScript assets.",
                    details=", ".join(sorted(set(exposed_maps))[:10]),
                    module=self.slug,
                )
            )
        else:
            results.append(
                CheckResult(
                    name="js-source-maps",
                    status="PASS",
                    severity="info",
                    summary="No exposed JavaScript source maps were detected.",
                    module=self.slug,
                )
            )

        for result_name, (_pattern, status, severity, summary) in SINK_PATTERNS.items():
            if sink_hits[result_name]:
                results.append(
                    CheckResult(
                        name=result_name,
                        status=cast(StatusType, status),
                        severity=cast(SeverityType, severity),
                        summary=summary,
                        details=", ".join(sorted(set(sink_hits[result_name]))[:10]),
                        module=self.slug,
                    )
                )
            else:
                results.append(
                    CheckResult(
                        name=result_name,
                        status="PASS",
                        severity="info",
                        summary=f"No matches found for {result_name}.",
                        module=self.slug,
                    )
                )

        if wildcard_postmessages:
            results.append(
                CheckResult(
                    name="js-postmessage-wildcard",
                    status="FAIL",
                    severity="high",
                    summary="JavaScript bundle uses postMessage with a wildcard target origin.",
                    details=", ".join(sorted(set(wildcard_postmessages))),
                    module=self.slug,
                )
            )
        else:
            results.append(
                CheckResult(
                    name="js-postmessage-wildcard",
                    status="PASS",
                    severity="info",
                    summary="No postMessage wildcard target origin usage was detected.",
                    module=self.slug,
                )
            )

        if secret_hits:
            results.append(
                CheckResult(
                    name="js-secret-patterns",
                    status="FAIL",
                    severity="high",
                    summary="High-signal secret patterns were detected in first-party JavaScript.",
                    details=", ".join(sorted(set(secret_hits))[:10]),
                    module=self.slug,
                )
            )
        else:
            results.append(
                CheckResult(
                    name="js-secret-patterns",
                    status="PASS",
                    severity="info",
                    summary="No high-signal secret patterns were detected in first-party JavaScript.",
                    module=self.slug,
                )
            )

        if insecure_urls:
            results.append(
                CheckResult(
                    name="js-insecure-endpoints",
                    status="FAIL",
                    severity="high",
                    summary="JavaScript contains insecure hardcoded http:// or ws:// URLs.",
                    details=", ".join(sorted(set(insecure_urls))[:10]),
                    module=self.slug,
                )
            )
        else:
            results.append(
                CheckResult(
                    name="js-insecure-endpoints",
                    status="PASS",
                    severity="info",
                    summary="No insecure hardcoded http:// or ws:// URLs were detected in first-party JavaScript.",
                    module=self.slug,
                )
            )

        if third_party_origins:
            results.append(
                CheckResult(
                    name="js-third-party-origins",
                    status="WARN",
                    severity="low",
                    summary="First-party JavaScript references third-party HTTPS origins.",
                    details=", ".join(sorted(third_party_origins)),
                    module=self.slug,
                )
            )
        else:
            results.append(
                CheckResult(
                    name="js-third-party-origins",
                    status="PASS",
                    severity="info",
                    summary="No unexpected third-party HTTPS origins were found in first-party JavaScript.",
                    module=self.slug,
                )
            )

        return results

    @staticmethod
    def _map_candidates(script_url: str, body: str) -> list[str]:
        candidates = [f"{script_url}.map"]
        match = SOURCE_MAP_RE.search(body)
        if match:
            candidates.append(urljoin(script_url, match.group(1).strip()))
        seen: list[str] = []
        for candidate in candidates:
            if candidate not in seen:
                seen.append(candidate)
        return seen
