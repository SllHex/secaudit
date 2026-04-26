"""Proxy and cache poisoning indicator checks."""

from __future__ import annotations

import re

from ..core import AuditContext, AuditModule, CheckResult, HttpClient


MARKER = "secaudit-probe.invalid"


def _response_reflects_marker(response_body: str, marker: str) -> bool:
    return marker.lower() in response_body.lower()


def _extract_canonical_targets(body: str) -> list[str]:
    patterns = [
        r'<link\s+rel="canonical"\s+href="([^"]+)"',
        r'<meta\s+property="og:url"\s+content="([^"]+)"',
    ]
    targets: list[str] = []
    for pattern in patterns:
        targets.extend(match.group(1).strip() for match in re.finditer(pattern, body, re.IGNORECASE))
    return targets


class ProxyCacheModule(AuditModule):
    """Check for proxy header reflection and weak cache/proxy handling indicators."""

    slug = "proxy_cache"
    name = "Proxy/Cache"
    description = "Safe probes for Host/X-Forwarded-* reflection, redirect poisoning indicators, and unsafe TRACE support."

    async def run(self, client: HttpClient, context: AuditContext) -> list[CheckResult]:
        results: list[CheckResult] = []

        trace_response = await client.request(context.url("/"), method="TRACE")
        if trace_response.status in {403, 404, 405, 501}:
            results.append(
                CheckResult(
                    name="trace-method",
                    status="PASS",
                    severity="info",
                    summary="TRACE is not enabled on the audited origin.",
                    details=f"status={trace_response.status}",
                    module=self.slug,
                )
            )
        else:
            results.append(
                CheckResult(
                    name="trace-method",
                    status="WARN",
                    severity="medium",
                    summary="TRACE returned an unexpected status and should be reviewed.",
                    details=f"status={trace_response.status!r}",
                    module=self.slug,
                )
            )

        poisoned_http = await client.request(context.insecure_url("/"), headers={"Host": MARKER}, allow_redirects=False)
        poisoned_location = poisoned_http.headers.get("location", "")
        if MARKER in poisoned_location:
            results.append(
                CheckResult(
                    name="host-header-http-redirect",
                    status="FAIL",
                    severity="high",
                    summary="HTTP redirect appears influenced by the Host header.",
                    details=poisoned_location,
                    module=self.slug,
                )
            )
        else:
            results.append(
                CheckResult(
                    name="host-header-http-redirect",
                    status="PASS",
                    severity="info",
                    summary="HTTP redirect did not reflect the injected Host header.",
                    details=poisoned_location or f"status={poisoned_http.status!r}",
                    module=self.slug,
                )
            )

        poisoned_https = await client.request(context.url("/"), headers={"Host": MARKER}, allow_redirects=False)
        canonical_targets = _extract_canonical_targets(poisoned_https.body)
        reflection_targets = canonical_targets + [poisoned_https.headers.get("location", ""), poisoned_https.body[:3000]]
        if any(MARKER in target for target in reflection_targets if target):
            results.append(
                CheckResult(
                    name="host-header-reflection",
                    status="FAIL",
                    severity="high",
                    summary="The HTTPS response appears to reflect the injected Host header.",
                    details=", ".join(target for target in canonical_targets if MARKER in target) or poisoned_https.headers.get("location", ""),
                    module=self.slug,
                )
            )
        else:
            results.append(
                CheckResult(
                    name="host-header-reflection",
                    status="PASS",
                    severity="info",
                    summary="The HTTPS response did not reflect the injected Host header.",
                    module=self.slug,
                )
            )

        forwarded_host = await client.request(context.url("/"), headers={"X-Forwarded-Host": MARKER}, allow_redirects=False)
        forwarded_targets = _extract_canonical_targets(forwarded_host.body) + [forwarded_host.headers.get("location", ""), forwarded_host.body[:3000]]
        if any(MARKER in target for target in forwarded_targets if target):
            results.append(
                CheckResult(
                    name="x-forwarded-host-reflection",
                    status="FAIL",
                    severity="high",
                    summary="The response appears to trust and reflect X-Forwarded-Host.",
                    details=forwarded_host.headers.get("location", "") or ", ".join(_extract_canonical_targets(forwarded_host.body)),
                    module=self.slug,
                )
            )
        else:
            results.append(
                CheckResult(
                    name="x-forwarded-host-reflection",
                    status="PASS",
                    severity="info",
                    summary="The response did not reflect the injected X-Forwarded-Host value.",
                    module=self.slug,
                )
            )

        forwarded_proto = await client.request(context.url("/"), headers={"X-Forwarded-Proto": "http"}, allow_redirects=False)
        proto_targets = _extract_canonical_targets(forwarded_proto.body)
        downgraded = any(target.startswith("http://") for target in proto_targets) or forwarded_proto.headers.get("location", "").startswith("http://")
        if downgraded:
            results.append(
                CheckResult(
                    name="x-forwarded-proto-downgrade",
                    status="FAIL",
                    severity="medium",
                    summary="The response appears to trust X-Forwarded-Proto and downgrade generated URLs.",
                    details=", ".join(proto_targets) or forwarded_proto.headers.get("location", ""),
                    module=self.slug,
                )
            )
        else:
            results.append(
                CheckResult(
                    name="x-forwarded-proto-downgrade",
                    status="PASS",
                    severity="info",
                    summary="Generated URLs did not downgrade when X-Forwarded-Proto was set to http.",
                    module=self.slug,
                )
            )

        homepage = await context.get_homepage(client)
        if homepage.headers.get("cache-control", "").lower().find("no-store") != -1:
            results.append(
                CheckResult(
                    name="dynamic-cache-policy",
                    status="PASS",
                    severity="info",
                    summary="Homepage is marked no-store, reducing cache-poisoning risk on the main document.",
                    details=homepage.headers.get("cache-control", ""),
                    module=self.slug,
                )
            )
        else:
            results.append(
                CheckResult(
                    name="dynamic-cache-policy",
                    status="WARN",
                    severity="medium",
                    summary="Homepage is cacheable; reflected header behavior should be reviewed carefully.",
                    details=homepage.headers.get("cache-control", "") or "<missing>",
                    module=self.slug,
                )
            )

        return results
