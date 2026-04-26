"""DNS reachability checks."""

from __future__ import annotations

from ..core import AuditContext, AuditModule, CheckResult, HttpClient


class DNSModule(AuditModule):
    """Validate apex and optional www DNS reachability."""

    slug = "dns"
    name = "DNS"
    description = "DNS resolution for the apex host and optional www alias."

    async def run(self, client: HttpClient, context: AuditContext) -> list[CheckResult]:
        results: list[CheckResult] = []
        if not context.host:
            return [
                CheckResult(
                    name="dns-apex",
                    status="FAIL",
                    severity="high",
                    summary="Could not determine hostname for DNS checks.",
                    module=self.slug,
                )
            ]

        ipv4, ipv6 = await client.resolve_host(context.host)
        if not ipv4 and not ipv6:
            results.append(
                CheckResult(
                    name="dns-apex",
                    status="FAIL",
                    severity="critical",
                    summary="Hostname does not resolve in DNS.",
                    details=context.host,
                    module=self.slug,
                )
            )
            return results

        details = []
        if ipv4:
            details.append(f"IPv4={','.join(sorted(ipv4))}")
        if ipv6:
            details.append(f"IPv6={','.join(sorted(ipv6))}")
        results.append(
            CheckResult(
                name="dns-apex",
                status="PASS",
                severity="info",
                summary="Hostname resolves in DNS.",
                details=" | ".join(details),
                module=self.slug,
            )
        )
        if ipv6:
            results.append(
                CheckResult(
                    name="dns-ipv6",
                    status="PASS",
                    severity="info",
                    summary="AAAA record detected for the apex host.",
                    module=self.slug,
                )
            )
        else:
            results.append(
                CheckResult(
                    name="dns-ipv6",
                    status="WARN",
                    severity="low",
                    summary="No AAAA record detected for the apex host.",
                    module=self.slug,
                )
            )

        if context.check_www:
            www_host = f"www.{context.host}"
            www_ipv4, www_ipv6 = await client.resolve_host(www_host)
            if not www_ipv4 and not www_ipv6:
                results.append(
                    CheckResult(
                        name="www-dns",
                        status="WARN",
                        severity="low",
                        summary="www host does not resolve.",
                        details=www_host,
                        module=self.slug,
                    )
                )
                return results

            www_details = []
            if www_ipv4:
                www_details.append(f"IPv4={','.join(sorted(www_ipv4))}")
            if www_ipv6:
                www_details.append(f"IPv6={','.join(sorted(www_ipv6))}")
            response = await client.request(f"https://{www_host}/")
            if response.status in {200, 301, 302, 307, 308}:
                results.append(
                    CheckResult(
                        name="www-dns",
                        status="PASS",
                        severity="info",
                        summary="www host resolves and responds.",
                        details=" | ".join(www_details),
                        module=self.slug,
                    )
                )
                if response.status in {301, 302, 307, 308}:
                    from urllib.parse import urlparse as _urlparse
                    location = response.headers.get("location", "")
                    expected_netloc = _urlparse(context.base_url).netloc
                    loc_netloc = _urlparse(location).netloc if location else ""
                    if loc_netloc == expected_netloc:
                        results.append(
                            CheckResult(
                                name="www-redirect",
                                status="PASS",
                                severity="info",
                                summary="www redirects to the canonical host.",
                                details=location,
                                module=self.slug,
                            )
                        )
                    else:
                        results.append(
                            CheckResult(
                                name="www-redirect",
                                status="WARN",
                                severity="medium",
                                summary="www responds but the redirect target is unexpected.",
                                details=location or "<missing>",
                                module=self.slug,
                            )
                        )
            else:
                results.append(
                    CheckResult(
                        name="www-dns",
                        status="WARN",
                        severity="medium",
                        summary="www host resolves but did not respond cleanly.",
                        details=f"status={response.status!r}",
                        module=self.slug,
                    )
                )
        return results
