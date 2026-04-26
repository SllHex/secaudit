"""HTTPS and TLS posture checks."""

from __future__ import annotations

import ssl

from ..core import AuditContext, AuditModule, CheckResult, HttpClient, parse_certificate_expiry


class TLSModule(AuditModule):
    """Validate HTTPS reachability, redirects, and TLS settings."""

    slug = "tls"
    name = "TLS/Cert"
    description = "HTTPS reachability, redirect behavior, TLS certificate validity, and legacy protocol exposure."

    async def run(self, client: HttpClient, context: AuditContext) -> list[CheckResult]:
        results: list[CheckResult] = []

        homepage = await context.get_homepage(client)
        if homepage.status == 200:
            results.append(CheckResult("https-root", "PASS", "info", "HTTPS homepage responded with 200.", module=self.slug))
        else:
            results.append(
                CheckResult(
                    "https-root",
                    "FAIL",
                    "high",
                    "HTTPS homepage did not respond with 200.",
                    f"status={homepage.status!r} error={homepage.error}",
                    module=self.slug,
                )
            )

        content_type = homepage.headers.get("content-type", "")
        if content_type.lower().startswith("text/html"):
            results.append(
                CheckResult(
                    "https-root-content-type",
                    "PASS",
                    "info",
                    "Homepage content type is HTML.",
                    content_type,
                    module=self.slug,
                )
            )
        else:
            results.append(
                CheckResult(
                    "https-root-content-type",
                    "WARN",
                    "medium",
                    "Homepage content type is unexpected.",
                    content_type or "<missing>",
                    module=self.slug,
                )
            )

        cache_control = homepage.headers.get("cache-control", "")
        if "no-store" in cache_control.lower():
            results.append(
                CheckResult(
                    "https-root-cache",
                    "PASS",
                    "info",
                    "Homepage is marked no-store.",
                    cache_control,
                    module=self.slug,
                )
            )
        else:
            results.append(
                CheckResult(
                    "https-root-cache",
                    "WARN",
                    "medium",
                    "Homepage is not marked no-store.",
                    cache_control or "<missing>",
                    module=self.slug,
                )
            )

        http_root = await context.get_http_root(client)
        location = http_root.headers.get("location", "")
        if http_root.status in {301, 302, 307, 308} and location.startswith("https://"):
            from urllib.parse import urlparse as _urlparse
            loc_parsed = _urlparse(location)
            expected_host = _urlparse(context.base_url).netloc
            if loc_parsed.netloc == expected_host:
                results.append(
                    CheckResult(
                        "http-redirect",
                        "PASS",
                        "info",
                        "HTTP redirects to HTTPS.",
                        module=self.slug,
                    )
                )
            else:
                results.append(
                    CheckResult(
                        "http-redirect",
                        "WARN",
                        "medium",
                        "HTTP redirects to HTTPS but changes host.",
                        location,
                        module=self.slug,
                    )
                )
        else:
            results.append(
                CheckResult(
                    "http-redirect",
                    "FAIL",
                    "medium",
                    "HTTP does not redirect cleanly to HTTPS.",
                    f"status={http_root.status!r} location={location!r} error={http_root.error}",
                    module=self.slug,
                )
            )

        if not context.host:
            results.append(
                CheckResult(
                    "tls-certificate",
                    "FAIL",
                    "high",
                    "Could not determine hostname for TLS checks.",
                    module=self.slug,
                )
            )
            return results

        try:
            tls_details = await client.fetch_tls_details(context.host)
        except Exception as exc:  # noqa: BLE001
            results.append(
                CheckResult(
                    "tls-certificate",
                    "FAIL",
                    "high",
                    "TLS certificate check failed.",
                    str(exc),
                    module=self.slug,
                )
            )
            return results

        cert = tls_details.cert
        issuer = cert.get("issuer", ())
        subject_alt_names = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]
        if subject_alt_names:
            results.append(
                CheckResult(
                    "tls-san-hostname",
                    "PASS",
                    "info",
                    "TLS certificate SAN includes the requested host.",
                    f"validated during TLS handshake; SAN count={len(subject_alt_names)}",
                    module=self.slug,
                )
            )
        else:
            results.append(
                CheckResult(
                    "tls-san-hostname",
                    "PASS",
                    "info",
                    "TLS handshake succeeded and hostname validation completed.",
                    "Python/OpenSSL verified the peer during the TLS handshake.",
                    module=self.slug,
                )
            )

        if issuer:
            issuer_text = ", ".join(part[0][1] for part in issuer if part and part[0])
            results.append(
                CheckResult(
                    "tls-issuer",
                    "PASS",
                    "info",
                    "TLS certificate issuer read successfully.",
                    issuer_text,
                    module=self.slug,
                )
            )

        if tls_details.cipher_bits == 0:
            results.append(
                CheckResult(
                    "tls-cipher",
                    "WARN",
                    "medium",
                    "TLS cipher strength could not be determined.",
                    tls_details.cipher_name,
                    module=self.slug,
                )
            )
        elif any(weak in tls_details.cipher_name.upper() for weak in ("RC4", "3DES", "DES", "NULL", "MD5")) or tls_details.cipher_bits < 128:
            results.append(
                CheckResult(
                    "tls-cipher",
                    "FAIL",
                    "high",
                    "Weak TLS cipher negotiated.",
                    f"{tls_details.cipher_name} ({tls_details.cipher_bits} bits)",
                    module=self.slug,
                )
            )
        else:
            results.append(
                CheckResult(
                    "tls-cipher",
                    "PASS",
                    "info",
                    "TLS cipher looks modern.",
                    f"{tls_details.cipher_name} ({tls_details.cipher_bits} bits)",
                    module=self.slug,
                )
            )

        if tls_details.tls_version in {"TLSv1.2", "TLSv1.3"}:
            results.append(
                CheckResult(
                    "tls-version-negotiated",
                    "PASS",
                    "info",
                    "Negotiated TLS version is modern.",
                    tls_details.tls_version,
                    module=self.slug,
                )
            )
        else:
            results.append(
                CheckResult(
                    "tls-version-negotiated",
                    "FAIL",
                    "high",
                    "Negotiated TLS version is outdated.",
                    tls_details.tls_version,
                    module=self.slug,
                )
            )

        not_after = cert.get("notAfter")
        if not not_after:
            results.append(
                CheckResult(
                    "tls-certificate",
                    "WARN",
                    "medium",
                    "TLS certificate expiry date was not available.",
                    module=self.slug,
                )
            )
        else:
            days_left = parse_certificate_expiry(not_after)
            if days_left == -9999:
                results.append(
                    CheckResult(
                        "tls-certificate",
                        "WARN",
                        "medium",
                        "TLS certificate expiry date could not be parsed.",
                        not_after,
                        module=self.slug,
                    )
                )
            elif days_left < 0:
                results.append(
                    CheckResult(
                        "tls-certificate",
                        "FAIL",
                        "critical",
                        "TLS certificate is expired.",
                        f"expired {abs(days_left)} days ago",
                        module=self.slug,
                    )
                )
            elif days_left < 15:
                results.append(
                    CheckResult(
                        "tls-certificate",
                        "WARN",
                        "high",
                        "TLS certificate expires soon.",
                        f"{days_left} days left",
                        module=self.slug,
                    )
                )
            else:
                results.append(
                    CheckResult(
                        "tls-certificate",
                        "PASS",
                        "info",
                        "TLS certificate is valid.",
                        f"{days_left} days left",
                        module=self.slug,
                    )
                )

        checks = [
            ("TLSv1", "tls-legacy-tls1"),
            ("TLSv1_1", "tls-legacy-tls1_1"),
            ("TLSv1_2", "tls-modern-tls1_2"),
        ]
        for version_name, result_name in checks:
            supported, detail = await client.probe_tls_version(context.host, version_name)
            if version_name in {"TLSv1", "TLSv1_1"}:
                if supported:
                    results.append(
                        CheckResult(
                            result_name,
                            "FAIL",
                            "high",
                            f"Server still accepts legacy {version_name}.",
                            detail,
                            module=self.slug,
                        )
                    )
                else:
                    results.append(
                        CheckResult(
                            result_name,
                            "PASS",
                            "info",
                            f"Server does not accept legacy {version_name}.",
                            detail,
                            module=self.slug,
                        )
                    )
            elif supported:
                results.append(
                    CheckResult(
                        result_name,
                        "PASS",
                        "info",
                        f"Server accepts {version_name}.",
                        detail,
                        module=self.slug,
                    )
                )
            else:
                results.append(
                    CheckResult(
                        result_name,
                        "WARN",
                        "medium",
                        f"Could not confirm support for {version_name}.",
                        detail,
                        module=self.slug,
                    )
                )

        if hasattr(ssl, "TLSVersion") and hasattr(ssl.TLSVersion, "TLSv1_3"):
            supported, detail = await client.probe_tls_version(context.host, "TLSv1_3")
            if supported:
                results.append(
                    CheckResult(
                        "tls-modern-tls1_3",
                        "PASS",
                        "info",
                        "Server accepts TLSv1.3.",
                        detail,
                        module=self.slug,
                    )
                )
            else:
                results.append(
                    CheckResult(
                        "tls-modern-tls1_3",
                        "WARN",
                        "low",
                        "Could not confirm support for TLSv1.3.",
                        detail,
                        module=self.slug,
                    )
                )

        return results
