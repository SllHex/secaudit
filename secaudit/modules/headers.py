"""HTTP header validation checks."""

from __future__ import annotations

import re
from typing import cast

from ..core import AuditContext, AuditModule, CheckResult, HttpClient, SeverityType


class HeadersModule(AuditModule):
    """Check the target's core security headers and error-page consistency."""

    slug = "headers"
    name = "Headers"
    description = "Security header presence and value validation, including 404 responses."

    async def run(self, client: HttpClient, context: AuditContext) -> list[CheckResult]:
        results: list[CheckResult] = []
        homepage = await context.get_homepage(client)
        headers = homepage.headers

        expectations = {
            "content-security-policy": "CSP header is present.",
            "strict-transport-security": "HSTS header is present.",
            "x-content-type-options": "nosniff header is present.",
            "x-frame-options": "frame protection header is present.",
            "referrer-policy": "Referrer-Policy header is present.",
            "permissions-policy": "Permissions-Policy header is present.",
            "cross-origin-opener-policy": "COOP header is present.",
            "cross-origin-resource-policy": "CORP header is present.",
        }
        for header, summary in expectations.items():
            if header in headers:
                results.append(CheckResult(f"header-{header}", "PASS", "info", summary, headers[header], self.slug))
            else:
                severity = cast(SeverityType, "medium" if header in {"content-security-policy", "strict-transport-security"} else "low")
                results.append(
                    CheckResult(
                        f"header-{header}",
                        "FAIL",
                        severity,
                        f"Missing security header: {header}.",
                        module=self.slug,
                    )
                )

        xcto = headers.get("x-content-type-options", "")
        if xcto.lower() == "nosniff":
            results.append(CheckResult("header-x-content-type-options-value", "PASS", "info", "X-Content-Type-Options is set to nosniff.", module=self.slug))
        elif xcto:
            results.append(CheckResult("header-x-content-type-options-value", "WARN", "medium", "X-Content-Type-Options has an unexpected value.", xcto, self.slug))

        xfo = headers.get("x-frame-options", "")
        if xfo.upper() == "DENY":
            results.append(CheckResult("header-x-frame-options-value", "PASS", "info", "X-Frame-Options is DENY.", module=self.slug))
        elif xfo:
            results.append(CheckResult("header-x-frame-options-value", "WARN", "medium", "X-Frame-Options is not DENY.", xfo, self.slug))

        referrer_policy = headers.get("referrer-policy", "")
        if referrer_policy == "no-referrer":
            results.append(CheckResult("header-referrer-policy-value", "PASS", "info", "Referrer-Policy is no-referrer.", module=self.slug))
        elif referrer_policy:
            results.append(CheckResult("header-referrer-policy-value", "WARN", "low", "Referrer-Policy is present but more permissive than expected.", referrer_policy, self.slug))

        hsts = headers.get("strict-transport-security", "")
        if hsts:
            max_age_match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
            max_age = int(max_age_match.group(1)) if max_age_match else 0
            if max_age >= 31536000:
                results.append(CheckResult("header-hsts-max-age", "PASS", "info", "HSTS max-age is at least one year.", str(max_age), self.slug))
            elif max_age > 0:
                results.append(CheckResult("header-hsts-max-age", "WARN", "medium", "HSTS max-age is shorter than one year.", str(max_age), self.slug))
            if "includesubdomains" in hsts.lower():
                results.append(CheckResult("header-hsts-subdomains", "PASS", "info", "HSTS includes subdomains.", module=self.slug))
            else:
                results.append(CheckResult("header-hsts-subdomains", "WARN", "medium", "HSTS does not include subdomains.", hsts, self.slug))

        coop = headers.get("cross-origin-opener-policy", "")
        if coop == "same-origin":
            results.append(CheckResult("header-coop-value", "PASS", "info", "COOP is same-origin.", module=self.slug))
        elif coop:
            results.append(CheckResult("header-coop-value", "WARN", "medium", "COOP is present but not same-origin.", coop, self.slug))

        corp = headers.get("cross-origin-resource-policy", "")
        if corp == "same-origin":
            results.append(CheckResult("header-corp-value", "PASS", "info", "CORP is same-origin.", module=self.slug))
        elif corp:
            results.append(CheckResult("header-corp-value", "WARN", "medium", "CORP is present but not same-origin.", corp, self.slug))

        if headers.get("permissions-policy"):
            results.append(CheckResult("header-permissions-policy-value", "PASS", "info", "Permissions-Policy has a value.", headers["permissions-policy"], self.slug))

        server_header = headers.get("server", "")
        if server_header:
            results.append(CheckResult("header-server", "WARN", "low", "Server header is exposed.", server_header, self.slug))
        else:
            results.append(CheckResult("header-server", "PASS", "info", "Server header is not exposed.", module=self.slug))

        if "x-powered-by" in headers:
            results.append(CheckResult("header-x-powered-by", "FAIL", "medium", "X-Powered-By header is exposed.", headers["x-powered-by"], self.slug))
        else:
            results.append(CheckResult("header-x-powered-by", "PASS", "info", "X-Powered-By header is not exposed.", module=self.slug))

        missing = await client.request(context.url("/definitely-missing-audit-path"))
        if missing.status == 404:
            results.append(CheckResult("error-404-status", "PASS", "info", "Unknown paths return 404.", module=self.slug))
        else:
            results.append(CheckResult("error-404-status", "WARN", "medium", "Unknown path did not return 404.", f"status={missing.status!r}", self.slug))

        for header in ("content-security-policy", "x-content-type-options", "x-frame-options", "referrer-policy"):
            if header in missing.headers:
                results.append(CheckResult(f"error-404-{header}", "PASS", "info", f"404 response includes {header}.", module=self.slug))
            else:
                results.append(CheckResult(f"error-404-{header}", "WARN", "medium", f"404 response is missing {header}.", module=self.slug))

        return results
