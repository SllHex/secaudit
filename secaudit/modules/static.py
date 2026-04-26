"""Static-file exposure and traversal checks."""

from __future__ import annotations

from typing import cast

from ..core import AuditContext, AuditModule, CheckResult, EXPECTED_ERROR_STATUSES, HttpClient, SeverityType


class StaticModule(AuditModule):
    """Check for source exposure, traversal escapes, and asset behavior."""

    slug = "static"
    name = "Static Files"
    description = "Static surface checks for source exposure, traversal handling, and expected asset reachability."

    async def run(self, client: HttpClient, context: AuditContext) -> list[CheckResult]:
        results: list[CheckResult] = []
        cases = [
            ("/contact_server.py", EXPECTED_ERROR_STATUSES, "Source file should not be web-accessible."),
            ("/app/contact_server.py", EXPECTED_ERROR_STATUSES, "App server source should not be web-accessible."),
            ("/deploy/portfolio-contact.service", EXPECTED_ERROR_STATUSES, "Deployment unit files should not be web-accessible."),
            ("/tools/site_audit.py", EXPECTED_ERROR_STATUSES, "Audit tool source should not be web-accessible."),
            ("/README.md", EXPECTED_ERROR_STATUSES, "Internal README should not be web-accessible."),
            ("/.git/config", EXPECTED_ERROR_STATUSES, ".git contents should not be exposed."),
            ("/.env", EXPECTED_ERROR_STATUSES, ".env files should not be exposed."),
            ("/.contact_server.env", EXPECTED_ERROR_STATUSES, "Secret env file should not be web-accessible."),
            ("/vendor/", EXPECTED_ERROR_STATUSES, "Public directories should not expose listings."),
            ("/vendor/../contact_server.py", EXPECTED_ERROR_STATUSES, "Plain traversal should not escape the static root."),
            ("/vendor/%2e%2e/contact_server.py", EXPECTED_ERROR_STATUSES, "Encoded traversal should not escape the static root."),
            ("/vendor/%2e%2e%2fcontact_server.py", EXPECTED_ERROR_STATUSES, "Encoded slash traversal should not escape the static root."),
            ("/vendor/%2e%2e%5ccontact_server.py", EXPECTED_ERROR_STATUSES, "Encoded backslash traversal should not escape the static root."),
            ("/New%20Folder/index(2).html", EXPECTED_ERROR_STATUSES, "Unpublished worktree files should not be exposed."),
            ("/vendor/react.production.min.js", {200}, "Expected public asset should remain reachable."),
        ]

        for path, acceptable, summary in cases:
            response = await client.request(context.url(path))
            if response.status in acceptable:
                results.append(CheckResult(f"path-{path}", "PASS", "info", summary, f"status={response.status}", self.slug))
            else:
                severity = cast(SeverityType, "high" if response.status == 200 and "should not" in summary.lower() else "medium")
                results.append(CheckResult(f"path-{path}", "FAIL", severity, summary, f"status={response.status!r} error={response.error}", self.slug))

        asset = await client.request(context.url("/vendor/react.production.min.js"), method="HEAD")
        if asset.status == 200:
            results.append(CheckResult("asset-head", "PASS", "info", "Vendor asset responds to HEAD.", module=self.slug))
            cache = asset.headers.get("cache-control", "")
            if "max-age" in cache.lower():
                results.append(CheckResult("asset-cache", "PASS", "info", "Vendor asset is cacheable.", cache, self.slug))
            else:
                results.append(CheckResult("asset-cache", "WARN", "medium", "Vendor asset is missing an explicit cache policy.", cache or "<missing>", self.slug))
            content_type = asset.headers.get("content-type", "")
            if "javascript" in content_type.lower():
                results.append(CheckResult("asset-content-type", "PASS", "info", "Vendor asset content type looks correct.", content_type, self.slug))
            else:
                results.append(CheckResult("asset-content-type", "WARN", "medium", "Vendor asset content type is unexpected.", content_type or "<missing>", self.slug))
        else:
            results.append(CheckResult("asset-head", "WARN", "medium", "Vendor asset HEAD request did not return 200.", f"status={asset.status!r}", self.slug))

        return results
