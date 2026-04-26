"""Cookie flag validation checks."""

from __future__ import annotations

from ..core import AuditContext, AuditModule, CSRF_COOKIE_NAME, CheckResult, HttpClient, parse_cookie_headers


class CookiesModule(AuditModule):
    """Validate cookie-level hardening controls."""

    slug = "cookies"
    name = "Cookies"
    description = "Cookie flag checks for Secure, HttpOnly, SameSite, and path scoping."

    async def run(self, client: HttpClient, context: AuditContext) -> list[CheckResult]:
        homepage = await context.get_homepage(client)
        cookies = parse_cookie_headers(homepage.header_values.get("set-cookie", []))
        morsel = cookies.get(CSRF_COOKIE_NAME)
        if morsel is None:
            return [
                CheckResult(
                    name="cookie-csrf",
                    status="FAIL",
                    severity="high",
                    summary="CSRF cookie is missing from homepage response.",
                    module=self.slug,
                )
            ]

        results = [CheckResult("cookie-csrf", "PASS", "info", "CSRF cookie is present on homepage response.", module=self.slug)]

        if morsel["secure"]:
            results.append(CheckResult("cookie-csrf-secure", "PASS", "info", "CSRF cookie is marked Secure.", module=self.slug))
        else:
            results.append(CheckResult("cookie-csrf-secure", "FAIL", "high", "CSRF cookie is not marked Secure.", module=self.slug))

        if morsel["httponly"]:
            results.append(CheckResult("cookie-csrf-httponly", "PASS", "info", "CSRF cookie is marked HttpOnly.", module=self.slug))
        else:
            results.append(CheckResult("cookie-csrf-httponly", "FAIL", "medium", "CSRF cookie is not marked HttpOnly.", module=self.slug))

        samesite = morsel["samesite"]
        if samesite.lower() == "strict":
            results.append(CheckResult("cookie-csrf-samesite", "PASS", "info", "CSRF cookie uses SameSite=Strict.", module=self.slug))
        elif samesite:
            results.append(CheckResult("cookie-csrf-samesite", "WARN", "medium", "CSRF cookie uses a weaker SameSite policy.", samesite, self.slug))
        else:
            results.append(CheckResult("cookie-csrf-samesite", "FAIL", "medium", "CSRF cookie is missing a SameSite attribute.", module=self.slug))

        if morsel["path"] == "/":
            results.append(CheckResult("cookie-csrf-path", "PASS", "info", "CSRF cookie path is '/'.", module=self.slug))
        else:
            results.append(CheckResult("cookie-csrf-path", "WARN", "low", "CSRF cookie path is unexpected.", morsel["path"] or "<missing>", self.slug))

        return results
