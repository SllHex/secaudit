"""API endpoint and anti-abuse checks."""

from __future__ import annotations

import asyncio

from ..core import AuditContext, AuditModule, CSRF_COOKIE_NAME, CheckResult, HttpClient


class APIModule(AuditModule):
    """Exercise defensive behavior on the public contact endpoint."""

    slug = "api"
    name = "API/CSRF"
    description = "Contact API checks for preflight behavior, CSRF, origin handling, anti-bot gates, and optional rate limiting."

    async def run(self, client: HttpClient, context: AuditContext) -> list[CheckResult]:
        await context.get_homepage(client)
        results: list[CheckResult] = []
        api_url = context.url("/api/contact")

        async def post_contact(
            payload: bytes,
            *,
            origin: str | None = None,
            csrf_meta: str = "",
            csrf_cookie: str = "",
            content_type: str = "application/json",
        ):
            headers = {"Content-Type": content_type}
            if origin is not None:
                headers["Origin"] = origin
            if csrf_meta:
                headers["X-CSRF-Token"] = csrf_meta
            if csrf_cookie:
                headers["Cookie"] = f"{CSRF_COOKIE_NAME}={csrf_cookie}"
            return await client.request(api_url, method="POST", headers=headers, body=payload)

        get_response = await client.request(api_url)
        if get_response.status in {403, 404, 405}:
            results.append(CheckResult("api-get", "PASS", "info", "Contact API does not allow plain GET browsing.", f"status={get_response.status}", self.slug))
        else:
            results.append(CheckResult("api-get", "WARN", "medium", "Unexpected GET behavior on contact API.", f"status={get_response.status}", self.slug))

        head_response = await client.request(api_url, method="HEAD")
        if head_response.status in {403, 404, 405}:
            results.append(CheckResult("api-head", "PASS", "info", "Contact API does not allow plain HEAD browsing.", f"status={head_response.status}", self.slug))
        else:
            results.append(CheckResult("api-head", "WARN", "medium", "Unexpected HEAD behavior on contact API.", f"status={head_response.status}", self.slug))

        missing_origin_options = await client.request(api_url, method="OPTIONS")
        if missing_origin_options.status == 403:
            results.append(CheckResult("api-preflight-missing-origin", "PASS", "info", "OPTIONS without Origin is blocked.", module=self.slug))
        else:
            results.append(CheckResult("api-preflight-missing-origin", "WARN", "medium", "OPTIONS without Origin was not blocked as expected.", f"status={missing_origin_options.status!r}", self.slug))

        bad_origin = await client.request(api_url, method="OPTIONS", headers={"Origin": "https://evil.example"})
        if bad_origin.status == 403:
            results.append(CheckResult("api-preflight-cross-origin", "PASS", "info", "Cross-origin preflight is blocked.", module=self.slug))
        else:
            results.append(CheckResult("api-preflight-cross-origin", "FAIL", "high", "Cross-origin preflight was not blocked.", f"status={bad_origin.status!r}", self.slug))

        good_origin = await client.request(api_url, method="OPTIONS", headers={"Origin": context.origin})
        if good_origin.status == 204 and good_origin.headers.get("access-control-allow-origin") == context.origin:
            results.append(CheckResult("api-preflight-same-origin", "PASS", "info", "Same-origin preflight is allowed cleanly.", module=self.slug))
        else:
            results.append(CheckResult("api-preflight-same-origin", "WARN", "medium", "Same-origin preflight did not look ideal.", f"status={good_origin.status!r} acao={good_origin.headers.get('access-control-allow-origin', '')!r}", self.slug))

        allow_headers = good_origin.headers.get("access-control-allow-headers", "")
        if "content-type" in allow_headers.lower() and "x-csrf-token" in allow_headers.lower():
            results.append(CheckResult("api-preflight-allow-headers", "PASS", "info", "Preflight exposes the expected allowed headers.", allow_headers, self.slug))
        else:
            results.append(CheckResult("api-preflight-allow-headers", "WARN", "medium", "Preflight allowed headers look incomplete.", allow_headers or "<missing>", self.slug))

        allow_methods = good_origin.headers.get("access-control-allow-methods", "")
        if "POST" in allow_methods and "OPTIONS" in allow_methods:
            results.append(CheckResult("api-preflight-allow-methods", "PASS", "info", "Preflight exposes the expected allowed methods.", allow_methods, self.slug))
        else:
            results.append(CheckResult("api-preflight-allow-methods", "WARN", "medium", "Preflight allowed methods look incomplete.", allow_methods or "<missing>", self.slug))

        vary = good_origin.headers.get("vary", "")
        if "origin" in vary.lower():
            results.append(CheckResult("api-preflight-vary", "PASS", "info", "Preflight varies on Origin.", vary, self.slug))
        else:
            results.append(CheckResult("api-preflight-vary", "WARN", "low", "Preflight does not advertise Vary: Origin.", vary or "<missing>", self.slug))

        wrong_type = await post_contact(b"{}", origin=context.origin, content_type="text/plain")
        if wrong_type.status == 415:
            results.append(CheckResult("api-content-type", "PASS", "info", "Contact API rejects non-JSON submissions.", module=self.slug))
        else:
            results.append(CheckResult("api-content-type", "WARN", "medium", "Contact API did not return the expected non-JSON rejection.", f"status={wrong_type.status!r}", self.slug))

        no_origin = await post_contact(b"{}", origin=None)
        if no_origin.status == 403:
            results.append(CheckResult("api-post-missing-origin", "PASS", "info", "POST without Origin is blocked.", module=self.slug))
        else:
            results.append(CheckResult("api-post-missing-origin", "FAIL", "high", "POST without Origin was not blocked.", f"status={no_origin.status!r}", self.slug))

        wrong_origin = await post_contact(b"{}", origin="https://evil.example")
        if wrong_origin.status == 403:
            results.append(CheckResult("api-post-cross-origin", "PASS", "info", "Cross-origin POST is blocked.", module=self.slug))
        else:
            results.append(CheckResult("api-post-cross-origin", "FAIL", "high", "Cross-origin POST was not blocked.", f"status={wrong_origin.status!r}", self.slug))

        missing_csrf = await post_contact(
            b'{"name":"SecAudit","email":"audit@example.com","message":"hello","turnstileToken":"invalid"}',
            origin=context.origin,
        )
        if missing_csrf.status == 403:
            results.append(CheckResult("api-csrf", "PASS", "info", "Contact API rejects requests without CSRF tokens.", module=self.slug))
        else:
            results.append(CheckResult("api-csrf", "FAIL", "high", "Contact API did not reject a missing-CSRF request.", f"status={missing_csrf.status!r}", self.slug))

        csrf_meta, csrf_cookie = context.extract_form_session()
        if not csrf_meta or not csrf_cookie:
            results.append(CheckResult("api-form-session", "FAIL", "high", "Could not extract CSRF session material from the homepage.", f"meta_present={bool(csrf_meta)} cookie_present={bool(csrf_cookie)}", self.slug))
            return results
        results.append(CheckResult("api-form-session", "PASS", "info", "Homepage exposes CSRF token and cookie for same-origin form use.", module=self.slug))

        mismatched_csrf = await post_contact(
            b'{"name":"SecAudit","email":"audit@example.com","message":"hello","turnstileToken":"invalid"}',
            origin=context.origin,
            csrf_meta=csrf_meta,
            csrf_cookie="invalid",
        )
        if mismatched_csrf.status == 403:
            results.append(CheckResult("api-csrf-mismatch", "PASS", "info", "Contact API rejects mismatched CSRF header/cookie pairs.", module=self.slug))
        else:
            results.append(CheckResult("api-csrf-mismatch", "FAIL", "high", "Mismatched CSRF header/cookie pair was not blocked.", f"status={mismatched_csrf.status!r}", self.slug))

        immediate = await post_contact(
            b'{"name":"SecAudit","email":"audit@example.com","message":"hello","turnstileToken":"invalid"}',
            origin=context.origin,
            csrf_meta=csrf_meta,
            csrf_cookie=csrf_cookie,
        )
        if immediate.status == 425:
            results.append(CheckResult("api-form-min-age", "PASS", "info", "Fresh forms are delayed by the minimum-age check.", module=self.slug))
        elif immediate.status == 403 and "Verification failed" in immediate.body:
            results.append(CheckResult("api-form-min-age", "INFO", "info", "First stateful probe reached Turnstile after the minimum-age window had already elapsed.", "This is not a security failure; the form simply progressed to Turnstile validation first.", self.slug))
        elif immediate.status == 429:
            results.append(CheckResult("api-form-min-age", "WARN", "medium", "Stateful API probes hit the rate limit before the minimum-age check could be observed.", "Wait about 60 seconds and rerun from a clean IP/session for the full stateful probe set.", self.slug))
            results.append(CheckResult("api-stateful-probes", "WARN", "medium", "Further stateful API probes were skipped because the auditor IP is already rate limited.", module=self.slug))
            return results
        else:
            results.append(CheckResult("api-form-min-age", "WARN", "medium", "Fresh forms did not return the expected Too Early response.", f"status={immediate.status!r} body={immediate.body[:120]!r}", self.slug))

        await asyncio.sleep(3)

        invalid_json = await post_contact(b"{bad json", origin=context.origin, csrf_meta=csrf_meta, csrf_cookie=csrf_cookie)
        if invalid_json.status == 400:
            results.append(CheckResult("api-invalid-json", "PASS", "info", "Contact API rejects malformed JSON bodies.", module=self.slug))
        elif invalid_json.status == 429:
            results.append(CheckResult("api-invalid-json", "WARN", "medium", "Stateful API probes hit the rate limit before malformed JSON could be checked.", module=self.slug))
            results.append(CheckResult("api-stateful-probes", "WARN", "medium", "Further stateful API probes were skipped because the auditor IP is already rate limited.", module=self.slug))
            return results
        else:
            results.append(CheckResult("api-invalid-json", "WARN", "medium", "Malformed JSON did not return the expected 400.", f"status={invalid_json.status!r}", self.slug))

        large_message = b'{"name":"SecAudit","email":"audit@example.com","message":"' + (b"A" * 33000) + b'","turnstileToken":"invalid"}'
        too_large = await post_contact(large_message, origin=context.origin, csrf_meta=csrf_meta, csrf_cookie=csrf_cookie)
        if too_large.status == 413:
            results.append(CheckResult("api-body-size", "PASS", "info", "Contact API rejects oversized request bodies.", module=self.slug))
        elif too_large.status == 429:
            results.append(CheckResult("api-body-size", "WARN", "medium", "Stateful API probes hit the rate limit before body-size enforcement could be checked.", module=self.slug))
            results.append(CheckResult("api-stateful-probes", "WARN", "medium", "Further stateful API probes were skipped because the auditor IP is already rate limited.", module=self.slug))
            return results
        else:
            results.append(CheckResult("api-body-size", "WARN", "medium", "Oversized request body did not return the expected 413.", f"status={too_large.status!r}", self.slug))

        honeypot = await post_contact(
            b'{"name":"SecAudit","email":"audit@example.com","message":"hello","website":"trap","turnstileToken":"invalid"}',
            origin=context.origin,
            csrf_meta=csrf_meta,
            csrf_cookie=csrf_cookie,
        )
        if honeypot.status == 200:
            results.append(CheckResult("api-honeypot", "PASS", "info", "Honeypot field short-circuits the contact API without error.", module=self.slug))
        elif honeypot.status == 429:
            results.append(CheckResult("api-honeypot", "WARN", "medium", "Stateful API probes hit the rate limit before honeypot behavior could be checked.", module=self.slug))
            results.append(CheckResult("api-stateful-probes", "WARN", "medium", "Further stateful API probes were skipped because the auditor IP is already rate limited.", module=self.slug))
            return results
        else:
            results.append(CheckResult("api-honeypot", "WARN", "medium", "Honeypot flow did not return the expected 200.", f"status={honeypot.status!r} body={honeypot.body[:120]!r}", self.slug))

        deeper = await post_contact(
            b'{"name":"SecAudit","email":"audit@example.com","message":"hello","turnstileToken":"invalid"}',
            origin=context.origin,
            csrf_meta=csrf_meta,
            csrf_cookie=csrf_cookie,
        )
        if deeper.status == 403:
            results.append(CheckResult("api-turnstile-enforcement", "PASS", "info", "Anti-bot check is enforced after origin and CSRF checks.", f"status={deeper.status}", self.slug))
        elif deeper.status == 200:
            results.append(CheckResult("api-turnstile-enforcement", "FAIL", "high", "Anti-bot check did not block the probe — the contact form may have been submitted.", f"body={deeper.body[:120]!r}", self.slug))
            return results
        elif deeper.status == 429:
            results.append(CheckResult("api-turnstile-enforcement", "WARN", "medium", "Rate limiting triggered before anti-bot enforcement could be verified.", f"status={deeper.status}", self.slug))
        else:
            results.append(CheckResult("api-turnstile-enforcement", "WARN", "medium", "Unexpected response while probing anti-bot enforcement.", f"status={deeper.status!r} body={deeper.body[:180]!r}", self.slug))

        if context.test_rate_limit:
            triggered = False
            statuses: list[str] = []
            for _ in range(6):
                response = await post_contact(
                    b'{"name":"SecAudit","email":"audit@example.com","message":"hello","turnstileToken":"invalid"}',
                    origin=context.origin,
                    csrf_meta=csrf_meta,
                    csrf_cookie=csrf_cookie,
                )
                statuses.append(str(response.status))
                if response.status == 429:
                    triggered = True
                    break
            if triggered:
                results.append(CheckResult("api-rate-limit", "PASS", "info", "Rate limiting triggered under repeated invalid submissions.", ",".join(statuses), self.slug))
            else:
                results.append(CheckResult("api-rate-limit", "WARN", "medium", "Repeated invalid submissions did not trigger rate limiting in the probe window.", ",".join(statuses), self.slug))

        return results
