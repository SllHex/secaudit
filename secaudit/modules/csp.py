"""CSP and front-end surface checks."""

from __future__ import annotations

import re

from ..core import AuditContext, AuditModule, CheckResult, HttpClient, TURNSTILE_HOST, normalize_whitespace


def parse_csp(header: str) -> dict[str, list[str]]:
    """Parse a CSP header into directive tokens."""

    directives: dict[str, list[str]] = {}
    for chunk in header.split(";"):
        part = chunk.strip()
        if not part:
            continue
        tokens = part.split()
        directives[tokens[0].lower()] = tokens[1:]
    return directives


class CSPModule(AuditModule):
    """Inspect CSP directives and front-end security markers."""

    slug = "csp"
    name = "CSP"
    description = "Content-Security-Policy quality, rendered HTML security markers, and front-end hygiene."

    async def run(self, client: HttpClient, context: AuditContext) -> list[CheckResult]:
        results: list[CheckResult] = []
        homepage = await context.get_homepage(client)
        if homepage.status != 200:
            return [
                CheckResult(
                    name="csp-skip",
                    status="INFO",
                    severity="info",
                    summary="Skipped CSP and HTML inspection because the homepage did not load cleanly.",
                    details=f"status={homepage.status!r}",
                    module=self.slug,
                )
            ]

        csp_header = homepage.headers.get("content-security-policy", "")
        if csp_header:
            directives = parse_csp(csp_header)
            required = {
                "default-src": "'self'",
                "object-src": "'none'",
                "base-uri": "'none'",
                "form-action": "'self'",
                "frame-ancestors": "'none'",
            }
            for directive, expected in required.items():
                values = directives.get(directive, [])
                if expected in values:
                    results.append(CheckResult(f"csp-{directive}", "PASS", "info", f"CSP {directive} includes {expected}.", module=self.slug))
                else:
                    results.append(
                        CheckResult(
                            f"csp-{directive}",
                            "FAIL",
                            "high",
                            f"CSP {directive} does not include {expected}.",
                            normalize_whitespace(" ".join(values)) or "<missing>",
                            self.slug,
                        )
                    )

            script_src = directives.get("script-src", [])
            if "'unsafe-inline'" in script_src:
                results.append(CheckResult("csp-script-inline", "FAIL", "high", "CSP allows inline scripts.", normalize_whitespace(" ".join(script_src)), self.slug))
            else:
                results.append(CheckResult("csp-script-inline", "PASS", "info", "CSP does not allow inline scripts in script-src.", module=self.slug))

            if "'unsafe-eval'" in script_src:
                results.append(CheckResult("csp-script-eval", "WARN", "medium", "CSP allows unsafe-eval in script-src.", normalize_whitespace(" ".join(script_src)), self.slug))
            else:
                results.append(CheckResult("csp-script-eval", "PASS", "info", "CSP does not allow unsafe-eval in script-src.", module=self.slug))

            script_src_attr = directives.get("script-src-attr", [])
            if script_src_attr == ["'none'"]:
                results.append(CheckResult("csp-script-attr", "PASS", "info", "CSP blocks inline script attributes.", module=self.slug))
            else:
                results.append(CheckResult("csp-script-attr", "WARN", "medium", "CSP does not cleanly block inline script attributes.", normalize_whitespace(" ".join(script_src_attr)) or "<missing>", self.slug))

            style_src = directives.get("style-src", [])
            style_src_elem = directives.get("style-src-elem", [])
            style_src_attr = directives.get("style-src-attr", [])
            if "'unsafe-inline'" in style_src or "'unsafe-inline'" in style_src_elem:
                results.append(
                    CheckResult(
                        "csp-style-inline",
                        "WARN",
                        "medium",
                        "CSP allows inline styles.",
                        f"style-src={normalize_whitespace(' '.join(style_src))} | style-src-elem={normalize_whitespace(' '.join(style_src_elem))}",
                        self.slug,
                    )
                )
            else:
                results.append(CheckResult("csp-style-inline", "PASS", "info", "CSP does not allow inline styles.", module=self.slug))
            if "'unsafe-inline'" in style_src_attr:
                results.append(CheckResult("csp-style-attr-inline", "WARN", "medium", "CSP still allows inline style attributes.", normalize_whitespace(" ".join(style_src_attr)), self.slug))
            elif style_src_attr:
                results.append(CheckResult("csp-style-attr-inline", "PASS", "info", "CSP does not allow unsafe inline style attributes.", normalize_whitespace(" ".join(style_src_attr)), self.slug))

            if TURNSTILE_HOST in homepage.body:
                for directive_name in ("script-src", "connect-src", "frame-src"):
                    values = directives.get(directive_name, [])
                    if TURNSTILE_HOST in values:
                        results.append(CheckResult(f"csp-turnstile-{directive_name}", "PASS", "info", f"CSP {directive_name} allows Cloudflare Turnstile.", module=self.slug))
                    else:
                        results.append(CheckResult(f"csp-turnstile-{directive_name}", "FAIL", "high", f"CSP {directive_name} does not allow Cloudflare Turnstile.", normalize_whitespace(" ".join(values)) or "<missing>", self.slug))
        else:
            results.append(CheckResult("csp-header-missing", "INFO", "info", "Skipped directive-level CSP validation because no CSP header was present.", module=self.slug))

        leaked = [token for token in ("__TURNSTILE_SITE_KEY__", "__CONTACT_CSRF_TOKEN__", "__CSP_NONCE__") if token in homepage.body]
        if leaked:
            results.append(CheckResult("html-placeholders", "FAIL", "high", "Rendered HTML still contains security placeholders.", ", ".join(leaked), self.slug))
        else:
            results.append(CheckResult("html-placeholders", "PASS", "info", "No security placeholders leaked into rendered HTML.", module=self.slug))

        csrf_match = re.search(r'<meta\s+name="contact-csrf-token"\s+content="([^"]*)"', homepage.body, re.IGNORECASE)
        csrf_value = csrf_match.group(1).strip() if csrf_match else ""
        if csrf_value and not csrf_value.startswith("__"):
            results.append(CheckResult("html-csrf-meta", "PASS", "info", "CSRF meta token is rendered into HTML.", module=self.slug))
        else:
            results.append(CheckResult("html-csrf-meta", "FAIL", "high", "CSRF meta token is missing or still a placeholder.", module=self.slug))

        if TURNSTILE_HOST in homepage.body:
            turnstile_match = re.search(r'<meta\s+name="turnstile-site-key"\s+content="([^"]*)"', homepage.body, re.IGNORECASE)
            if not turnstile_match:
                results.append(CheckResult("turnstile-meta", "FAIL", "high", "Turnstile site key meta tag is missing.", module=self.slug))
            else:
                turnstile_value = turnstile_match.group(1).strip()
                if not turnstile_value or turnstile_value.startswith("__"):
                    results.append(CheckResult("turnstile-meta", "FAIL", "high", "Turnstile site key was not rendered into HTML.", turnstile_value or "<empty>", self.slug))
                else:
                    results.append(CheckResult("turnstile-meta", "PASS", "info", "Turnstile site key is rendered into HTML.", module=self.slug))
        else:
            results.append(CheckResult("turnstile-meta", "INFO", "info", "Turnstile not detected on this page; site key check skipped.", module=self.slug))

        canonical_match = re.search(r'<link\s+rel="canonical"\s+href="([^"]+)"', homepage.body, re.IGNORECASE)
        canonical = canonical_match.group(1).strip() if canonical_match else ""
        if canonical == context.base_url:
            results.append(CheckResult("html-canonical", "PASS", "info", "Canonical URL matches the audited base URL.", canonical, self.slug))
        elif canonical:
            results.append(CheckResult("html-canonical", "WARN", "medium", "Canonical URL does not match the audited base URL.", canonical, self.slug))
        else:
            results.append(CheckResult("html-canonical", "WARN", "low", "Canonical URL is missing from HTML.", module=self.slug))

        attr_http_refs = re.findall(r'''(?:src|href)=["'](http://[^"']+)["']''', homepage.body, re.IGNORECASE)
        if attr_http_refs:
            results.append(CheckResult("html-mixed-content", "FAIL", "high", "HTML contains explicit http:// resource links.", ", ".join(sorted(set(attr_http_refs))[:8]), self.slug))
        else:
            results.append(CheckResult("html-mixed-content", "PASS", "info", "HTML does not contain explicit http:// resource links.", module=self.slug))

        external_scripts = re.findall(r'''<script[^>]+src=["'](https?://[^"']+)["']''', homepage.body, re.IGNORECASE)
        unexpected = sorted({item for item in external_scripts if not item.startswith(TURNSTILE_HOST)})
        if unexpected:
            results.append(CheckResult("html-external-scripts", "WARN", "medium", "Unexpected external scripts were found in HTML.", ", ".join(unexpected), self.slug))
        else:
            results.append(CheckResult("html-external-scripts", "PASS", "info", "No unexpected external scripts were found in HTML.", module=self.slug))

        if TURNSTILE_HOST + "/turnstile/" in homepage.body:
            results.append(CheckResult("html-turnstile-script", "PASS", "info", "Turnstile client script is referenced in HTML.", module=self.slug))
        elif TURNSTILE_HOST in homepage.body:
            results.append(CheckResult("html-turnstile-script", "WARN", "medium", "Turnstile host is referenced but the expected script path was not found.", module=self.slug))
        else:
            results.append(CheckResult("html-turnstile-script", "INFO", "info", "Turnstile not detected on this page; script check skipped.", module=self.slug))

        if "/vendor/babel.min.js" in homepage.body:
            results.append(CheckResult("runtime-babel", "WARN", "medium", "Production page still loads Babel in the browser.", "This increases attack surface and is better precompiled away.", self.slug))
        else:
            results.append(CheckResult("runtime-babel", "PASS", "info", "Page does not load browser-side Babel.", module=self.slug))

        unsafe_blank_links = []
        for anchor in re.finditer(r"<a\b[^>]*>", homepage.body, re.IGNORECASE):
            tag = anchor.group(0)
            if 'target="_blank"' not in tag.lower():
                continue
            rel_match = re.search(r'''rel=["']([^"']+)["']''', tag, re.IGNORECASE)
            rel_value = rel_match.group(1).lower() if rel_match else ""
            if "noopener" not in rel_value or "noreferrer" not in rel_value:
                unsafe_blank_links.append(tag)
        if unsafe_blank_links:
            results.append(CheckResult("html-target-blank-rel", "WARN", "medium", "Some target=_blank links are missing rel=noopener noreferrer.", unsafe_blank_links[0][:200], self.slug))
        else:
            results.append(CheckResult("html-target-blank-rel", "PASS", "info", "target=_blank links include rel=noopener noreferrer.", module=self.slug))

        return results
