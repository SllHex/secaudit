"""Email and domain metadata checks."""

from __future__ import annotations

import asyncio
import re

from ..core import AuditContext, AuditModule, CheckResult, HttpClient

try:
    import dns.exception
    import dns.resolver
except ImportError:  # pragma: no cover - optional dependency path
    dns = None  # type: ignore[assignment]


def _format_txt_record(record: object) -> str:
    if hasattr(record, "strings"):
        try:
            return b"".join(getattr(record, "strings")).decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
    text = getattr(record, "to_text", lambda: str(record))()
    return text.strip('"')


def _lookup_records_sync(host: str, record_type: str) -> list[str]:
    if dns is None:
        return []
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    answers = resolver.resolve(host, record_type)
    if record_type == "TXT":
        return [_format_txt_record(answer) for answer in answers]
    return [answer.to_text().rstrip(".") for answer in answers]


async def _lookup_records(host: str, record_type: str) -> list[str]:
    return await asyncio.to_thread(_lookup_records_sync, host, record_type)


class EmailDNSModule(AuditModule):
    """Inspect domain records related to email and responsible disclosure."""

    slug = "email_dns"
    name = "Email/DNS"
    description = "Checks for MX, SPF, DMARC, CAA, and public security.txt disclosure guidance."

    async def run(self, client: HttpClient, context: AuditContext) -> list[CheckResult]:
        results: list[CheckResult] = []
        mx_found = False
        if not context.host:
            return [
                CheckResult(
                    name="email-dns-host",
                    status="FAIL",
                    severity="high",
                    summary="Could not determine hostname for email/DNS checks.",
                    module=self.slug,
                )
            ]

        if dns is None:
            results.append(
                CheckResult(
                    name="email-dns-dependency",
                    status="INFO",
                    severity="info",
                    summary="Install dnspython to enable MX/SPF/DMARC/CAA lookups.",
                    details="pip install dnspython>=2.6",
                    module=self.slug,
                )
            )
        else:
            mx_records, mx_error = await self._safe_lookup(context.host, "MX")
            if mx_error:
                results.append(
                    CheckResult(
                        name="email-mx-lookup",
                        status="WARN",
                        severity="low",
                        summary="MX lookup could not be completed reliably.",
                        details=mx_error,
                        module=self.slug,
                    )
                )
            elif mx_records:
                mx_found = True
                results.append(
                    CheckResult(
                        name="email-mx",
                        status="PASS",
                        severity="info",
                        summary="MX records were found for the apex domain.",
                        details=", ".join(mx_records),
                        module=self.slug,
                    )
                )
            else:
                results.append(
                    CheckResult(
                        name="email-mx",
                        status="WARN",
                        severity="low",
                        summary="No MX records were found for the apex domain.",
                        details="The domain may not receive mail directly.",
                        module=self.slug,
                    )
                )

            txt_records, txt_error = await self._safe_lookup(context.host, "TXT")
            spf_records = [record for record in txt_records if record.lower().startswith("v=spf1")]
            if txt_error:
                results.append(
                    CheckResult(
                        name="email-spf-lookup",
                        status="WARN",
                        severity="low",
                        summary="TXT lookup could not be completed reliably while checking SPF.",
                        details=txt_error,
                        module=self.slug,
                    )
                )
            elif spf_records:
                results.append(
                    CheckResult(
                        name="email-spf",
                        status="PASS",
                        severity="info",
                        summary="SPF TXT records are present.",
                        details=", ".join(spf_records),
                        module=self.slug,
                    )
                )
            else:
                results.append(
                    CheckResult(
                        name="email-spf",
                        status="WARN",
                        severity="medium" if mx_found else "low",
                        summary="No SPF TXT records were found on the apex domain.",
                        details="Severity is reduced when the domain has no MX records.",
                        module=self.slug,
                    )
                )

            dmarc_records, dmarc_error = await self._safe_lookup(f"_dmarc.{context.host}", "TXT")
            dmarc_entries = [record for record in dmarc_records if record.lower().startswith("v=dmarc1")]
            if dmarc_error:
                results.append(
                    CheckResult(
                        name="email-dmarc-lookup",
                        status="WARN",
                        severity="low",
                        summary="DMARC TXT lookup could not be completed reliably.",
                        details=dmarc_error,
                        module=self.slug,
                    )
                )
            elif not dmarc_entries:
                results.append(
                    CheckResult(
                        name="email-dmarc",
                        status="WARN",
                        severity="medium" if mx_found else "low",
                        summary="No DMARC policy record was found.",
                        details="Severity is reduced when the domain has no MX records.",
                        module=self.slug,
                    )
                )
            else:
                policy_match = re.search(r"\bp=([a-z]+)", dmarc_entries[0], re.IGNORECASE)
                policy = (policy_match.group(1).lower() if policy_match else "").strip()
                if policy in {"reject", "quarantine"}:
                    results.append(
                        CheckResult(
                            name="email-dmarc",
                            status="PASS",
                            severity="info",
                            summary="DMARC policy is present with enforcement enabled.",
                            details=dmarc_entries[0],
                            module=self.slug,
                        )
                    )
                elif policy:
                    results.append(
                        CheckResult(
                            name="email-dmarc",
                            status="WARN",
                            severity="medium",
                            summary="DMARC policy exists but is not enforcing strongly.",
                            details=dmarc_entries[0],
                            module=self.slug,
                        )
                    )
                else:
                    results.append(
                        CheckResult(
                            name="email-dmarc",
                            status="WARN",
                            severity="medium",
                            summary="DMARC record exists but the policy could not be parsed.",
                            details=dmarc_entries[0],
                            module=self.slug,
                        )
                    )

            caa_records, caa_error = await self._safe_lookup(context.host, "CAA")
            if caa_error:
                results.append(
                    CheckResult(
                        name="domain-caa-lookup",
                        status="WARN",
                        severity="low",
                        summary="CAA lookup could not be completed reliably.",
                        details=caa_error,
                        module=self.slug,
                    )
                )
            elif caa_records:
                results.append(
                    CheckResult(
                        name="domain-caa",
                        status="PASS",
                        severity="info",
                        summary="CAA records are present.",
                        details=", ".join(caa_records),
                        module=self.slug,
                    )
                )
            else:
                results.append(
                    CheckResult(
                        name="domain-caa",
                        status="WARN",
                        severity="low",
                        summary="No CAA records were found.",
                        details="CAA records help restrict which certificate authorities may issue certificates for the domain.",
                        module=self.slug,
                    )
                )

        security_response = await client.request(context.url("/.well-known/security.txt"))
        if security_response.status != 200:
            security_response = await client.request(context.url("/security.txt"))
        if security_response.status == 200:
            lower_body = security_response.body.lower()
            if "contact:" in lower_body:
                results.append(
                    CheckResult(
                        name="security-txt",
                        status="PASS",
                        severity="info",
                        summary="A security.txt file was found with contact information.",
                        details=security_response.url,
                        module=self.slug,
                    )
                )
            else:
                results.append(
                    CheckResult(
                        name="security-txt",
                        status="WARN",
                        severity="low",
                        summary="A security.txt file was found but no Contact field was detected.",
                        details=security_response.url,
                        module=self.slug,
                    )
                )
        else:
            results.append(
                CheckResult(
                    name="security-txt",
                    status="WARN",
                    severity="low",
                    summary="No security.txt file was found.",
                    details="Checked /.well-known/security.txt and /security.txt",
                    module=self.slug,
                )
            )

        return results

    @staticmethod
    async def _safe_lookup(host: str, record_type: str) -> tuple[list[str], str | None]:
        if dns is None:
            return [], None
        try:
            return await _lookup_records(host, record_type), None
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):  # type: ignore[attr-defined]
            return [], None
        except Exception as exc:  # noqa: BLE001
            return [], str(exc)
