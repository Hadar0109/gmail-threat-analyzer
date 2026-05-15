"""Map internal detector reasons to concise technical copy for More details (presentation only)."""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.explain.synthesis import ResolvedSignal
from app.schemas import MessageAuthentication, ReputationSummary

_PASS_AUTH = frozenset({"pass"})
_SKIP_REP = frozenset(
    {
        "skipped_no_api_key",
        "skipped_no_urls",
        "skipped_budget",
        "skipped_cooldown",
    },
)


@dataclass(frozen=True, slots=True)
class _Finding:
    group_id: str
    dedupe_key: str
    message: str
    priority: int = 50


def collect_technical_findings(
    resolved: list[ResolvedSignal],
    technical_reasons: list[str],
    *,
    reputation: ReputationSummary | None,
    authentication: MessageAuthentication | None,
) -> dict[str, tuple[str, ...]]:
    """Return deduplicated technical bullets keyed by detail group id."""
    findings: list[_Finding] = []

    for text in technical_reasons:
        mapped = _map_technical_reason(text)
        if mapped is not None:
            findings.extend(mapped)

    findings.extend(_authentication_from_summary(authentication))
    findings.extend(_reputation_findings(reputation))

    # Resolved rows can surface auth/link themes not present in trimmed reason lists.
    for row in resolved:
        findings.extend(_map_technical_reason(row.technical) or ())

    return _finalize_groups(findings)


def _finalize_groups(findings: list[_Finding]) -> dict[str, tuple[str, ...]]:
    by_group: dict[str, dict[str, _Finding]] = {}
    for item in findings:
        by_group.setdefault(item.group_id, {})
        existing = by_group[item.group_id].get(item.dedupe_key)
        if existing is None or item.priority > existing.priority:
            by_group[item.group_id][item.dedupe_key] = item

    out: dict[str, tuple[str, ...]] = {}
    for group_id, keyed in by_group.items():
        ordered = sorted(keyed.values(), key=lambda f: (-f.priority, f.message))
        out[group_id] = tuple(f.message for f in ordered[:8])
    return out


def _authentication_from_summary(
    authentication: MessageAuthentication | None,
) -> list[_Finding]:
    if authentication is None:
        return []

    spf = (authentication.spf or "").strip().lower()
    dkim = (authentication.dkim or "").strip().lower()
    dmarc = (authentication.dmarc or "").strip().lower()

    if not spf and not dkim and not dmarc:
        return [
            _Finding(
                "authentication",
                "auth:no_summary",
                "No SPF/DKIM/DMARC authentication results were provided",
                priority=40,
            ),
        ]

    if spf in _PASS_AUTH and dkim in _PASS_AUTH and dmarc in _PASS_AUTH:
        return []

    findings: list[_Finding] = []
    findings.extend(_auth_mechanism("spf", spf))
    findings.extend(_auth_mechanism("dkim", dkim))
    findings.extend(_auth_mechanism("dmarc", dmarc))

    if not dkim:
        findings.append(
            _Finding(
                "authentication",
                "auth:dkim_missing",
                "DKIM signature missing",
                priority=70,
            ),
        )

    return findings


def _auth_mechanism(name: str, value: str) -> list[_Finding]:
    if not value or value in _PASS_AUTH:
        return []
    if value == "fail":
        labels = {
            "spf": "SPF validation failed",
            "dkim": "DKIM signature verification failed",
            "dmarc": "DMARC policy check failed",
        }
        return [
            _Finding(
                "authentication",
                f"auth:{name}_fail",
                labels[name],
                priority=90,
            ),
        ]
    if value == "softfail" and name == "spf":
        return [
            _Finding(
                "authentication",
                "auth:spf_softfail",
                "SPF returned softfail (sender not fully authorized)",
                priority=75,
            ),
        ]
    if value in {"neutral", "none"}:
        return [
            _Finding(
                "authentication",
                f"auth:{name}_{value}",
                f"{name.upper()} returned {value!r} (no strong pass/fail signal)",
                priority=35,
            ),
        ]
    if value in {"temperror", "permerror"}:
        return [
            _Finding(
                "authentication",
                f"auth:{name}_{value}",
                f"{name.upper()} returned {value} (authentication lookup error)",
                priority=55,
            ),
        ]
    return [
        _Finding(
            "authentication",
            f"auth:{name}_other",
            f"{name.upper()} returned an uncommon result ({value!r})",
            priority=45,
        ),
    ]


def _reputation_findings(reputation: ReputationSummary | None) -> list[_Finding]:
    if reputation is None or not reputation.providers:
        return []

    findings: list[_Finding] = []
    for provider, status in reputation.providers.items():
        finding = _reputation_provider_finding(provider, status, contributed=reputation.contributed)
        if finding is not None:
            findings.append(finding)
    return findings


def _reputation_provider_finding(
    provider: str,
    status: str,
    *,
    contributed: bool,
) -> _Finding | None:
    raw = (status or "").strip().lower()
    if not raw or raw in _SKIP_REP:
        return None

    if provider == "safe_browsing":
        if raw == "threat":
            return _Finding(
                "reputation",
                "rep:safe_browsing",
                "Google Safe Browsing flagged the URL",
                priority=98,
            )
        if raw.startswith("error"):
            return _Finding(
                "reputation",
                "rep:safe_browsing",
                "Google Safe Browsing lookup unavailable",
                priority=30,
            )
        if contributed and raw == "clean":
            return _Finding(
                "reputation",
                "rep:safe_browsing",
                "Google Safe Browsing: no threats reported",
                priority=10,
            )
        return None

    if provider == "virustotal":
        if raw == "malicious":
            return _Finding(
                "reputation",
                "rep:virustotal",
                "VirusTotal reported malicious detections",
                priority=96,
            )
        if raw == "suspicious":
            return _Finding(
                "reputation",
                "rep:virustotal",
                "VirusTotal reported suspicious detections",
                priority=88,
            )
        if raw.startswith("error"):
            return _Finding(
                "reputation",
                "rep:virustotal",
                "VirusTotal lookup unavailable",
                priority=30,
            )
        if contributed and raw in {"clean", "not_found"}:
            return _Finding(
                "reputation",
                "rep:virustotal",
                "VirusTotal: no known reports",
                priority=10,
            )
        return None

    return None


def _quoted_filename(text: str) -> str | None:
    match = re.search(r"'([^']+)'", text)
    if match:
        return match.group(1)
    match = re.search(r'"([^"]+)"', text)
    return match.group(1) if match else None


def _map_technical_reason(text: str) -> tuple[_Finding, ...] | None:
    raw = text.strip()
    if not raw:
        return None
    lower = raw.lower()

    # --- Authentication (exact / pattern on internal strings) ---
    if lower.startswith("spf result was 'fail'"):
        return (
            _Finding(
                "authentication",
                "auth:spf_fail",
                "SPF validation failed",
                priority=90,
            ),
        )
    if lower.startswith("dkim result was 'fail'"):
        return (
            _Finding(
                "authentication",
                "auth:dkim_fail",
                "DKIM signature verification failed",
                priority=90,
            ),
        )
    if lower.startswith("dmarc result was 'fail'"):
        return (
            _Finding(
                "authentication",
                "auth:dmarc_fail",
                "DMARC policy check failed",
                priority=90,
            ),
        )
    if "spf reported 'softfail'" in lower:
        return (
            _Finding(
                "authentication",
                "auth:spf_softfail",
                "SPF returned softfail (sender not fully authorized)",
                priority=75,
            ),
        )
    if "no spf/dkim/dmarc summary was provided" in lower:
        return (
            _Finding(
                "authentication",
                "auth:no_summary",
                "No SPF/DKIM/DMARC authentication results were provided",
                priority=40,
            ),
        )
    if "spf, dkim, and dmarc all reported pass" in lower:
        return ()
    if "authentication summary present without explicit failures" in lower:
        return ()

    # --- Attachments ---
    filename = _quoted_filename(raw)
    if "double extension trick" in lower:
        name = filename or "attachment"
        return (
            _Finding(
                "attachments",
                f"att:double_ext:{name.lower()}",
                f"Double-extension attachment detected: {name}",
                priority=92,
            ),
        )
    if "macro-enabled office attachment" in lower:
        name = filename or "attachment"
        return (
            _Finding(
                "attachments",
                f"att:macro:{name.lower()}",
                f"Macro-enabled Office document detected: {name}",
                priority=90,
            ),
        )
    if "potentially executable attachment" in lower:
        name = filename or "attachment"
        return (
            _Finding(
                "attachments",
                f"att:executable:{name.lower()}",
                f"Potentially executable attachment detected: {name}",
                priority=88,
            ),
        )
    if "archive attachment may hide malware" in lower:
        name = filename or "attachment"
        return (
            _Finding(
                "attachments",
                f"att:archive:{name.lower()}",
                f"Archive attachment may conceal payloads: {name}",
                priority=80,
            ),
        )
    if "password protection" in lower and "archive" in lower:
        name = filename or "attachment"
        return (
            _Finding(
                "attachments",
                f"att:password_archive:{name.lower()}",
                f"Password-protected archive attachment: {name}",
                priority=91,
            ),
        )
    if "html/svg attachment" in lower:
        name = filename or "attachment"
        return (
            _Finding(
                "attachments",
                f"att:html:{name.lower()}",
                f"HTML/SVG attachment can carry active content: {name}",
                priority=70,
            ),
        )
    if "business-themed filename with risky extension" in lower:
        name = filename or "attachment"
        return (
            _Finding(
                "attachments",
                f"att:lure_name:{name.lower()}",
                f"Payment-themed attachment with risky file type: {name}",
                priority=85,
            ),
        )
    if lower.startswith("large attachment"):
        name = filename or "attachment"
        return (
            _Finding(
                "attachments",
                f"att:large:{name.lower()}",
                f"Unusually large attachment: {name}",
                priority=45,
            ),
        )
    if "unusually high attachment count" in lower:
        return (
            _Finding(
                "attachments",
                "att:high_count",
                "High attachment count combined with risky file types",
                priority=65,
            ),
        )

    # --- Reputation (detector strings; provider rows handled separately) ---
    if "google safe browsing matched" in lower:
        return (
            _Finding(
                "reputation",
                "rep:safe_browsing",
                "Google Safe Browsing flagged the URL",
                priority=98,
            ),
        )
    if "virustotal reports multiple" in lower and "malicious" in lower:
        return (
            _Finding(
                "reputation",
                "rep:virustotal",
                "VirusTotal reported malicious detections",
                priority=96,
            ),
        )
    if "virustotal" in lower and "suspicious" in lower:
        return (
            _Finding(
                "reputation",
                "rep:virustotal",
                "VirusTotal reported suspicious detections",
                priority=88,
            ),
        )

    # --- Links ---
    if "uses http instead of https" in lower:
        return (
            _Finding(
                "links",
                "link:http",
                "Non-HTTPS link detected",
                priority=60,
            ),
        )
    if "resembles a login or verification endpoint" in lower:
        return (
            _Finding(
                "links",
                "link:login_path",
                "Login-style URL detected",
                priority=78,
            ),
        )
    if "path contains '@'" in lower:
        return (
            _Finding(
                "links",
                "link:at_sign",
                "URL path contains '@' (credential-phishing pattern)",
                priority=85,
            ),
        )
    if "embeds another http" in lower or "embeds a nested http" in lower:
        return (
            _Finding(
                "links",
                "link:nested_dest",
                "URL embeds a nested http(s) destination (redirect chain)",
                priority=80,
            ),
        )
    if "public shortener" in lower or "shortener, hiding" in lower:
        return (
            _Finding(
                "links",
                "link:shortener",
                "URL shortener hides the final destination",
                priority=72,
            ),
        )
    if "raw ip address" in lower:
        return (
            _Finding(
                "links",
                "link:ip_host",
                "Link points to a raw IP address instead of a hostname",
                priority=82,
            ),
        )
    if "punycode" in lower or "idn" in lower:
        return (
            _Finding(
                "links",
                "link:idn",
                "IDN/punycode hostname may mimic a trusted domain",
                priority=76,
            ),
        )
    if "abused tld" in lower:
        return (
            _Finding(
                "links",
                "link:abused_tld",
                "Link uses a frequently abused top-level domain",
                priority=68,
            ),
        )
    if "no recognizable host" in lower:
        return (
            _Finding(
                "links",
                "link:no_host",
                "Malformed or unparseable link host",
                priority=70,
            ),
        )
    if "outside the sender domain" in lower or "off-domain links" in lower:
        return (
            _Finding(
                "links",
                "link:off_domain",
                "Link host is outside the sender From domain",
                priority=74,
            ),
        )
    if "body references" in lower and "link host" in lower and "not on an official" in lower:
        return (
            _Finding(
                "sender_identity",
                "sender:brand_domain_mismatch",
                "Claimed brand does not match the sender domain",
                priority=86,
            ),
        )
    if "multiple high-risk urls" in lower:
        return (
            _Finding(
                "links",
                "link:multi_high_risk",
                "Multiple high-risk URLs detected",
                priority=77,
            ),
        )

    # --- Sender identity ---
    if lower.startswith("reply-to domain"):
        return (
            _Finding(
                "sender_identity",
                "sender:reply_to_drift",
                "Reply-To domain differs from the From domain",
                priority=88,
            ),
        )
    if "long all-caps string" in lower:
        return (
            _Finding(
                "sender_identity",
                "sender:display_caps",
                "Display name is an unusually long ALL-CAPS string",
                priority=55,
            ),
        )
    if "senior-role title" in lower:
        return (
            _Finding(
                "sender_identity",
                "sender:exec_title",
                "Display name includes an executive title used in impersonation",
                priority=58,
            ),
        )
    if "closely resembles" in lower and "phishing trick" in lower:
        return (
            _Finding(
                "sender_identity",
                "sender:lookalike_domain",
                "From domain is a lookalike of a known brand domain",
                priority=90,
            ),
        )
    if "confusable characters" in lower:
        return (
            _Finding(
                "sender_identity",
                "sender:confusable_domain",
                "From domain uses confusable characters (homoglyph risk)",
                priority=88,
            ),
        )
    if "punycode/idn" in lower and "from domain" in lower:
        return (
            _Finding(
                "sender_identity",
                "sender:from_idn",
                "From domain uses punycode/IDN (lookalike-domain risk)",
                priority=86,
            ),
        )
    if "display name references" in lower and "not from" in lower:
        return (
            _Finding(
                "sender_identity",
                "sender:brand_domain_mismatch",
                "Claimed brand does not match the sender domain",
                priority=84,
            ),
        )
    if "corporate-style display name with consumer mail host" in lower:
        return (
            _Finding(
                "sender_identity",
                "sender:consumer_host",
                "Corporate display name sent from a consumer mail provider",
                priority=70,
            ),
        )
    if "message body mentions" in lower and "not on an official domain" in lower:
        return (
            _Finding(
                "sender_identity",
                "sender:brand_domain_mismatch",
                "Claimed brand does not match the sender domain",
                priority=72,
            ),
        )
    if "embeds brand-like label" in lower:
        return (
            _Finding(
                "sender_identity",
                "sender:subdomain_deception",
                "From domain embeds a brand label on an unrelated registered domain",
                priority=87,
            ),
        )
    if "brand" in lower and "sender domain is not authorized" in lower:
        return (
            _Finding(
                "sender_identity",
                "sender:brand_domain_mismatch",
                "Claimed brand does not match the sender domain",
                priority=80,
            ),
        )

    return None
