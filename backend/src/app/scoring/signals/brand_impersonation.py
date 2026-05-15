"""Brand impersonation and domain-deception heuristics."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from app.schemas import ScoreRequest
from app.scoring.features.brands import (
    display_name_mentions_brand,
    extract_brand_mentions,
    is_foreign_brand_sender,
    load_brand_registry,
    sender_domain_authorized,
    url_host_matches_brand,
)
from app.scoring.features.domains import (
    domain_from_address,
    is_free_mail_domain,
    normalize_hostname,
    registrable_domain,
)
from app.scoring.features.emails import domain_has_punycode
from app.scoring.features.homoglyphs import domains_lookalike
from app.scoring.signals.content._base import scoring_blob
from app.scoring.types import Finding, SignalChunk

_SUBDOMAIN_DECEPTION = re.compile(
    r"^(?P<brand>[a-z0-9-]+)\.(?P<rest>[a-z0-9.-]+\.[a-z]{2,})$",
    re.I,
)


def _text_blob(req: ScoreRequest) -> str:
    return scoring_blob(req)


def _collect_findings(req: ScoreRequest) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    from_domain = domain_from_address(req.from_email)
    from_reg = registrable_domain(from_domain) if from_domain else None
    display = (req.display_name or "").strip()
    blob = _text_blob(req)

    if from_domain and domain_has_punycode(from_domain):
        findings.append(
            Finding(
                tag="homoglyph_domain",
                severity="high",
                reason=(
                    f"From domain uses punycode/IDN ({from_domain}), which can disguise look-alike names."
                ),
            ),
        )

    if from_domain and any(ch in from_domain for ch in _CONFUSABLE_CHARS):
        findings.append(
            Finding(
                tag="homoglyph_domain",
                severity="high",
                reason="From domain contains confusable characters that mimic a trusted brand.",
            ),
        )

    if from_reg:
        for brand in load_brand_registry():
            for canonical in brand.domains:
                canon_reg = registrable_domain(canonical) or canonical
                if from_reg == canon_reg:
                    continue
                if domains_lookalike(from_reg, canon_reg):
                    findings.append(
                        Finding(
                            tag="lookalike_domain",
                            severity="high",
                            reason=(
                                f"From domain {from_reg!r} closely resembles "
                                f"{canon_reg!r} ({brand.id}), a common phishing trick."
                            ),
                        ),
                    )
                    break

    for brand in display_name_mentions_brand(display):
        if is_foreign_brand_sender(brand, from_domain):
            findings.append(
                Finding(
                    tag="display_name_brand_mismatch",
                    severity="high",
                    reason=(
                        f"Display name references {brand.names[0]!r} but the message is not from "
                        f"an official {brand.id} domain."
                    ),
                ),
            )

    if display and from_domain and is_free_mail_domain(from_domain):
        for brand in display_name_mentions_brand(display):
            findings.append(
                Finding(
                    tag="display_name_brand_mismatch",
                    severity="medium",
                    reason=(
                        f"Corporate-style display name with consumer mail host ({from_domain})."
                    ),
                ),
            )
            break

    for brand in extract_brand_mentions(blob):
        if is_foreign_brand_sender(brand, from_domain):
            findings.append(
                Finding(
                    tag="brand_mention_foreign_sender",
                    severity="medium",
                    reason=(
                        f"Message body mentions {brand.names[0]!r} but sender "
                        f"{from_domain or 'unknown'} is not on an official domain."
                    ),
                ),
            )

    if from_reg:
        host = from_reg
        match = _SUBDOMAIN_DECEPTION.match(host)
        if match:
            prefix = match.group("brand").lower()
            for brand in load_brand_registry():
                if any(prefix in n.replace(" ", "") for n in brand.names):
                    findings.append(
                        Finding(
                            tag="subdomain_deception",
                            severity="high",
                            reason=(
                                f"From domain embeds brand-like label {prefix!r} before unrelated "
                                f"registrable domain {match.group('rest')!r}."
                            ),
                        ),
                    )
                    break

    mentioned = extract_brand_mentions(blob)
    for url in req.urls:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if not host:
            continue
        for brand in mentioned:
            if not url_host_matches_brand(host, brand):
                findings.append(
                    Finding(
                        tag="brand_url_mismatch",
                        severity="high",
                        reason=(
                            f"Body references {brand.names[0]!r} but link host {host!r} "
                            "is not on an official domain for that brand."
                        ),
                    ),
                )
                break

    for brand in mentioned:
        if display and brand in display_name_mentions_brand(display):
            if from_domain and not sender_domain_authorized(brand, from_domain):
                if not any(f.tag == "display_name_brand_mismatch" for f in findings):
                    findings.append(
                        Finding(
                            tag="display_name_brand_mismatch",
                            severity="medium",
                            reason=(
                                f"Brand {brand.id} appears in display and body but sender domain "
                                "is not authorized."
                            ),
                        ),
                    )

    return _dedupe_findings(findings)


# Cyrillic/Latin confusable subset mirrored from homoglyphs map keys.
_CONFUSABLE_CHARS = frozenset("аеорсухіӏɡℓⅰⓞ")


def _dedupe_findings(findings: list[Finding]) -> tuple[Finding, ...]:
    seen: set[str] = set()
    out: list[Finding] = []
    for f in findings:
        key = f"{f.tag}:{f.reason}"
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return tuple(out)


_SEVERITY_POINTS: dict[str, float] = {
    "low": 14.0,
    "medium": 28.0,
    "high": 44.0,
}


def evaluate_brand_impersonation(req: ScoreRequest) -> tuple[SignalChunk, tuple[Finding, ...]]:
    findings = _collect_findings(req)
    if not findings:
        return SignalChunk(0.0, ()), ()

    points = 0.0
    for finding in findings:
        points = max(points, _SEVERITY_POINTS.get(finding.severity, 20.0))

    # Stack moderate additional hits without dominating.
    extra = sum(
        _SEVERITY_POINTS.get(f.severity, 10.0) * 0.25
        for f in findings[1:]
    )
    points = min(100.0, points + extra)
    reasons = tuple(f.reason for f in findings)
    return SignalChunk(points, reasons), findings
