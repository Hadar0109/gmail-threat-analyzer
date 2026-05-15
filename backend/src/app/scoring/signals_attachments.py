"""Attachment metadata heuristics — Phase 2 (no content inspection)."""

from __future__ import annotations

import re

from app.schemas import ScoreRequest
from app.scoring.aggregate import points_from_attachment_findings
from app.scoring.types import Finding, SignalChunk

_DANGEROUS_MIME = frozenset(
    {
        "application/x-msdownload",
        "application/x-dosexec",
        "application/x-msi",
        "application/x-executable",
        "application/x-msdos-program",
        "application/bat",
        "application/x-bat",
        "application/x-sh",
        "application/vnd.ms-excel.sheet.macroenabled.12",
        "application/vnd.ms-word.document.macroenabled.12",
        "application/vnd.ms-powerpoint.presentation.macroenabled.12",
    },
)

_DANGEROUS_SUFFIX = re.compile(
    r"\.(exe|scr|bat|cmd|com|pif|js|jse|vbs|vbe|ps1|msi|dll|jar)\b",
    re.I,
)

_DOUBLE_EXT = re.compile(
    r"\.[a-z0-9]{2,5}\.(exe|zip|scr|bat|cmd|msi|js|jar|pdf|doc)\b",
    re.I,
)

_ARCHIVE_SUFFIX = re.compile(r"\.(zip|rar|7z|iso|tar|gz|bz2)\b", re.I)
_MACRO_SUFFIX = re.compile(r"\.(docm|xlsm|pptm)\b", re.I)
_HTML_SVG_SUFFIX = re.compile(r"\.(html?|svg)\b", re.I)
_PASSWORD_HINT = re.compile(r"\b(pass(word)?|pwd|protected|encrypted|unlock)\b", re.I)
_LURE_NAME = re.compile(r"\b(invoice|payment|wire|statement|remittance|payroll)\b", re.I)
_FAKE_PDF = re.compile(r"\.pdf\.(html?|htm|zip|exe|js)\b", re.I)
_FAKE_DOC = re.compile(r"\.(docx?|xlsx?)\.(html?|zip|exe|js)\b", re.I)

_RISKY_ATTACHMENT_TAGS = frozenset(
    {
        "executable_attachment",
        "double_extension",
        "archive_attachment",
        "macro_attachment",
        "password_protected_archive",
        "misleading_attachment_name",
        "html_svg_attachment",
    },
)


def _attachment_findings(req: ScoreRequest) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    risky_count = 0
    total_size = 0

    for att in req.attachments:
        name = att.filename.lower()
        mime = att.mime_type.lower()
        if att.size_bytes:
            total_size += att.size_bytes

        if mime in _DANGEROUS_MIME or _DANGEROUS_SUFFIX.search(name):
            risky_count += 1
            findings.append(
                Finding(
                    tag="executable_attachment",
                    severity="high",
                    reason=f"Potentially executable attachment metadata: {att.filename!r}.",
                ),
            )

        if _DOUBLE_EXT.search(name):
            risky_count += 1
            findings.append(
                Finding(
                    tag="double_extension",
                    severity="high",
                    reason=f"Filename suggests a double extension trick: {att.filename!r}.",
                ),
            )

        if _ARCHIVE_SUFFIX.search(name):
            risky_count += 1
            findings.append(
                Finding(
                    tag="archive_attachment",
                    severity="medium",
                    reason=f"Archive attachment may hide malware: {att.filename!r}.",
                ),
            )

        if _MACRO_SUFFIX.search(name) or "macroenabled" in mime:
            risky_count += 1
            findings.append(
                Finding(
                    tag="macro_attachment",
                    severity="high",
                    reason=f"Macro-enabled Office attachment: {att.filename!r}.",
                ),
            )

        if _ARCHIVE_SUFFIX.search(name) and _PASSWORD_HINT.search(name):
            risky_count += 1
            findings.append(
                Finding(
                    tag="password_protected_archive",
                    severity="high",
                    reason=(
                        f"Archive filename hints at password protection ({att.filename!r}), "
                        "common in invoice fraud."
                    ),
                ),
            )

        if _HTML_SVG_SUFFIX.search(name):
            risky_count += 1
            findings.append(
                Finding(
                    tag="html_svg_attachment",
                    severity="medium",
                    reason=f"HTML/SVG attachment can carry phishing payloads: {att.filename!r}.",
                ),
            )

        if _LURE_NAME.search(name) and (
            _HTML_SVG_SUFFIX.search(name)
            or _FAKE_PDF.search(name)
            or _FAKE_DOC.search(name)
            or _DANGEROUS_SUFFIX.search(name)
        ):
            risky_count += 1
            findings.append(
                Finding(
                    tag="misleading_attachment_name",
                    severity="high",
                    reason=(
                        f"Business-themed filename with risky extension: {att.filename!r}."
                    ),
                ),
            )

        if att.size_bytes is not None and att.size_bytes > 25 * 1024 * 1024:
            findings.append(
                Finding(
                    tag="large_attachment",
                    severity="low",
                    reason=f"Large attachment ({att.filename}) increases risk surface.",
                ),
            )

    if len(req.attachments) > 5 and (risky_count > 0 or total_size > 8 * 1024 * 1024):
        findings.append(
            Finding(
                tag="high_attachment_count",
                severity="low",
                reason="Unusually high attachment count combined with risky or large files.",
            ),
        )

    return _dedupe_findings(findings)


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


def evaluate_attachments(req: ScoreRequest) -> SignalChunk:
    if not req.attachments:
        return SignalChunk(0.0, ())

    findings = _attachment_findings(req)
    points = points_from_attachment_findings(findings)
    reasons = tuple(f.reason for f in findings)
    return SignalChunk(points, reasons)


def attachment_findings(req: ScoreRequest) -> tuple[Finding, ...]:
    """Expose attachment tags for the combo engine."""
    if not req.attachments:
        return ()
    return _attachment_findings(req)


def attachment_tags(req: ScoreRequest) -> frozenset[str]:
    return frozenset(f.tag for f in attachment_findings(req))
