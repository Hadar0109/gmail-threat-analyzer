"""Attachment metadata heuristics — Phase 2 (no content inspection)."""

from __future__ import annotations

import re

from app.schemas import ScoreRequest
from app.scoring.types import SignalChunk

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
    },
)

_DANGEROUS_SUFFIX = re.compile(r"\.(exe|scr|bat|cmd|com|pif|js|jse|vbs|vbe|ps1|msi|dll|jar)\b", re.I)

_DOUBLE_EXT = re.compile(r"\.[a-z0-9]{2,5}\.(exe|zip|scr|bat|cmd|msi|js|jar)\b", re.I)


def evaluate_attachments(req: ScoreRequest) -> SignalChunk:
    if not req.attachments:
        return SignalChunk(0.0, ())

    reasons: list[str] = []
    points = 0.0

    if len(req.attachments) > 5:
        points += 14.0
        reasons.append("Unusually high attachment count for a typical thread.")

    for att in req.attachments:
        name = att.filename.lower()
        mime = att.mime_type.lower()

        if mime in _DANGEROUS_MIME or _DANGEROUS_SUFFIX.search(name):
            points += 42.0
            reasons.append(f"Potentially executable attachment metadata: {att.filename!r}.")

        if _DOUBLE_EXT.search(name):
            points += 40.0
            reasons.append(f"Filename suggests a double extension trick: {att.filename!r}.")

        if att.size_bytes is not None and att.size_bytes > 25 * 1024 * 1024:
            points += 12.0
            reasons.append(f"Large attachment ({att.filename}) increases risk surface.")

    return SignalChunk(min(100.0, points), tuple(dict.fromkeys(reasons)))
