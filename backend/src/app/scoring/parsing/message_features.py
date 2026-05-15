"""Message feature extraction.

Responsible for building MessageFeatures from ScoreRequest for tests and future use.
Does not contribute directly to live scoring output today.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.schemas import ScoreRequest
from app.scoring.parsing.domains import domain_from_address
from app.scoring.parsing.emails import parse_email_address


@dataclass(frozen=True, slots=True)
class MessageFeatures:
    """Parsed message surface used by detectors and aggregation (not sent over the wire)."""

    from_email: str
    from_domain: str | None
    reply_to_email: str | None
    reply_to_domain: str | None
    display_name: str | None
    subject: str
    snippet: str
    scoring_text: str
    urls: tuple[str, ...]

    @classmethod
    def from_request(cls, req: ScoreRequest) -> MessageFeatures:
        from_parsed = parse_email_address(req.from_email)
        reply_parsed = parse_email_address(req.reply_to)

        body = (req.body_text_for_scoring or req.snippet or "").strip()
        subject = req.subject or ""
        if subject and body:
            scoring_text = f"{subject}\n{body}"
        elif subject:
            scoring_text = subject
        else:
            scoring_text = body

        return cls(
            from_email=from_parsed.address if from_parsed else req.from_email.strip().lower(),
            from_domain=from_parsed.domain if from_parsed else domain_from_address(req.from_email),
            reply_to_email=reply_parsed.address if reply_parsed else None,
            reply_to_domain=reply_parsed.domain if reply_parsed else domain_from_address(req.reply_to),
            display_name=(req.display_name or "").strip() or None,
            subject=subject,
            snippet=req.snippet or "",
            scoring_text=scoring_text,
            urls=tuple(req.urls),
        )
