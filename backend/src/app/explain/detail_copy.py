"""Grouped, short copy for the collapsible More details section (presentation only)."""

from __future__ import annotations

from dataclasses import dataclass

from app.explain.synthesis import ResolvedSignal
from app.explain.types import SynthesisTheme
from app.schemas import MessageAuthentication, ReputationSummary, SignalBreakdown

# --- Authentication ---
AUTH_SENDER_INCOMPLETE = "Sender verification could not be completed"
AUTH_SPF_FAIL = "SPF validation failed for this sender"
AUTH_DKIM_FAIL = "DKIM validation failed for this sender"
AUTH_DMARC_FAIL = "DMARC validation did not pass for this sender"
AUTH_SPF_SOFTFAIL = "SPF reported a partial failure for this sender"
AUTH_NEUTRAL = "Sender authentication returned inconclusive results"

# --- Link checks ---
LINK_NON_SECURE = "Some links use non-secure connections"
LINK_SAFE_BROWSING = "Google Safe Browsing flagged one of the links as suspicious"
LINK_VIRUSTOTAL = "VirusTotal reported suspicious activity related to a linked domain"
LINK_EXTERNAL_HOST = "A link points to a website outside the sender's organization"
LINK_SHORTENER = "A link uses a shortener that hides the final destination"
LINK_REPUTATION_ELEVATED = "External link checks reported elevated caution for a URL"

_PASS_AUTH = frozenset({"pass"})
_SKIP_REP = frozenset(
    {
        "skipped_no_api_key",
        "skipped_no_urls",
        "skipped_budget",
        "skipped_cooldown",
    },
)
_CLEAN_REP = frozenset({"clean", "not_found"})


@dataclass(frozen=True, slots=True)
class DetailGroup:
    group_id: str
    label: str
    items: tuple[str, ...]


def build_detail_groups(
    resolved: list[ResolvedSignal],
    technical_reasons: list[str],
    *,
    reputation: ReputationSummary | None,
    authentication: MessageAuthentication | None,
    signals: SignalBreakdown | None,
) -> tuple[DetailGroup, ...]:
    """Build filtered, deduplicated detail groups for the add-on."""
    auth_items = _authentication_items(resolved, technical_reasons, authentication)
    link_items = _link_items(resolved, technical_reasons, reputation)
    signal_items = _signal_items(signals)

    groups: list[DetailGroup] = []
    if auth_items:
        groups.append(DetailGroup("authentication", "Authentication", auth_items))
    if link_items:
        groups.append(DetailGroup("link_checks", "Link checks", link_items))
    if signal_items:
        groups.append(DetailGroup("signal_scores", "Signal scores", signal_items))
    return tuple(groups)


def _authentication_items(
    resolved: list[ResolvedSignal],
    technical_reasons: list[str],
    authentication: MessageAuthentication | None,
) -> tuple[str, ...]:
    found: set[str] = set()
    out: list[str] = []

    def add(msg: str) -> None:
        if msg not in found:
            found.add(msg)
            out.append(msg)

    texts = [r.technical for r in resolved if r.theme == SynthesisTheme.AUTH_CHECK]
    texts.extend(
        t
        for t in technical_reasons
        if any(k in t.lower() for k in ("spf", "dkim", "dmarc", "authentication"))
    )

    for text in texts:
        lower = text.lower()
        if "spf" in lower and "fail" in lower:
            add(AUTH_SPF_FAIL)
        elif "dkim" in lower and "fail" in lower:
            add(AUTH_DKIM_FAIL)
        elif "dmarc" in lower and "fail" in lower:
            add(AUTH_DMARC_FAIL)
        elif "softfail" in lower:
            add(AUTH_SPF_SOFTFAIL)
        elif "neutral" in lower or "none" in lower or "no spf/dkim/dmarc summary" in lower:
            add(AUTH_SENDER_INCOMPLETE)
        elif "temperror" in lower or "permerror" in lower or "uncommon" in lower:
            add(AUTH_NEUTRAL)

    if authentication is not None:
        spf = (authentication.spf or "").strip().lower()
        dkim = (authentication.dkim or "").strip().lower()
        dmarc = (authentication.dmarc or "").strip().lower()
        if spf == "fail":
            add(AUTH_SPF_FAIL)
        elif spf == "softfail":
            add(AUTH_SPF_SOFTFAIL)
        if dkim == "fail":
            add(AUTH_DKIM_FAIL)
        if dmarc == "fail":
            add(AUTH_DMARC_FAIL)
        if not (spf in _PASS_AUTH and dkim in _PASS_AUTH and dmarc in _PASS_AUTH):
            if not spf and not dkim and not dmarc:
                add(AUTH_SENDER_INCOMPLETE)
            elif spf not in _PASS_AUTH or dkim not in _PASS_AUTH or dmarc not in _PASS_AUTH:
                if not out:
                    add(AUTH_SENDER_INCOMPLETE)

    return tuple(out[:6])


def _link_items(
    resolved: list[ResolvedSignal],
    technical_reasons: list[str],
    reputation: ReputationSummary | None,
) -> tuple[str, ...]:
    found: set[str] = set()
    out: list[str] = []

    def add(msg: str) -> None:
        if msg not in found:
            found.add(msg)
            out.append(msg)

    http_seen = False
    for text in technical_reasons:
        lower = text.lower()
        if not http_seen and (
            "http instead of https" in lower
            or "non-secure" in lower
            or ("http://" in lower and "https" not in lower.split("http")[0])
        ):
            add(LINK_NON_SECURE)
            http_seen = True
        if "shortener" in lower:
            add(LINK_SHORTENER)
        if "outside the sender domain" in lower or "external registrable" in lower:
            add(LINK_EXTERNAL_HOST)

    for row in resolved:
        if row.theme == SynthesisTheme.MALICIOUS_LINK:
            add(LINK_SAFE_BROWSING)
        t = row.technical.lower()
        if "safe browsing" in t:
            add(LINK_SAFE_BROWSING)
        if "virustotal" in t and any(k in t for k in ("malicious", "suspicious", "elevated")):
            add(LINK_VIRUSTOTAL)
        if row.theme == SynthesisTheme.TECHNICAL_DETAIL and "reputation" in t:
            add(LINK_REPUTATION_ELEVATED)

    if reputation and reputation.providers:
        sb = reputation.providers.get("safe_browsing", "")
        vt = reputation.providers.get("virustotal", "")
        if sb == "threat":
            add(LINK_SAFE_BROWSING)
        if vt in {"malicious", "suspicious"}:
            add(LINK_VIRUSTOTAL)
        if sb not in _SKIP_REP and sb not in _CLEAN_REP and sb.startswith("error"):
            add(LINK_REPUTATION_ELEVATED)

    return tuple(out[:8])


def _signal_items(signals: SignalBreakdown | None) -> tuple[str, ...]:
    if signals is None:
        return ()

    pairs = (
        ("Sender", signals.sender),
        ("Links", signals.urls),
        ("Content", signals.urgency),
        ("Headers", signals.headers),
        ("Attachments", signals.attachments),
        ("Link reputation", signals.reputation_overlay),
    )
    out: list[str] = []
    for label, value in pairs:
        score = int(round(value))
        if score > 0:
            out.append(f"{label}: {score}")
    return tuple(out)
