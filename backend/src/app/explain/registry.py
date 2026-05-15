"""Central registry mapping internal detector reasons to user-facing copy.

Responsible for deterministic reason → (category, severity, message, guidance) lookup.
Does not run detectors or alter scores.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.explain.types import ExplanationCategory, ExplanationSeverity

_SEV = ExplanationSeverity
_CAT = ExplanationCategory


@dataclass(frozen=True, slots=True)
class ExplanationSpec:
    category: ExplanationCategory
    severity: ExplanationSeverity
    message: str
    guidance: str | None = None


def _spec(
    category: ExplanationCategory,
    severity: ExplanationSeverity,
    message: str,
    *,
    guidance: str | None = None,
) -> ExplanationSpec:
    return ExplanationSpec(category, severity, message, guidance)


# --- Exact-match entries (technical reason string → user copy) ---

EXACT: dict[str, ExplanationSpec] = {
    # Headers / authentication
    "No SPF/DKIM/DMARC summary was provided; header authentication was not scored "
    "beyond a conservative baseline.": _spec(
        _CAT.SENDER_IDENTITY,
        _SEV.LOW,
        "We could not verify who sent this email using standard sender checks.",
        guidance="If the message looks important, confirm the sender through another channel.",
    ),
    "SPF, DKIM, and DMARC all reported pass in the summarized authentication results.": _spec(
        _CAT.SENDER_IDENTITY,
        _SEV.LOW,
        "Sender checks suggest this message passed common email authenticity tests.",
    ),
    "Authentication summary present without explicit failures; "
    "a small residual uncertainty remains.": _spec(
        _CAT.SENDER_IDENTITY,
        _SEV.LOW,
        "Sender checks did not show a clear failure, but the results were incomplete.",
    ),
    # Sender
    "Display name is an unusually long all-caps string.": _spec(
        _CAT.SENDER_IDENTITY,
        _SEV.MEDIUM,
        "The sender name looks unusual and may be trying to get your attention.",
    ),
    "Display name contains a senior-role title often abused in impersonation.": _spec(
        _CAT.SENDER_IDENTITY,
        _SEV.MEDIUM,
        "The sender name includes an executive title that scammers sometimes copy.",
        guidance="Confirm urgent requests from executives using a known phone number or chat.",
    ),
    # URLs (static)
    "URL has no recognizable host.": _spec(
        _CAT.LINKS_WEBSITES,
        _SEV.MEDIUM,
        "A link in this message does not point to a normal website address.",
        guidance="Avoid clicking links until you verify the sender.",
    ),
    "URL host is a raw IP address, uncommon for legitimate marketing mail.": _spec(
        _CAT.LINKS_WEBSITES,
        _SEV.HIGH,
        "A link uses a numeric web address instead of a familiar company website.",
        guidance="Avoid clicking links in this message until you verify the sender.",
    ),
    "Hostname uses punycode (IDN), which can hide look-alike domains.": _spec(
        _CAT.LINKS_WEBSITES,
        _SEV.MEDIUM,
        "A link may use special characters to mimic a trusted website name.",
        guidance="Check the sender before opening links.",
    ),
    "Link uses a public shortener, hiding the final destination.": _spec(
        _CAT.LINKS_WEBSITES,
        _SEV.MEDIUM,
        "A link hides its real destination behind a short link.",
        guidance="Avoid clicking shortened links unless you trust the sender.",
    ),
    "At least one URL uses HTTP instead of HTTPS.": _spec(
        _CAT.LINKS_WEBSITES,
        _SEV.LOW,
        "A link does not use a secure (HTTPS) connection.",
        guidance="Be cautious entering personal information on non-secure pages.",
    ),
    "URL path contains '@', sometimes used in credential phishing.": _spec(
        _CAT.LINKS_WEBSITES,
        _SEV.HIGH,
        "A link is formatted in a way often used to trick people into signing in.",
        guidance="Do not sign in through links in this email unless you verified the sender.",
    ),
    "URL path resembles a login or verification endpoint.": _spec(
        _CAT.LINKS_WEBSITES,
        _SEV.MEDIUM,
        "A link may lead to a sign-in or verification page.",
        guidance="Go to the company's website directly instead of using email links.",
    ),
    "URL appears to embed a nested http(s) prefix.": _spec(
        _CAT.LINKS_WEBSITES,
        _SEV.HIGH,
        "A link is structured in an unusual way that can hide the real website.",
        guidance="Avoid clicking links in this message until you verify the sender.",
    ),
    # Brand
    "From domain contains confusable characters that mimic a trusted brand.": _spec(
        _CAT.SENDER_IDENTITY,
        _SEV.HIGH,
        "The message may be pretending to be a trusted company.",
        guidance="Compare the sender address carefully with official contact details.",
    ),
    # Reputation
    "Google Safe Browsing matched at least one URL against a known threat list.": _spec(
        _CAT.REPUTATION,
        _SEV.CRITICAL,
        "A link in this email was reported as unsafe by Google's threat database.",
        guidance="Do not click links or download files from this message.",
    ),
    "VirusTotal reports multiple antivirus engines flagging at least one URL as malicious.": _spec(
        _CAT.REPUTATION,
        _SEV.CRITICAL,
        "A link in this email was flagged as malicious by multiple security scanners.",
        guidance="Do not click links or download files from this message.",
    ),
    "VirusTotal shows elevated suspicious verdicts for at least one URL.": _spec(
        _CAT.REPUTATION,
        _SEV.HIGH,
        "A link in this email has raised suspicion in external security checks.",
        guidance="Avoid clicking links until you verify the sender.",
    ),
    "VirusTotal shows a small number of suspicious verdicts for at least one URL.": _spec(
        _CAT.REPUTATION,
        _SEV.MEDIUM,
        "A link received a few caution flags from external security checks.",
        guidance="Treat links with extra care before clicking.",
    ),
    # Compose / system overlays
    "External reputation flagged a link, but the sender and authentication alignment "
    "were treated as trusted transactional mail so reputation did not force a high severity floor.": _spec(
        _CAT.SYSTEM,
        _SEV.LOW,
        "A link was flagged externally, but the sender looked like routine business mail so the score stayed moderated.",
    ),
    "External reputation reported high-severity link signals; overall severity reflects at least elevated danger.": _spec(
        _CAT.REPUTATION,
        _SEV.HIGH,
        "External link checks reported serious warning signs that increased the overall risk.",
        guidance="Avoid clicking links until you verify the sender.",
    ),
    "SPF, DKIM, and DMARC all passed, so urgency-style wording alone was weighted more cautiously.": _spec(
        _CAT.SYSTEM,
        _SEV.LOW,
        "The message passed sender checks, so urgent wording alone did not raise the score as much.",
    ),
    "Peak severity was limited because urgency language dominated without enough corroborating link or sender risk.": _spec(
        _CAT.SYSTEM,
        _SEV.LOW,
        "The score was capped because pressure language appeared without enough other warning signs.",
    ),
    "No strong risk patterns matched; score mostly reflects conservative baselines and weak signals.": _spec(
        _CAT.SYSTEM,
        _SEV.LOW,
        "No strong warning patterns stood out; the score reflects cautious defaults.",
    ),
    "Review links and sender context manually before taking action.": _spec(
        _CAT.SYSTEM,
        _SEV.LOW,
        "When in doubt, confirm who sent this message before clicking links or replying.",
    ),
    # Combo rules (exact strings from combos/rules.py)
    "Payment or wire language combined with identity mismatch signals.": _spec(
        _CAT.SENSITIVE_REQUESTS,
        _SEV.HIGH,
        "The message asks for payment while the sender identity looks inconsistent.",
        guidance="Verify payment requests by phone or in person before sending money.",
    ),
    "Payment or invoice wording with executable or double-extension attachment.": _spec(
        _CAT.ATTACHMENTS,
        _SEV.CRITICAL,
        "Payment wording appears together with a risky attachment type.",
        guidance="Do not open attachments until you confirm the invoice is legitimate.",
    ),
    "Gift-card refund pressure with urgency and external or abusive-sender TLD cues.": _spec(
        _CAT.URGENCY_PRESSURE,
        _SEV.HIGH,
        "Refund pressure and urgent language appear together with suspicious links.",
        guidance="Legitimate refunds rarely ask for gift cards or rushed action by email.",
    ),
    "Invoice or remittance wording with a risky archive or macro attachment.": _spec(
        _CAT.ATTACHMENTS,
        _SEV.HIGH,
        "Invoice language appears with an attachment type often used in scams.",
        guidance="Confirm the invoice with the company using a known contact method.",
    ),
    "Invoice lure with password-hint archive attachment.": _spec(
        _CAT.ATTACHMENTS,
        _SEV.CRITICAL,
        "An invoice-style message includes a password-protected archive attachment.",
        guidance="Do not open the attachment or use a password from the email.",
    ),
    "Fake security notification with external link and brand impersonation cues.": _spec(
        _CAT.SENDER_IDENTITY,
        _SEV.CRITICAL,
        "The message may fake a security alert while pretending to be a trusted brand.",
        guidance="Sign in through the company's official app or website, not email links.",
    ),
    "Account verification or security-alert language with an external login-style link.": _spec(
        _CAT.LINKS_WEBSITES,
        _SEV.HIGH,
        "The message urges account action and includes a sign-in style link on another site.",
        guidance="Go to the service directly instead of using the email link.",
    ),
    "Generic security-team phrasing with credential language and an external link.": _spec(
        _CAT.SENDER_IDENTITY,
        _SEV.HIGH,
        "Generic security wording and sign-in prompts appear with an external link.",
        guidance="Do not enter passwords through links in this email.",
    ),
    "Credential request language with links to an external domain.": _spec(
        _CAT.SENSITIVE_REQUESTS,
        _SEV.HIGH,
        "The message asks you to sign in or verify while linking to an outside website.",
        guidance="Be careful sharing passwords or payment details in response to this email.",
    ),
    "Brand impersonation cues with external login-style links.": _spec(
        _CAT.SENDER_IDENTITY,
        _SEV.CRITICAL,
        "The message may be pretending to be a trusted company with a sign-in link elsewhere.",
        guidance="Avoid clicking links until you verify the sender.",
    ),
    "Credential language with brand-themed URLs on unrelated hosts.": _spec(
        _CAT.LINKS_WEBSITES,
        _SEV.HIGH,
        "Sign-in wording appears with links that do not match the company named in the message.",
        guidance="Go to the company's website directly instead of using email links.",
    ),
    "OTP or verification-code language with login-like URL paths.": _spec(
        _CAT.SENSITIVE_REQUESTS,
        _SEV.HIGH,
        "Verification-code language appears with a link that may ask you to sign in.",
        guidance="Never share one-time codes with anyone who contacts you by email.",
    ),
    "Payment pressure combined with urgency or security-alert wording.": _spec(
        _CAT.URGENCY_PRESSURE,
        _SEV.HIGH,
        "The message pressures you to pay quickly or cites a security problem.",
        guidance="Slow down and verify payment requests before acting.",
    ),
    "Raw IP link host combined with credential or payment language.": _spec(
        _CAT.LINKS_WEBSITES,
        _SEV.CRITICAL,
        "Payment or sign-in wording appears with a link to a numeric web address.",
        guidance="Do not click the link or share financial details.",
    ),
    "Payment instructions with Reply-To domain drift.": _spec(
        _CAT.SENDER_IDENTITY,
        _SEV.HIGH,
        "Payment instructions may go to a different email domain than the sender.",
        guidance="Confirm payment details using a trusted contact method.",
    ),
    "Authentication failure together with suspicious sender signals increased the combined risk score.": _spec(
        _CAT.SENDER_IDENTITY,
        _SEV.HIGH,
        "Sender checks failed while the sender identity also looked suspicious.",
        guidance="Treat this message with extra caution before replying or clicking links.",
    ),
    "Multiple moderate indicators together exceed isolated single-family risk.": _spec(
        _CAT.SYSTEM,
        _SEV.MEDIUM,
        "Several smaller warning signs together raised the overall concern level.",
    ),
    # Content — urgency
    "Message language stresses urgency.": _spec(
        _CAT.URGENCY_PRESSURE,
        _SEV.MEDIUM,
        "The message uses urgent language that can pressure you to act quickly.",
    ),
    "Demands immediate action.": _spec(
        _CAT.URGENCY_PRESSURE,
        _SEV.MEDIUM,
        "The message pushes you to act right away.",
        guidance="Pause and verify before responding to urgent requests.",
    ),
    "Uses generic 'click here' phrasing.": _spec(
        _CAT.URGENCY_PRESSURE,
        _SEV.LOW,
        "The message uses vague “click here” wording instead of clear context.",
    ),
    "Uses time-pressure phrasing.": _spec(
        _CAT.URGENCY_PRESSURE,
        _SEV.MEDIUM,
        "The message creates time pressure to respond.",
    ),
    "Sets a short response deadline.": _spec(
        _CAT.URGENCY_PRESSURE,
        _SEV.MEDIUM,
        "The message gives you very little time to respond.",
    ),
    # Content — credential
    "Asks to verify an account or identity.": _spec(
        _CAT.SENSITIVE_REQUESTS,
        _SEV.MEDIUM,
        "The message asks you to verify an account or identity.",
        guidance="Be careful sharing passwords or payment details in response to this email.",
    ),
    "Asks to verify login information.": _spec(
        _CAT.SENSITIVE_REQUESTS,
        _SEV.HIGH,
        "The message asks you to confirm login details.",
        guidance="Do not share passwords through email links.",
    ),
    "Requests a password reset or update.": _spec(
        _CAT.SENSITIVE_REQUESTS,
        _SEV.MEDIUM,
        "The message asks you to reset or update a password.",
        guidance="Reset passwords only through the official website or app.",
    ),
    "Prompts to sign in again.": _spec(
        _CAT.SENSITIVE_REQUESTS,
        _SEV.MEDIUM,
        "The message asks you to sign in again.",
        guidance="Go to the service directly instead of using the email link.",
    ),
    "Claims a session expired.": _spec(
        _CAT.SENSITIVE_REQUESTS,
        _SEV.MEDIUM,
        "The message says your session expired and you need to sign in.",
    ),
    "References unusual sign-in activity.": _spec(
        _CAT.SENSITIVE_REQUESTS,
        _SEV.MEDIUM,
        "The message warns about unusual sign-in activity.",
        guidance="Check your account through the official app, not email links.",
    ),
    "Asks to confirm credentials or login.": _spec(
        _CAT.SENSITIVE_REQUESTS,
        _SEV.HIGH,
        "The message asks you to confirm login credentials.",
        guidance="Be careful sharing passwords or payment details in response to this email.",
    ),
    # Content — sensitive
    "Requests a Social Security number.": _spec(
        _CAT.SENSITIVE_REQUESTS,
        _SEV.CRITICAL,
        "The message asks for a Social Security number.",
        guidance="Do not send government ID numbers by email.",
    ),
    "References tax form W-2.": _spec(
        _CAT.SENSITIVE_REQUESTS,
        _SEV.HIGH,
        "The message references tax form information.",
        guidance="Verify tax requests through official agency or employer channels.",
    ),
    "Requests government ID details.": _spec(
        _CAT.SENSITIVE_REQUESTS,
        _SEV.CRITICAL,
        "The message asks for government ID information.",
        guidance="Do not send ID documents through email.",
    ),
    "Requests payroll information.": _spec(
        _CAT.SENSITIVE_REQUESTS,
        _SEV.HIGH,
        "The message asks for payroll or HR records.",
        guidance="Confirm HR requests through your employer's official process.",
    ),
    "Requests tax documents.": _spec(
        _CAT.SENSITIVE_REQUESTS,
        _SEV.HIGH,
        "The message asks for tax documents.",
    ),
    # Content — financial / invoice / delivery / crypto / otp / fake security / social
    "References wire transfers (common in BEC scams).": _spec(
        _CAT.SENSITIVE_REQUESTS,
        _SEV.HIGH,
        "The message mentions wire transfers or bank payments.",
        guidance="Verify payment changes with the requester by phone before sending money.",
    ),
    "Mentions ACH transfers.": _spec(
        _CAT.SENSITIVE_REQUESTS,
        _SEV.MEDIUM,
        "The message mentions bank transfer instructions.",
    ),
    "Mentions SWIFT transfers.": _spec(
        _CAT.SENSITIVE_REQUESTS,
        _SEV.MEDIUM,
        "The message mentions international wire transfer instructions.",
    ),
    "Requests bank account changes.": _spec(
        _CAT.SENSITIVE_REQUESTS,
        _SEV.HIGH,
        "The message asks to change bank account details.",
        guidance="Confirm account changes by phone before paying.",
    ),
    "Shares payment or transfer instructions.": _spec(
        _CAT.SENSITIVE_REQUESTS,
        _SEV.MEDIUM,
        "The message includes payment or transfer instructions.",
    ),
    "Invoice or payment pressure language.": _spec(
        _CAT.URGENCY_PRESSURE,
        _SEV.MEDIUM,
        "The message pressures you about an invoice or payment.",
    ),
    "Claims an invoice is attached.": _spec(
        _CAT.ATTACHMENTS,
        _SEV.MEDIUM,
        "The message says an invoice is attached.",
        guidance="Open attachments only after confirming the sender.",
    ),
    "References remittance.": _spec(
        _CAT.SENSITIVE_REQUESTS,
        _SEV.MEDIUM,
        "The message discusses remittance or payment settlement.",
    ),
    "States an invoice or payment is overdue.": _spec(
        _CAT.URGENCY_PRESSURE,
        _SEV.MEDIUM,
        "The message says a bill or payment is overdue.",
    ),
    "Directs payment of an invoice.": _spec(
        _CAT.SENSITIVE_REQUESTS,
        _SEV.MEDIUM,
        "The message tells you to pay an invoice.",
    ),
    "References an outstanding invoice or balance.": _spec(
        _CAT.SENSITIVE_REQUESTS,
        _SEV.MEDIUM,
        "The message references money you supposedly owe.",
    ),
    "Claims a package is held or delayed.": _spec(
        _CAT.URGENCY_PRESSURE,
        _SEV.MEDIUM,
        "The message claims a delivery is held or delayed.",
        guidance="Track packages on the carrier's official website.",
    ),
    "Requests customs or clearance fees.": _spec(
        _CAT.SENSITIVE_REQUESTS,
        _SEV.MEDIUM,
        "The message asks for customs or delivery fees.",
    ),
    "Claims a tracking or delivery problem.": _spec(
        _CAT.URGENCY_PRESSURE,
        _SEV.MEDIUM,
        "The message claims there is a shipping or tracking problem.",
    ),
    "Uses failed-delivery notice phrasing.": _spec(
        _CAT.URGENCY_PRESSURE,
        _SEV.MEDIUM,
        "The message looks like a failed delivery notice.",
    ),
    "Mentions gift cards (frequent in refund scams).": _spec(
        _CAT.SENSITIVE_REQUESTS,
        _SEV.HIGH,
        "The message mentions gift cards, which scammers often request as payment.",
    ),
    "Mentions cryptocurrency or digital wallets.": _spec(
        _CAT.SENSITIVE_REQUESTS,
        _SEV.HIGH,
        "The message mentions cryptocurrency or digital wallets.",
    ),
    "Uses refund-processing phrasing.": _spec(
        _CAT.URGENCY_PRESSURE,
        _SEV.MEDIUM,
        "The message discusses a refund that may need your action.",
    ),
    "Mentions prepaid cards.": _spec(
        _CAT.SENSITIVE_REQUESTS,
        _SEV.HIGH,
        "The message mentions prepaid cards.",
    ),
    "Requests a one-time code or password.": _spec(
        _CAT.SENSITIVE_REQUESTS,
        _SEV.CRITICAL,
        "The message asks for a one-time code or password.",
        guidance="Never share verification codes with anyone who emails you.",
    ),
    "Mentions a verification code.": _spec(
        _CAT.SENSITIVE_REQUESTS,
        _SEV.HIGH,
        "The message mentions a verification code.",
        guidance="Do not share codes from text messages or authenticator apps.",
    ),
    "References a numeric verification code.": _spec(
        _CAT.SENSITIVE_REQUESTS,
        _SEV.HIGH,
        "The message references a numeric sign-in code.",
    ),
    "Requests a 2FA or MFA code.": _spec(
        _CAT.SENSITIVE_REQUESTS,
        _SEV.CRITICAL,
        "The message asks for a two-factor authentication code.",
        guidance="Never share login codes with anyone.",
    ),
    "Uses security-alert phrasing.": _spec(
        _CAT.URGENCY_PRESSURE,
        _SEV.MEDIUM,
        "The message uses alarming security wording.",
    ),
    "Claims unauthorized access or activity.": _spec(
        _CAT.URGENCY_PRESSURE,
        _SEV.MEDIUM,
        "The message claims someone accessed your account without permission.",
    ),
    "Claims the account was compromised.": _spec(
        _CAT.URGENCY_PRESSURE,
        _SEV.HIGH,
        "The message says your account was compromised.",
        guidance="Check your account through the official app, not email links.",
    ),
    "Claims an account is suspended or locked.": _spec(
        _CAT.URGENCY_PRESSURE,
        _SEV.MEDIUM,
        "The message says your account is locked or suspended.",
    ),
    "Warns about suspicious activity or login.": _spec(
        _CAT.URGENCY_PRESSURE,
        _SEV.MEDIUM,
        "The message warns about suspicious sign-in activity.",
    ),
    "References unusual account activity.": _spec(
        _CAT.URGENCY_PRESSURE,
        _SEV.MEDIUM,
        "The message cites unusual activity on your account.",
    ),
    "Mentions temporary account restrictions.": _spec(
        _CAT.URGENCY_PRESSURE,
        _SEV.MEDIUM,
        "The message mentions temporary limits on your account.",
    ),
    "Invokes tax authority (IRS) pressure.": _spec(
        _CAT.URGENCY_PRESSURE,
        _SEV.HIGH,
        "The message uses tax authority pressure to rush you.",
    ),
    "Invokes law-enforcement authority.": _spec(
        _CAT.URGENCY_PRESSURE,
        _SEV.HIGH,
        "The message invokes police or legal authority to scare you.",
    ),
    "Uses executive (CEO) pressure for a request.": _spec(
        _CAT.URGENCY_PRESSURE,
        _SEV.HIGH,
        "The message uses executive pressure for a sensitive request.",
        guidance="Verify urgent executive requests through a known contact.",
    ),
    "Threatens legal consequences.": _spec(
        _CAT.URGENCY_PRESSURE,
        _SEV.HIGH,
        "The message threatens legal action.",
    ),
    "Instructs secrecy (common in BEC).": _spec(
        _CAT.URGENCY_PRESSURE,
        _SEV.HIGH,
        "The message tells you to keep the request secret.",
        guidance="Legitimate workplaces rarely ask you to hide payment requests.",
    ),
    "Unusually high attachment count combined with risky or large files.": _spec(
        _CAT.ATTACHMENTS,
        _SEV.MEDIUM,
        "This message has many attachments, including some that look risky.",
    ),
}

# --- Pattern rules (first match wins) ---

_PATTERN_RULES: tuple[tuple[re.Pattern[str], ExplanationSpec], ...] = (
    (
        re.compile(r"^SPF result was 'fail'", re.I),
        _spec(
            _CAT.SENDER_IDENTITY,
            _SEV.HIGH,
            "This email could not verify that it was sent from the real organization.",
            guidance="Confirm the sender before trusting links or attachments.",
        ),
    ),
    (
        re.compile(r"^DKIM result was 'fail'", re.I),
        _spec(
            _CAT.SENDER_IDENTITY,
            _SEV.HIGH,
            "Part of the sender verification for this message failed.",
            guidance="Confirm the sender before trusting links or attachments.",
        ),
    ),
    (
        re.compile(r"^DMARC result was 'fail'", re.I),
        _spec(
            _CAT.SENDER_IDENTITY,
            _SEV.HIGH,
            "This email failed an important sender authenticity check.",
            guidance="Confirm the sender before trusting links or attachments.",
        ),
    ),
    (
        re.compile(r"^SPF reported 'softfail'", re.I),
        _spec(
            _CAT.SENDER_IDENTITY,
            _SEV.MEDIUM,
            "Sender verification for this message was inconclusive.",
        ),
    ),
    (
        re.compile(r"^DKIM reported 'softfail'", re.I),
        _spec(
            _CAT.SENDER_IDENTITY,
            _SEV.MEDIUM,
            "Part of the sender verification was inconclusive.",
        ),
    ),
    (
        re.compile(r"^DMARC reported 'softfail'", re.I),
        _spec(
            _CAT.SENDER_IDENTITY,
            _SEV.MEDIUM,
            "Sender policy checks were inconclusive for this message.",
        ),
    ),
    (
        re.compile(r"^(SPF|DKIM|DMARC) reported '(neutral|none)'", re.I),
        _spec(
            _CAT.SENDER_IDENTITY,
            _SEV.LOW,
            "Sender checks did not strongly confirm or deny who sent this email.",
        ),
    ),
    (
        re.compile(r"^(SPF|DKIM|DMARC) reported '(temperror|permerror)'", re.I),
        _spec(
            _CAT.SENDER_IDENTITY,
            _SEV.MEDIUM,
            "Sender checks could not be completed reliably for this message.",
        ),
    ),
    (
        re.compile(r"^(SPF|DKIM|DMARC) returned an uncommon", re.I),
        _spec(
            _CAT.SENDER_IDENTITY,
            _SEV.MEDIUM,
            "Sender check results were unclear, so this message was treated cautiously.",
        ),
    ),
    (
        re.compile(r"^Reply-To domain \(", re.I),
        _spec(
            _CAT.SENDER_IDENTITY,
            _SEV.HIGH,
            "Replies may go to a different organization than the sender shows.",
            guidance="Check the reply address before sending sensitive information.",
        ),
    ),
    (
        re.compile(r"^Hostname ends with a frequently abused TLD", re.I),
        _spec(
            _CAT.LINKS_WEBSITES,
            _SEV.MEDIUM,
            "A link uses a web address ending that is often seen in scams.",
            guidance="Avoid clicking links until you verify the sender.",
        ),
    ),
    (
        re.compile(r"^Message contains \d+ links to external", re.I),
        _spec(
            _CAT.LINKS_WEBSITES,
            _SEV.MEDIUM,
            "This email contains several links to outside websites.",
        ),
    ),
    (
        re.compile(r"^Multiple high-risk URLs", re.I),
        _spec(
            _CAT.LINKS_WEBSITES,
            _SEV.HIGH,
            "This email contains multiple links that look risky.",
            guidance="Avoid clicking links in this message until you verify the sender.",
        ),
    ),
    (
        re.compile(r"^Link host .+ is outside the sender domain", re.I),
        _spec(
            _CAT.LINKS_WEBSITES,
            _SEV.MEDIUM,
            "This email contains a link that may lead to an unsafe website.",
            guidance="Avoid clicking links until you verify the sender.",
        ),
    ),
    (
        re.compile(r"^From domain uses punycode", re.I),
        _spec(
            _CAT.SENDER_IDENTITY,
            _SEV.HIGH,
            "The sender address may be disguised to look like a trusted company.",
        ),
    ),
    (
        re.compile(r"^From domain .+ closely resembles", re.I),
        _spec(
            _CAT.SENDER_IDENTITY,
            _SEV.HIGH,
            "The message may be pretending to be a trusted company.",
            guidance="Compare the sender address with official contact details.",
        ),
    ),
    (
        re.compile(r"^Display name references .+ but the message is not from", re.I),
        _spec(
            _CAT.SENDER_IDENTITY,
            _SEV.HIGH,
            "The sender name looks like a well-known company, but the email address does not match.",
        ),
    ),
    (
        re.compile(r"^Corporate-style display name with consumer mail host", re.I),
        _spec(
            _CAT.SENDER_IDENTITY,
            _SEV.MEDIUM,
            "A business-style sender name is using a personal email provider.",
        ),
    ),
    (
        re.compile(r"^Message body mentions .+ but sender", re.I),
        _spec(
            _CAT.SENDER_IDENTITY,
            _SEV.MEDIUM,
            "The message mentions a company that does not match the sender address.",
        ),
    ),
    (
        re.compile(r"^From domain embeds brand-like label", re.I),
        _spec(
            _CAT.SENDER_IDENTITY,
            _SEV.HIGH,
            "The sender web address is structured to look like a known brand.",
        ),
    ),
    (
        re.compile(r"^Body references .+ but link host", re.I),
        _spec(
            _CAT.LINKS_WEBSITES,
            _SEV.HIGH,
            "A link does not match the company mentioned in the message.",
            guidance="Avoid clicking links until you verify the sender.",
        ),
    ),
    (
        re.compile(r"^Brand .+ appears in display and body but sender domain", re.I),
        _spec(
            _CAT.SENDER_IDENTITY,
            _SEV.MEDIUM,
            "A brand appears in the message, but the sender is not on that company's email.",
        ),
    ),
    (
        re.compile(r"^Potentially executable attachment", re.I),
        _spec(
            _CAT.ATTACHMENTS,
            _SEV.CRITICAL,
            "An attachment may be a program that could harm your computer.",
            guidance="Do not open this attachment unless you expected it from a trusted sender.",
        ),
    ),
    (
        re.compile(r"^Filename suggests a double extension trick", re.I),
        _spec(
            _CAT.ATTACHMENTS,
            _SEV.CRITICAL,
            "An attachment name may hide its real file type.",
            guidance="Do not open unexpected attachments.",
        ),
    ),
    (
        re.compile(r"^Archive attachment may hide malware", re.I),
        _spec(
            _CAT.ATTACHMENTS,
            _SEV.HIGH,
            "A compressed attachment can hide harmful files inside.",
            guidance="Scan attachments with caution and confirm the sender first.",
        ),
    ),
    (
        re.compile(r"^Macro-enabled Office attachment", re.I),
        _spec(
            _CAT.ATTACHMENTS,
            _SEV.HIGH,
            "An Office attachment can run macros that may be unsafe.",
            guidance="Do not enable macros unless you fully trust the sender.",
        ),
    ),
    (
        re.compile(r"^Archive filename hints at password protection", re.I),
        _spec(
            _CAT.ATTACHMENTS,
            _SEV.CRITICAL,
            "A password-protected archive is a common trick in invoice scams.",
            guidance="Do not open the attachment or use a password from the email.",
        ),
    ),
    (
        re.compile(r"^HTML/SVG attachment can carry phishing", re.I),
        _spec(
            _CAT.ATTACHMENTS,
            _SEV.MEDIUM,
            "A web-style attachment could try to steal information when opened.",
        ),
    ),
    (
        re.compile(r"^Business-themed filename with risky extension", re.I),
        _spec(
            _CAT.ATTACHMENTS,
            _SEV.HIGH,
            "An attachment is named like a bill or payment but may not be safe to open.",
        ),
    ),
    (
        re.compile(r"^Large attachment \(", re.I),
        _spec(
            _CAT.ATTACHMENTS,
            _SEV.LOW,
            "This message includes a very large attachment.",
        ),
    ),
)
