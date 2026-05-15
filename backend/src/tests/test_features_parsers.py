"""Parsing helper tests.

Responsible for email and domain normalization utilities in scoring/parsing.
"""

from __future__ import annotations

import pytest

from app.scoring.parsing.domains import (
    domain_from_address,
    domains_equal,
    is_free_mail_domain,
    registrable_domain,
)
from app.scoring.parsing.emails import domain_has_punycode, parse_email_address


@pytest.mark.parametrize(
    ("raw", "address", "domain"),
    [
        ("user@Example.COM", "user@example.com", "example.com"),
        ("Billing <billing@acme.co.uk>", "billing@acme.co.uk", "acme.co.uk"),
        ('"Microsoft Security" <security.alert@gmail.com>', "security.alert@gmail.com", "gmail.com"),
        ("CFO Payments <wire.handler@payments-offshore.net>", "wire.handler@payments-offshore.net", "payments-offshore.net"),
        ("Name user@host.com", "user@host.com", "host.com"),
    ],
)
def test_parse_email_address(raw: str, address: str, domain: str) -> None:
    parsed = parse_email_address(raw)
    assert parsed is not None
    assert parsed.address == address
    assert parsed.domain == domain


@pytest.mark.parametrize(
    "raw",
    ["", "not-an-email", "@missing.com", "user@", "user @ host . com"],
)
def test_parse_email_address_rejects_invalid(raw: str) -> None:
    assert parse_email_address(raw) is None


def test_domain_from_address_uses_angle_bracket_mailbox() -> None:
    assert domain_from_address("PayPal <service@evil.tld>") == "evil.tld"


def test_registrable_domain_multi_part_suffix() -> None:
    assert registrable_domain("mail.acme.co.uk") == "acme.co.uk"
    assert registrable_domain("www.shop.example.com") == "example.com"


def test_domains_equal_subdomain_same_org() -> None:
    assert domains_equal("acme.com", "mail.acme.com")
    assert not domains_equal("acme.com", "evil.net")


def test_is_free_mail_domain() -> None:
    assert is_free_mail_domain("gmail.com")
    assert is_free_mail_domain("mail.googlemail.com")
    assert not is_free_mail_domain("acme.com")


def test_domain_has_punycode() -> None:
    assert domain_has_punycode("xn--paypa1-abc.com")
    assert not domain_has_punycode("paypal.com")
