"""Tests for email header parsing, spoofing detection and phishing verdicts."""

import pytest

import database
from modules.email_analyzer import (
    classify_ip,
    extract_mail_path,
    check_authentication,
    check_spoofing,
    check_subject_keywords,
    decide_verdict,
    extract_origin_ip,
    extract_urls,
    parse_email,
)


# ------------------------------------------------------------------- parsing
def test_valid_email_parses(phishing_email):
    ok, message = parse_email(phishing_email)
    assert ok
    assert message.get("From")


def test_headers_only_paste_is_accepted():
    """Analysts are often given headers without a body."""
    ok, _ = parse_email("From: a@b.com\nSubject: Test\n")
    assert ok


@pytest.mark.parametrize("junk,expected", [
    ("", "paste"),
    ("   ", "paste"),
    ("hi", "short"),
    ("just some body text with no headers whatsoever in it", "header"),
])
def test_non_emails_are_rejected_with_guidance(junk, expected):
    ok, message = parse_email(junk)
    assert not ok
    assert expected in message.lower()


# ------------------------------------------------------------ authentication
def test_failed_authentication_is_read(phishing_email):
    _, message = parse_email(phishing_email)
    auth = check_authentication(message)
    assert auth == {"spf": "fail", "dkim": "fail", "dmarc": "fail"}


def test_passing_authentication_is_read(legitimate_email):
    _, message = parse_email(legitimate_email)
    auth = check_authentication(message)
    assert auth == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}


def test_missing_authentication_headers_yield_none():
    _, message = parse_email("From: a@b.com\nSubject: Hello\n")
    auth = check_authentication(message)
    assert auth == {"spf": None, "dkim": None, "dmarc": None}


def test_received_spf_header_is_used_as_a_fallback():
    """Older servers write Received-SPF instead of Authentication-Results."""
    _, message = parse_email(
        "Received-SPF: pass (google.com: domain of a@b.com)\n"
        "From: a@b.com\nSubject: Hello\n"
    )
    assert check_authentication(message)["spf"] == "pass"


# ------------------------------------------------------------------ spoofing
def test_return_path_mismatch_is_detected(phishing_email):
    _, message = parse_email(phishing_email)
    spoof = check_spoofing(message)
    assert spoof["from_domain"] == "paypa1-secure.xyz"
    assert spoof["return_path_domain"] == "evil-host.ru"
    assert any("Return-Path" in f for f in spoof["findings"])


def test_reply_to_mismatch_is_detected(phishing_email):
    _, message = parse_email(phishing_email)
    spoof = check_spoofing(message)
    assert any("Reply-To" in f for f in spoof["findings"])


def test_matching_domains_produce_no_findings(legitimate_email):
    _, message = parse_email(legitimate_email)
    spoof = check_spoofing(message)
    assert spoof["findings"] == []
    assert spoof["from_domain"] == "github.com"


# ---------------------------------------------------------------- origin IP
def test_originating_ip_comes_from_the_earliest_hop(phishing_email):
    """Received headers stack newest-first, so the last one is the origin."""
    _, message = parse_email(phishing_email)
    assert extract_origin_ip(message) == "185.220.101.10"


def test_private_relay_addresses_are_skipped(phishing_email):
    """The 10.0.0.5 internal relay must not be reported as the sender."""
    _, message = parse_email(phishing_email)
    assert extract_origin_ip(message) != "10.0.0.5"


def test_no_received_headers_yields_no_ip():
    _, message = parse_email("From: a@b.com\nSubject: Hello\n")
    assert extract_origin_ip(message) is None


# ---------------------------------------------------------------- mail path
# Headers taken from the "Golden Invoice" SOC training scenario: a three-hop
# chain mixing an external sender, a relay, and an internal NHS server.
GOLDEN_INVOICE = (
    "Received: from mx01.brackenmoor.nhs.uk (10.24.8.15) by"
    " mailstore01.brackenmoor.nhs.uk with ESMTP id STORE88217;"
    " Mon, 25 Aug 2026 09:16:41 +0100\n"
    "Received: from outbound01.payhub-notify-secure.com (198.51.100.42) by"
    " mx01.brackenmoor.nhs.uk with ESMTPS id BMNHS88217;"
    " Mon, 25 Aug 2026 09:16:39 +0100\n"
    "Received: from mail.payhub-notify-secure.com"
    " (mail.payhub-notify-secure.com [203.0.113.77]) by"
    " outbound01.payhub-notify-secure.com with ESMTP id GINV01;"
    " Mon, 25 Aug 2026 08:14:31 +0000\n"
    "From: \"PayHub Invoicing\" <no-reply@payhub-notify-secure.com>\n"
    "Subject: Invoice INV-33421 Shared With You\n"
)


@pytest.mark.parametrize("address,expected", [
    ("8.8.8.8", "public"),
    ("40.93.15.201", "public"),
    ("10.24.8.15", "internal"),
    ("192.168.1.1", "internal"),
    ("127.0.0.1", "loopback"),
    ("203.0.113.77", "documentation"),
    ("198.51.100.42", "documentation"),
    ("192.0.2.1", "documentation"),
])
def test_ip_classification(address, expected):
    """Documentation ranges must be told apart from genuine internal relays.

    Python reports both as private, which is correct for routing but hides a
    distinction that matters: a training placeholder is not an internal hop.
    """
    assert classify_ip(address) == expected


def test_mail_path_is_ordered_oldest_hop_first():
    """Received headers stack newest-first, so the path must be reversed."""
    _, message = parse_email(GOLDEN_INVOICE)
    path = extract_mail_path(message)

    assert [hop["position"] for hop in path] == [1, 2, 3]
    assert path[0]["ip"] == "203.0.113.77"
    assert path[-1]["ip"] == "10.24.8.15"


def test_mail_path_returns_every_hop_including_internal():
    """Unlike extract_origin_ip, nothing is skipped -- the analyst sees it all."""
    _, message = parse_email(GOLDEN_INVOICE)
    assert len(extract_mail_path(message)) == 3


def test_mail_path_records_hosts_and_timestamp():
    _, message = parse_email(GOLDEN_INVOICE)
    first = extract_mail_path(message)[0]

    assert first["from_host"] == "mail.payhub-notify-secure.com"
    assert first["by_host"] == "outbound01.payhub-notify-secure.com"
    assert first["timestamp"] == "Mon, 25 Aug 2026 08:14:31 +0000"


def test_mail_path_labels_each_address_type():
    _, message = parse_email(GOLDEN_INVOICE)
    kinds = [hop["ip_kind"] for hop in extract_mail_path(message)]
    assert kinds == ["documentation", "documentation", "internal"]


def test_mail_path_handles_bracketed_and_bare_ip_formats():
    """Hop 1 writes the IP in brackets, hop 2 in bare parentheses."""
    _, message = parse_email(GOLDEN_INVOICE)
    path = extract_mail_path(message)
    assert path[0]["ip"] == "203.0.113.77"      # [203.0.113.77]
    assert path[1]["ip"] == "198.51.100.42"     # (198.51.100.42)


def test_no_received_headers_gives_an_empty_path():
    _, message = parse_email("From: a@b.com\nSubject: Hello\n")
    assert extract_mail_path(message) == []


def test_origin_ip_and_mail_path_can_disagree():
    """A real difference worth understanding.

    extract_origin_ip skips anything Python calls private -- which includes
    documentation ranges -- so it finds no origin here. The mail path still
    shows every hop, which is exactly why both exist.
    """
    _, message = parse_email(GOLDEN_INVOICE)
    assert extract_origin_ip(message) is None
    assert len(extract_mail_path(message)) == 3


# --------------------------------------------------------------------- URLs
def test_urls_are_extracted(phishing_email):
    urls = extract_urls(phishing_email)
    assert "http://paypa1-secure.xyz/verify" in urls


def test_duplicate_urls_are_collapsed():
    text = "See http://a.com/x and http://a.com/x and http://b.com/y"
    assert len(extract_urls(text)) == 2


def test_trailing_punctuation_is_trimmed():
    assert extract_urls("Visit http://example.com/page.") == ["http://example.com/page"]


def test_url_extraction_is_capped():
    text = " ".join(f"http://site{i}.com" for i in range(50))
    assert len(extract_urls(text, limit=15)) == 15


# ----------------------------------------------------------------- keywords
def test_urgency_keywords_are_found(phishing_email):
    _, message = parse_email(phishing_email)
    keywords = check_subject_keywords(message)
    assert "urgent" in keywords
    assert "suspended" in keywords


def test_ordinary_subject_has_no_keywords(legitimate_email):
    _, message = parse_email(legitimate_email)
    assert check_subject_keywords(message) == []


# ------------------------------------------------------------------ verdicts
NO_REPUTATION = {"available": False}


def analyse(raw):
    """Run every check on *raw* and return the verdict plus its reasons."""
    _, message = parse_email(raw)
    return decide_verdict(
        check_authentication(message),
        check_spoofing(message),
        NO_REPUTATION,
        check_subject_keywords(message),
        extract_urls(raw),
    )


def test_phishing_email_is_malicious(phishing_email):
    verdict, _ = analyse(phishing_email)
    assert verdict == database.VERDICT_MALICIOUS


def test_legitimate_email_is_clean(legitimate_email):
    verdict, _ = analyse(legitimate_email)
    assert verdict == database.VERDICT_CLEAN


def test_dmarc_failure_alone_is_conclusive():
    """DMARC is the domain owner's own policy on authenticity."""
    verdict, reasons = decide_verdict(
        {"spf": "pass", "dkim": "pass", "dmarc": "fail"},
        {"findings": []}, NO_REPUTATION, [], [],
    )
    assert verdict == database.VERDICT_MALICIOUS
    assert any("DMARC" in r for r in reasons)


def test_spf_and_dkim_both_failing_is_malicious():
    verdict, _ = decide_verdict(
        {"spf": "fail", "dkim": "fail", "dmarc": None},
        {"findings": []}, NO_REPUTATION, [], [],
    )
    assert verdict == database.VERDICT_MALICIOUS


def test_malicious_sending_ip_escalates():
    verdict, reasons = decide_verdict(
        {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        {"findings": []},
        {"available": True, "abuse_score": 95},
        [], [],
    )
    assert verdict == database.VERDICT_MALICIOUS
    assert any("95" in r for r in reasons)


def test_spoofing_evidence_is_reported_even_when_already_malicious(phishing_email):
    """An analyst writing this up needs every indicator, not just the
    one that tipped the decision."""
    verdict, reasons = analyse(phishing_email)
    assert verdict == database.VERDICT_MALICIOUS
    assert any("Return-Path" in r for r in reasons)
    assert any("Reply-To" in r for r in reasons)


def test_urgency_alone_does_not_convict():
    """Legitimate mail says 'urgent' too."""
    verdict, _ = decide_verdict(
        {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        {"findings": []}, NO_REPUTATION, ["urgent"], [],
    )
    assert verdict == database.VERDICT_CLEAN


def test_missing_authentication_is_flagged_as_unproven():
    _, reasons = decide_verdict(
        {"spf": None, "dkim": None, "dmarc": None},
        {"findings": []}, NO_REPUTATION, [], [],
    )
    assert any("unproven" in r.lower() or "did not check" in r.lower() for r in reasons)
