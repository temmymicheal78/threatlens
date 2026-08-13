"""Tests for email header parsing, spoofing detection and phishing verdicts."""

import pytest

import database
from modules.email_analyzer import (
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
