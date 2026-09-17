"""Tests for email header parsing, spoofing detection and phishing verdicts."""

import pytest

import database
from modules.email_analyzer import (
    classify_auth_result,
    extract_origin,
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


def test_documentation_range_is_reported_as_the_origin():
    """In a training capture the documentation range *is* the sender.

    Skipping it, as an earlier version did, threw away the answer entirely.
    """
    _, message = parse_email(GOLDEN_INVOICE)
    assert extract_origin_ip(message) == "203.0.113.77"


# --------------------------------------------------- origin determination
# A relayed message: the true sender is 203.0.113.77, but the mail passes
# through Microsoft 365 on the way, so the earliest *public* hop belongs to
# Microsoft rather than the attacker.
RELAYED = (
    "Received: from MW4NAM10FT021.eop-NAM10.prod.protection.outlook.com"
    " (unknown [40.93.15.201]) by mx.example.com with ESMTP;"
    " Mon, 10 Aug 2026 09:17:59 +0100\n"
    "Received: from mail.payhub-notify-secure.com"
    " (mail.payhub-notify-secure.com [203.0.113.77]) by"
    " MW4NAM10FT021.eop-NAM10.prod.protection.outlook.com with ESMTP;"
    " Mon, 10 Aug 2026 09:15:31 +0100\n"
    "Received-SPF: Fail (domain does not designate 203.0.113.77 as permitted"
    " sender) client-ip=203.0.113.77;"
    " envelope-from=no-reply@payhub-notify-secure.com;\n"
    "From: \"PayHub Invoicing\" <no-reply@payhub-notify-secure.com>\n"
    "Subject: Invoice overdue\n"
)


def test_client_ip_is_preferred_over_walking_the_hops():
    """The receiving server's own determination beats our reconstruction.

    Without this, the earliest public hop is Microsoft's relay, and the tool
    reports an innocent middleman as the sender.
    """
    _, message = parse_email(RELAYED)
    origin = extract_origin(message)

    assert origin["ip"] == "203.0.113.77"
    assert origin["ip"] != "40.93.15.201"
    assert "client-ip" in origin["source"]


def test_hop_walking_is_used_when_no_client_ip_is_published():
    _, message = parse_email(
        "Received: from evil.example (evil.example [8.8.4.4]) by mx.example.com"
        " with ESMTP; Mon, 10 Aug 2026 09:15:31 +0100\n"
        "From: a@b.com\nSubject: Hello\n"
    )
    origin = extract_origin(message)
    assert origin["ip"] == "8.8.4.4"
    assert origin["source"] == "earliest Received hop"


def test_sender_ip_spelling_is_also_recognised():
    """Microsoft writes sender-ip rather than client-ip."""
    _, message = parse_email(
        "Authentication-Results: spf=fail sender-ip=203.0.113.99;\n"
        "From: a@b.com\nSubject: Hello\n"
    )
    assert extract_origin(message)["ip"] == "203.0.113.99"


def test_no_headers_gives_no_origin_and_no_source():
    _, message = parse_email("From: a@b.com\nSubject: Hello\n")
    assert extract_origin(message) == {"ip": None, "source": None}


def test_internal_relays_are_never_reported_as_the_origin():
    _, message = parse_email(
        "Received: from relay (relay [10.0.0.5]) by mx.example.com with ESMTP;"
        " Mon, 10 Aug 2026 09:15:31 +0100\n"
        "From: a@b.com\nSubject: Hello\n"
    )
    assert extract_origin(message)["ip"] is None


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


# ------------------------------------------- reading authentication results
@pytest.mark.parametrize("value,expected", [
    ("pass", "pass"),
    ("fail", "fail"),
    ("softfail", "weak"),
    ("none", "unverified"),
    ("neutral", "unverified"),
    ("temperror", "unverified"),
    ("permerror", "unverified"),
    (None, None),
])
def test_auth_results_are_sorted_by_what_they_prove(value, expected):
    """Only pass proves anything and only fail disproves anything."""
    assert classify_auth_result(value) == expected


def test_permerror_and_none_are_parsed_from_real_headers():
    _, message = parse_email(
        "Authentication-Results: mail.pot; spf=fail smtp.mailfrom=x.com;"
        " dkim=none (no signature); dmarc=permerror (no valid record)"
        " header.from=x.com\n"
        "From: a@x.com\nSubject: Hello\n"
    )
    assert check_authentication(message) == {
        "spf": "fail", "dkim": "none", "dmarc": "permerror",
    }


def test_dmarc_permerror_is_not_reported_as_a_policy_failure():
    """The defect this guards against.

    permerror means the DMARC record could not be read. It was reported as
    "the sending domain's own policy says this message is not authentic",
    which the domain never said.
    """
    verdict, reasons = decide_verdict(
        {"spf": "pass", "dkim": "pass", "dmarc": "permerror"},
        {"findings": []}, NO_REPUTATION, [], [],
    )
    assert verdict == database.VERDICT_CLEAN
    assert not any("own policy" in r for r in reasons)
    assert any("PERMERROR" in r and "Not a failure" in r for r in reasons)


def test_unsigned_message_is_not_a_failed_signature():
    """DKIM none means no signature was present, not that one failed."""
    verdict, reasons = decide_verdict(
        {"spf": "pass", "dkim": "none", "dmarc": "pass"},
        {"findings": []}, NO_REPUTATION, [], [],
    )
    assert verdict == database.VERDICT_CLEAN
    assert any("no DKIM signature" in r for r in reasons)
    assert not any("Failed authentication" in r for r in reasons)


def test_spf_fail_with_no_signature_is_suspicious_not_conclusive():
    """One definite failure and one absence of evidence is not proof.

    Only SPF actively failed. It warrants escalation, and the analyst is
    told nothing else vouches for the message -- but the tool does not claim
    a certainty the headers cannot support.
    """
    verdict, reasons = decide_verdict(
        {"spf": "fail", "dkim": "none", "dmarc": None},
        {"findings": []}, NO_REPUTATION, [], [],
    )
    assert verdict == database.VERDICT_SUSPICIOUS
    assert any("Failed authentication: SPF" in r for r in reasons)
    assert any("No authentication mechanism passed" in r for r in reasons)


def test_golden_invoice_authentication_is_read_accurately():
    """spf=fail, dkim=none, dmarc=permerror with replies diverted to Gmail.

    Every signal is still reported, but only SPF counts as a failure.
    """
    verdict, reasons = decide_verdict(
        {"spf": "fail", "dkim": "none", "dmarc": "permerror"},
        {"findings": ["Reply-To domain (gmail.com) differs from From domain "
                      "(payhub-notify-secure.com) -- replies would go to a "
                      "third party"]},
        NO_REPUTATION, [], [],
    )
    assert verdict == database.VERDICT_SUSPICIOUS
    assert any("Failed authentication: SPF" in r for r in reasons)
    assert any("DKIM NONE" in r for r in reasons)
    assert any("DMARC PERMERROR" in r for r in reasons)
    assert any("gmail.com" in r for r in reasons)
    assert not any("own policy" in r for r in reasons)


def test_real_dmarc_fail_is_still_conclusive():
    """The fix narrows what counts as failure -- it must not weaken it."""
    verdict, _ = decide_verdict(
        {"spf": "none", "dkim": "none", "dmarc": "fail"},
        {"findings": []}, NO_REPUTATION, [], [],
    )
    assert verdict == database.VERDICT_MALICIOUS


def test_spf_softfail_raises_suspicion():
    verdict, reasons = decide_verdict(
        {"spf": "softfail", "dkim": "none", "dmarc": None},
        {"findings": []}, NO_REPUTATION, [], [],
    )
    assert verdict == database.VERDICT_SUSPICIOUS
    assert any("SOFTFAIL" in r for r in reasons)


def test_temperror_is_explained_as_temporary():
    _, reasons = decide_verdict(
        {"spf": "temperror", "dkim": "pass", "dmarc": "pass"},
        {"findings": []}, NO_REPUTATION, [], [],
    )
    assert any("temporary error" in r for r in reasons)
