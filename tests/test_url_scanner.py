"""Tests for URL validation and the URL verdict logic."""

import pytest

import database
from modules.url_scanner import decide_verdict, validate_url


# ---------------------------------------------------------------- validation
def test_bare_domain_gets_a_scheme():
    """Users paste bare domains; VirusTotal needs a full URL."""
    ok, cleaned, domain = validate_url("example.com")
    assert ok
    assert cleaned == "http://example.com"
    assert domain == "example.com"


def test_existing_scheme_is_preserved():
    ok, cleaned, domain = validate_url("https://example.com/login")
    assert ok
    assert cleaned == "https://example.com/login"
    assert domain == "example.com"


def test_subdomains_and_paths_survive():
    ok, cleaned, domain = validate_url("https://sub.domain.co.uk/path?q=1")
    assert ok
    assert domain == "sub.domain.co.uk"
    assert "?q=1" in cleaned


def test_port_is_stripped_from_the_domain():
    ok, _, domain = validate_url("http://example.com:8080/admin")
    assert ok
    assert domain == "example.com"


@pytest.mark.parametrize("scheme_url", ["ftp://files.com", "file:///etc/passwd"])
def test_non_http_schemes_are_rejected(scheme_url):
    ok, message, _ = validate_url(scheme_url)
    assert not ok
    assert message


def test_javascript_pseudo_scheme_is_rejected():
    """Guards against a javascript: payload reaching the page."""
    ok, _, _ = validate_url("javascript:alert(1)")
    assert not ok


@pytest.mark.parametrize("junk", ["", "   ", "not a url", "http://", "...."])
def test_malformed_input_is_rejected(junk):
    ok, message, _ = validate_url(junk)
    assert not ok
    assert message


def test_absurdly_long_url_is_rejected():
    ok, message, _ = validate_url("http://example.com/" + "a" * 3000)
    assert not ok
    assert "too long" in message.lower()


# ------------------------------------------------------------------ verdicts
def vt(malicious=0, suspicious=0, engines=91, flagged=None):
    return {"available": True, "malicious": malicious, "suspicious": suspicious,
            "total_engines": engines, "flagged_by": flagged or []}


def whois(age_days, **extra):
    return {"available": True, "age_days": age_days,
            "age_label": f"{age_days} days old", **extra}


UNAVAILABLE = {"available": False, "error": "unavailable"}


def test_many_engines_flagging_is_malicious():
    verdict, reasons = decide_verdict(vt(malicious=12), whois(2000))
    assert verdict == database.VERDICT_MALICIOUS
    assert any("12" in r for r in reasons)


def test_one_engine_flagging_is_suspicious():
    verdict, _ = decide_verdict(vt(malicious=1), UNAVAILABLE)
    assert verdict == database.VERDICT_SUSPICIOUS


def test_clean_url_on_a_brand_new_domain_is_suspicious():
    """The key rule: domain age escalates on its own.

    A phishing site registered this morning has not been reported by anyone
    yet, so engine detections always lag. Age catches it in that window.
    """
    verdict, reasons = decide_verdict(vt(), whois(3))
    assert verdict == database.VERDICT_SUSPICIOUS
    assert any("3 day" in r for r in reasons)


def test_clean_url_on_an_old_domain_is_clean():
    verdict, _ = decide_verdict(vt(), whois(4000))
    assert verdict == database.VERDICT_CLEAN


def test_domain_age_just_under_thirty_days_is_suspicious():
    verdict, _ = decide_verdict(vt(), whois(29))
    assert verdict == database.VERDICT_SUSPICIOUS


def test_domain_age_at_thirty_days_is_clean():
    """30 is the documented boundary; at it, age stops escalating."""
    verdict, _ = decide_verdict(vt(), whois(30))
    assert verdict == database.VERDICT_CLEAN


def test_flagging_engines_are_named():
    _, reasons = decide_verdict(
        vt(malicious=5, flagged=["Kaspersky", "ESET"]), UNAVAILABLE
    )
    assert any("Kaspersky" in r for r in reasons)


def test_verdict_always_has_reasons():
    for v, w in [(vt(malicious=12), whois(2000)), (vt(), whois(3)),
                 (vt(), whois(4000)), (UNAVAILABLE, UNAVAILABLE)]:
        _, reasons = decide_verdict(v, w)
        assert len(reasons) >= 1
