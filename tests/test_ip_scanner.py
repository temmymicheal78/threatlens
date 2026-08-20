"""Tests for the IP scanner's validation and verdict logic.

Both functions under test are pure -- they touch no network and no database
-- so intel responses are supplied as plain dicts.
"""

import pytest

import database
from modules.ip_scanner import decide_verdict, validate_ip


# ---------------------------------------------------------------- validation
@pytest.mark.parametrize("address", [
    "8.8.8.8",
    "185.220.101.10",
    "1.1.1.1",
    "2606:4700:4700::1111",
])
def test_public_addresses_are_accepted(address):
    ok, result = validate_ip(address)
    assert ok
    assert result == address


def test_surrounding_whitespace_is_stripped():
    ok, result = validate_ip("  8.8.8.8  ")
    assert ok
    assert result == "8.8.8.8"


@pytest.mark.parametrize("address,expected_word", [
    ("192.168.1.1", "private"),
    ("10.0.0.1", "private"),
    ("127.0.0.1", "loopback"),
    ("224.0.0.1", "multicast"),
])
def test_non_routable_addresses_are_rejected_with_the_right_reason(address, expected_word):
    """Each rejection explains itself specifically, not generically.

    Loopback is checked before private because is_private is also true for
    loopback -- testing in the wrong order gives a misleading message.
    """
    ok, message = validate_ip(address)
    assert not ok
    assert expected_word in message.lower()


@pytest.mark.parametrize("junk", ["", "   ", "not-an-ip", "999.999.999.999", "8.8.8"])
def test_malformed_input_is_rejected(junk):
    ok, message = validate_ip(junk)
    assert not ok
    assert message


# ------------------------------------------------------------------ verdicts
def abuse(score, **extra):
    """Build an AbuseIPDB-shaped response."""
    return {"available": True, "abuse_score": score, "total_reports": 0,
            "distinct_reporters": 0, **extra}


def vt(malicious=0, suspicious=0):
    """Build a VirusTotal-shaped response."""
    return {"available": True, "malicious": malicious, "suspicious": suspicious}


UNAVAILABLE = {"available": False, "error": "No API key configured"}


def test_high_abuse_score_is_malicious():
    verdict, reasons = decide_verdict(abuse(100), UNAVAILABLE)
    assert verdict == database.VERDICT_MALICIOUS
    assert any("100" in r for r in reasons)


def test_abuse_score_exactly_at_threshold_is_malicious():
    """50 is the documented threshold, so 50 itself must escalate."""
    verdict, _ = decide_verdict(abuse(50), UNAVAILABLE)
    assert verdict == database.VERDICT_MALICIOUS


def test_abuse_score_just_below_threshold_is_not_malicious():
    verdict, _ = decide_verdict(abuse(49), UNAVAILABLE)
    assert verdict == database.VERDICT_SUSPICIOUS


def test_moderate_abuse_score_is_suspicious():
    verdict, _ = decide_verdict(abuse(30), UNAVAILABLE)
    assert verdict == database.VERDICT_SUSPICIOUS


def test_zero_abuse_score_is_clean():
    verdict, _ = decide_verdict(abuse(0), UNAVAILABLE)
    assert verdict == database.VERDICT_CLEAN


def test_three_virustotal_engines_is_malicious():
    verdict, _ = decide_verdict(UNAVAILABLE, vt(malicious=3))
    assert verdict == database.VERDICT_MALICIOUS


def test_one_virustotal_engine_is_only_suspicious():
    """Single-engine detections are frequently false positives."""
    verdict, _ = decide_verdict(UNAVAILABLE, vt(malicious=1))
    assert verdict == database.VERDICT_SUSPICIOUS


def test_either_source_alone_can_escalate():
    """Escalation is asymmetric by design -- one source is enough."""
    from_abuse, _ = decide_verdict(abuse(90), vt(malicious=0))
    from_vt, _ = decide_verdict(abuse(0), vt(malicious=10))
    assert from_abuse == database.VERDICT_MALICIOUS
    assert from_vt == database.VERDICT_MALICIOUS


def test_no_sources_available_is_never_reported_as_clean():
    """The most dangerous failure mode a triage tool has.

    If every lookup fails -- rate limit, outage, missing key -- nothing has
    actually checked the address. Reporting CLEAN would tell an analyst it
    is safe on the strength of no evidence whatsoever.
    """
    verdict, reasons = decide_verdict(UNAVAILABLE, UNAVAILABLE, UNAVAILABLE)
    assert verdict == database.VERDICT_SUSPICIOUS
    assert any("not a clean result" in r for r in reasons)


def test_failure_reasons_name_the_source_that_failed():
    """An analyst needs to know *why* the scan could not be completed."""
    _, reasons = decide_verdict(
        {"available": False, "error": "Rate limit reached"},
        {"available": False, "error": "Invalid API key"},
        {"available": False, "error": "Connection failed"},
    )
    joined = " ".join(reasons)
    assert "AbuseIPDB: Rate limit reached" in joined
    assert "VirusTotal: Invalid API key" in joined


def test_one_working_source_reporting_nothing_is_genuinely_clean():
    """A source that answered and found nothing is real evidence."""
    verdict, _ = decide_verdict(abuse(0), UNAVAILABLE, UNAVAILABLE)
    assert verdict == database.VERDICT_CLEAN


def test_tor_exit_node_is_reported():
    _, reasons = decide_verdict(abuse(100, is_tor=True), UNAVAILABLE)
    assert any("tor" in r.lower() for r in reasons)


def test_every_verdict_carries_at_least_one_reason():
    """No verdict is ever returned bare."""
    for a, v in [(abuse(100), vt(5)), (abuse(30), vt()), (abuse(0), vt()),
                 (UNAVAILABLE, UNAVAILABLE)]:
        _, reasons = decide_verdict(a, v)
        assert len(reasons) >= 1
