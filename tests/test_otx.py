"""Tests for OTX's contribution to the IP verdict.

OTX is a third opinion rather than a required source, so the key property
under test is that its absence changes nothing.
"""

import database
from modules.ip_scanner import decide_verdict

CLEAN_ABUSE = {"available": True, "abuse_score": 0, "total_reports": 0,
               "distinct_reporters": 0}
NO_VT = {"available": False, "error": "no key"}
NO_OTX = {"available": False, "error": "No API key configured"}


def otx(pulses, names=None, tags=None):
    return {"available": True, "pulse_count": pulses,
            "pulse_names": names or [], "tags": tags or []}


def test_omitting_otx_entirely_still_works():
    """Backwards compatible: the third argument is optional."""
    verdict, reasons = decide_verdict(CLEAN_ABUSE, NO_VT)
    assert verdict == database.VERDICT_CLEAN
    assert reasons


def test_unavailable_otx_does_not_change_the_verdict():
    with_otx, _ = decide_verdict(CLEAN_ABUSE, NO_VT, NO_OTX)
    without, _ = decide_verdict(CLEAN_ABUSE, NO_VT)
    assert with_otx == without == database.VERDICT_CLEAN


def test_many_pulses_is_malicious():
    verdict, reasons = decide_verdict(CLEAN_ABUSE, NO_VT, otx(7))
    assert verdict == database.VERDICT_MALICIOUS
    assert any("7 OTX" in r for r in reasons)


def test_pulse_count_at_threshold_is_malicious():
    verdict, _ = decide_verdict(CLEAN_ABUSE, NO_VT, otx(3))
    assert verdict == database.VERDICT_MALICIOUS


def test_one_pulse_is_only_suspicious():
    """A single pulse can be one researcher's broad sweep."""
    verdict, _ = decide_verdict(CLEAN_ABUSE, NO_VT, otx(1))
    assert verdict == database.VERDICT_SUSPICIOUS


def test_zero_pulses_stays_clean():
    verdict, _ = decide_verdict(CLEAN_ABUSE, NO_VT, otx(0))
    assert verdict == database.VERDICT_CLEAN


def test_campaign_names_are_reported():
    _, reasons = decide_verdict(
        CLEAN_ABUSE, NO_VT, otx(5, names=["Emotet C2", "Cobalt Strike"])
    )
    assert any("Emotet C2" in r for r in reasons)


def test_otx_can_escalate_when_other_sources_are_silent():
    """Any single source is enough -- that is the design."""
    verdict, _ = decide_verdict(CLEAN_ABUSE, {"available": True, "malicious": 0,
                                              "suspicious": 0}, otx(10))
    assert verdict == database.VERDICT_MALICIOUS
