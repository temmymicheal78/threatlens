"""Tests for VPN, proxy, Tor and hosting detection on the IP scanner.

The property that matters most: anonymisation is context and must never
change a verdict. The second: an unanswered source is reported as unknown,
never as a reassuring "No".
"""

import pytest

import app as flask_app
import database
from modules import ip_scanner
from modules.ip_scanner import assess_anonymisation
from threat_intel import geolocation

UNAVAILABLE = {"available": False, "error": "unavailable"}


def abuse(**fields):
    base = {"available": True, "abuse_score": 0, "total_reports": 0,
            "distinct_reporters": 0, "is_tor": False,
            "usage_type": "Fixed Line ISP"}
    base.update(fields)
    return base


def geo(**fields):
    base = {"available": True, "country": "Germany", "proxy": False,
            "hosting": False, "mobile": False}
    base.update(fields)
    return base


def otx(tags):
    return {"available": True, "pulse_count": 0, "tags": tags}


# ------------------------------------------------------------ detection
def test_vpn_or_proxy_is_detected():
    result = assess_anonymisation(abuse(), geo(proxy=True))
    assert result["proxy"] is True
    assert result["flagged"] is True
    assert any("VPN or proxy" in note for note in result["notes"])


def test_hosting_is_detected_from_ip_api():
    result = assess_anonymisation(abuse(), geo(hosting=True))
    assert result["hosting"] is True
    assert any("data-centre" in note for note in result["notes"])


def test_hosting_is_detected_from_abuseipdb_usage_type_alone():
    """A second source can answer when ip-api is down."""
    result = assess_anonymisation(
        abuse(usage_type="Data Center/Web Hosting/Transit"), UNAVAILABLE
    )
    assert result["hosting"] is True


def test_tor_is_detected_but_not_repeated_in_notes():
    """decide_verdict already reports Tor; saying it twice is noise."""
    result = assess_anonymisation(abuse(is_tor=True), geo())
    assert result["tor"] is True
    assert result["flagged"] is True
    assert not any("tor" in note.lower() for note in result["notes"])


def test_mobile_network_is_explained():
    result = assess_anonymisation(abuse(), geo(mobile=True))
    assert result["mobile"] is True
    assert any("mobile network" in note for note in result["notes"])


def test_residential_address_is_clear():
    result = assess_anonymisation(abuse(), geo())
    assert (result["tor"], result["proxy"], result["hosting"]) == (False, False, False)
    assert result["flagged"] is False
    assert result["summary"].startswith("No sign of")
    assert result["notes"] == []


# ------------------------------------------------- honesty about unknowns
def test_no_sources_means_unknown_never_no():
    """The same principle as the fail-safe fix: unchecked is not clear."""
    result = assess_anonymisation(UNAVAILABLE, UNAVAILABLE)
    assert result["tor"] is None
    assert result["proxy"] is None
    assert result["hosting"] is None
    assert result["flagged"] is False
    assert "Could not be assessed" in result["summary"]


def test_partial_answers_say_so():
    """AbuseIPDB answered, ip-api did not -- proxy status is genuinely unknown."""
    result = assess_anonymisation(abuse(), UNAVAILABLE)
    assert result["tor"] is False
    assert result["proxy"] is None
    assert "not every source" in result["summary"]


def test_any_yes_outweighs_a_no():
    """One source seeing hosting is enough, even if another did not."""
    result = assess_anonymisation(
        abuse(usage_type="Data Center/Web Hosting/Transit"), geo(hosting=False)
    )
    assert result["hosting"] is True


# ------------------------------------------------------------- OTX tags
def test_otx_anonymiser_tags_are_picked_out():
    result = assess_anonymisation(
        abuse(), geo(), otx(["webscanner", "Open Proxy", "tor-exit", "bruteforce"])
    )
    assert result["otx_tags"] == ["Open Proxy", "tor-exit"]
    assert result["flagged"] is True


@pytest.mark.parametrize("tag", ["monitor", "threat actor", "detector", "vendor"])
def test_tag_matching_uses_whole_words_not_substrings(tag):
    """'tor' must not match inside 'monitor' or 'actor'."""
    result = assess_anonymisation(abuse(), geo(), otx([tag]))
    assert result["otx_tags"] == []


# ------------------------------------------- context never changes verdict
def _patch_sources(monkeypatch, abuse_result, geo_result):
    monkeypatch.setattr(ip_scanner.abuseipdb, "check_ip", lambda ip: abuse_result)
    monkeypatch.setattr(ip_scanner.virustotal, "check_ip",
                        lambda ip: {"available": True, "malicious": 0,
                                    "suspicious": 0})
    monkeypatch.setattr(ip_scanner.otx, "check_ip", lambda ip: UNAVAILABLE)
    monkeypatch.setattr(ip_scanner.geolocation, "lookup", lambda ip: geo_result)


def test_anonymised_but_clean_address_stays_clean(monkeypatch):
    """A VPN on a cloud host with no bad reputation is not malicious."""
    _patch_sources(monkeypatch, abuse(), geo(proxy=True, hosting=True))

    result = ip_scanner.scan("8.8.4.4")

    assert result["verdict"] == database.VERDICT_CLEAN
    assert result["anonymisation"]["flagged"] is True
    assert any("VPN or proxy" in r for r in result["reasons"])


def test_anonymisation_notes_are_saved_to_history(monkeypatch):
    _patch_sources(monkeypatch, abuse(), geo(proxy=True))
    ip_scanner.scan("8.8.4.4")
    saved = database.search_scans(query="8.8.4.4")[0]
    assert "VPN or proxy" in saved["details"]


def test_malicious_verdict_is_unchanged_by_anonymisation(monkeypatch):
    _patch_sources(monkeypatch, abuse(abuse_score=100, is_tor=True), geo(proxy=True))
    result = ip_scanner.scan("8.8.4.4")
    assert result["verdict"] == database.VERDICT_MALICIOUS


# ------------------------------------------------------------ ip-api call
def test_geolocation_requests_the_anonymisation_fields(monkeypatch):
    """ip-api omits proxy, hosting and mobile unless they are asked for."""
    captured = {}

    class FakeResponse:
        status_code = 200

        def json(self):
            return {"status": "success", "country": "Germany",
                    "proxy": True, "hosting": True, "mobile": False}

    def fake_get(url, params=None, timeout=None):
        captured["params"] = params
        return FakeResponse()

    monkeypatch.setattr(geolocation.requests, "get", fake_get)
    result = geolocation.lookup("8.8.4.4")

    for field in ("proxy", "hosting", "mobile"):
        assert field in captured["params"]["fields"]
    assert result["proxy"] is True
    assert result["hosting"] is True
    assert result["mobile"] is False


# ----------------------------------------------------------------- page
@pytest.fixture
def client():
    flask_app.app.config["TESTING"] = True
    with flask_app.app.test_client() as test_client:
        yield test_client


def test_panel_renders_yes_no_and_unknown(monkeypatch, client):
    _patch_sources(monkeypatch, abuse(), geo(proxy=True, mobile=None))
    body = client.post("/ip", data={"ip": "8.8.4.4"}).get_data(as_text=True)

    assert "Anonymisation" in body
    assert "flag-yes" in body          # VPN / proxy
    assert "flag-no" in body           # Tor, hosting
    assert "flag-unknown" in body      # mobile not reported
    assert "Context, not a verdict" in body
