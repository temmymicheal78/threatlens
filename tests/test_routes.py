"""Tests for the Flask routes.

These deliberately avoid triggering live API calls: pages are fetched with
GET, and POSTs use input that fails validation before any network request is
made. The one exception patches the scanner module directly.
"""

import pytest

import app as flask_app
import database


@pytest.fixture
def client():
    flask_app.app.config["TESTING"] = True
    with flask_app.app.test_client() as test_client:
        yield test_client


# -------------------------------------------------------------------- pages
@pytest.mark.parametrize("route", ["/", "/ip", "/url", "/email", "/file", "/history"])
def test_every_page_loads(client, route):
    assert client.get(route).status_code == 200


def test_unknown_route_is_404(client):
    assert client.get("/does-not-exist").status_code == 404


def test_navigation_links_every_page(client):
    body = client.get("/").get_data(as_text=True)
    for route in ["/ip", "/url", "/email", "/file", "/history"]:
        assert f'href="{route}"' in body


# ---------------------------------------------------------------- dashboard
def test_empty_dashboard_shows_an_empty_state(client):
    body = client.get("/").get_data(as_text=True)
    assert "No scans recorded yet" in body


def test_dashboard_hides_charts_when_there_is_no_data(client):
    """Charts of nothing are noise, so they only appear once data exists."""
    assert "<canvas" not in client.get("/").get_data(as_text=True)


def test_dashboard_shows_charts_and_scans_once_data_exists(client):
    database.save_scan("185.220.101.10", "IP", "MALICIOUS", "AbuseIPDB", "tor")
    body = client.get("/").get_data(as_text=True)
    assert body.count("<canvas") == 3
    assert "185.220.101.10" in body
    assert "badge-malicious" in body


# ----------------------------------------------------------- input handling
@pytest.mark.parametrize("route,field,value", [
    ("/ip", "ip", "192.168.1.1"),
    ("/ip", "ip", "not-an-ip"),
    ("/ip", "ip", ""),
    ("/url", "url", "not a url"),
    ("/url", "url", "ftp://files.com"),
    ("/url", "url", ""),
    ("/email", "raw_email", ""),
    ("/email", "raw_email", "no headers here"),
    ("/file", "hash", "zzz"),
    ("/file", "hash", ""),
])
def test_invalid_input_shows_an_error_without_crashing(client, route, field, value):
    response = client.post(route, data={field: value})
    assert response.status_code == 200
    assert "error-msg" in response.get_data(as_text=True)


def test_invalid_input_is_not_recorded(client):
    """Rejected input must not pollute the scan history."""
    client.post("/ip", data={"ip": "192.168.1.1"})
    assert database.get_stats()["total_scans"] == 0


# --------------------------------------------------------------- scan flow
def test_successful_scan_is_saved_and_shown(client, monkeypatch):
    """Patches the scanner so the route is tested without a live API call."""
    monkeypatch.setattr(flask_app.ip_module, "scan", lambda raw: {
        "ok": True, "ip": "185.220.101.10", "verdict": "MALICIOUS",
        "reasons": ["AbuseIPDB confidence 100%"], "sources": "AbuseIPDB",
        "abuse": {"available": False, "error": "stub"},
        "virustotal": {"available": False, "error": "stub"},
        "geo": {"available": False, "error": "stub"},
    })

    body = client.post("/ip", data={"ip": "185.220.101.10"}).get_data(as_text=True)
    assert "verdict-malicious" in body
    assert "AbuseIPDB confidence 100%" in body


# ----------------------------------------------------------------- history
def test_history_filters_by_type(client):
    database.save_scan("8.8.8.8", "IP", "CLEAN", "t", "x")
    database.save_scan("a@b.com", "EMAIL", "CLEAN", "t", "x")

    body = client.get("/history?type=IP").get_data(as_text=True)
    assert "8.8.8.8" in body
    assert "a@b.com" not in body


def test_history_search_is_injection_safe(client):
    database.save_scan("8.8.8.8", "IP", "CLEAN", "t", "x")
    body = client.get("/history?q=' OR 1=1--").get_data(as_text=True)
    assert "8.8.8.8" not in body
    assert database.get_stats()["total_scans"] == 1


def test_history_shows_a_message_when_filters_match_nothing(client):
    database.save_scan("8.8.8.8", "IP", "CLEAN", "t", "x")
    body = client.get("/history?verdict=MALICIOUS").get_data(as_text=True)
    assert "No scans match" in body


# ------------------------------------------------------------------ uploads
def test_oversized_upload_is_rejected_gracefully(client):
    """The 32 MB cap must produce a readable message, not a bare 413."""
    oversized = b"x" * (33 * 1024 * 1024)
    response = client.post(
        "/file",
        data={"hash": "", "file": (__import__("io").BytesIO(oversized), "big.bin")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 413
    assert "32 MB" in response.get_data(as_text=True)
