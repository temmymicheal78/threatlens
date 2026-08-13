"""Tests for persistence, statistics and history filtering.

Every test runs against a throwaway database created fresh by the autouse
fixture in conftest.py.
"""

import database


def seed():
    """Insert a small, known set of scans covering every verdict and type."""
    database.save_scan("185.220.101.10", "IP", "MALICIOUS", "AbuseIPDB", "tor exit")
    database.save_scan("8.8.8.8", "IP", "CLEAN", "AbuseIPDB", "no reports")
    database.save_scan("http://evil.xyz", "URL", "SUSPICIOUS", "VirusTotal", "new domain")
    database.save_scan("a@b.com", "EMAIL", "MALICIOUS", "Header analysis", "dmarc fail")


# ------------------------------------------------------------------- inserts
def test_init_db_is_safe_to_run_twice():
    """Startup calls it every time; existing data must survive."""
    database.save_scan("1.1.1.1", "IP", "CLEAN", "test", "first")
    database.init_db()
    assert database.get_stats()["total_scans"] == 1


def test_save_scan_returns_a_row_id():
    assert database.save_scan("1.1.1.1", "IP", "CLEAN", "test", "x") is not None


def test_verdict_is_stored_uppercase():
    database.save_scan("1.1.1.1", "IP", "clean", "test", "lowercase input")
    assert database.get_recent_scans()[0]["verdict"] == "CLEAN"


def test_optional_fields_may_be_omitted():
    database.save_scan("1.1.1.1", "IP", "CLEAN")
    assert database.get_stats()["total_scans"] == 1


# ---------------------------------------------------------------- statistics
def test_empty_database_reports_zeroes():
    stats = database.get_stats()
    assert stats["total_scans"] == 0
    assert stats["last_scan"] == "Never"


def test_threat_count_includes_suspicious():
    """An analyst needs eyes on suspicious, not only malicious."""
    seed()
    stats = database.get_stats()
    assert stats["total_scans"] == 4
    assert stats["threats"] == 3
    assert stats["clean"] == 1


def test_last_scan_is_formatted_for_display():
    seed()
    assert database.get_stats()["last_scan"] != "Never"
    assert "T" not in database.get_stats()["last_scan"]


# ------------------------------------------------------------------ ordering
def test_recent_scans_are_newest_first():
    database.save_scan("first@x.com", "EMAIL", "CLEAN", "t", "1")
    database.save_scan("second@x.com", "EMAIL", "CLEAN", "t", "2")
    assert database.get_recent_scans()[0]["indicator"] == "second@x.com"


def test_recent_scans_respects_its_limit():
    for i in range(10):
        database.save_scan(f"10.0.0.{i}", "IP", "CLEAN", "t", "x")
    assert len(database.get_recent_scans(limit=3)) == 3


# ------------------------------------------------------------------- charts
def test_verdict_breakdown_uses_a_fixed_order():
    """Fixed order keeps the chart's colours from shuffling between loads."""
    seed()
    order = [row["verdict"] for row in database.get_verdict_breakdown()]
    assert order == ["MALICIOUS", "SUSPICIOUS", "CLEAN"]


def test_verdict_breakdown_includes_absent_verdicts_as_zero():
    database.save_scan("1.1.1.1", "IP", "CLEAN", "t", "x")
    counts = {r["verdict"]: r["count"] for r in database.get_verdict_breakdown()}
    assert counts["MALICIOUS"] == 0
    assert counts["CLEAN"] == 1


def test_type_breakdown_is_ordered_by_count():
    seed()
    rows = database.get_type_breakdown()
    assert rows[0]["type"] == "IP"
    assert rows[0]["count"] == 2


def test_daily_activity_fills_missing_days_with_zero():
    """Without zero-filling, the line would imply activity on empty days."""
    seed()
    activity = database.get_daily_activity(days=14)
    assert len(activity) == 14
    assert sum(day["count"] for day in activity) == 4
    assert activity[0]["count"] == 0


# ------------------------------------------------------------------ history
def test_search_with_no_filters_returns_everything():
    seed()
    assert len(database.search_scans()) == 4


def test_filter_by_type():
    seed()
    assert len(database.search_scans(indicator_type="IP")) == 2


def test_filter_by_verdict():
    seed()
    assert len(database.search_scans(verdict="MALICIOUS")) == 2


def test_filters_combine():
    seed()
    results = database.search_scans(indicator_type="IP", verdict="MALICIOUS")
    assert len(results) == 1
    assert results[0]["indicator"] == "185.220.101.10"


def test_substring_search():
    seed()
    assert len(database.search_scans(query="185.220")) == 1


def test_search_matching_nothing_returns_empty():
    seed()
    assert database.search_scans(query="nothing-matches-this") == []


def test_search_is_not_vulnerable_to_sql_injection():
    """A classic injection string must be treated as a literal, not SQL."""
    seed()
    assert database.search_scans(query="' OR 1=1--") == []
    assert database.get_stats()["total_scans"] == 4


def test_indicator_types_are_distinct_and_sorted():
    seed()
    assert database.get_indicator_types() == ["EMAIL", "IP", "URL"]
