"""SQLite persistence for ThreatLens.

Every scan run by any module (IP, URL, email, file hash) is recorded here,
giving the dashboard its statistics and an audit trail of past lookups.

Author: Temiloluwa Michael Ogunrinde
"""

import os
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

# Database lives next to this file, so it works no matter where you run from.
# THREATLENS_DB redirects it elsewhere -- used when testing, so that test
# scans never end up mixed into the real scan history.
DB_PATH = Path(
    os.environ.get("THREATLENS_DB", Path(__file__).resolve().parent / "threatlens.db")
)

# Verdicts a scanner may record. These match the CSS badge classes.
VERDICT_MALICIOUS = "MALICIOUS"
VERDICT_SUSPICIOUS = "SUSPICIOUS"
VERDICT_CLEAN = "CLEAN"


def get_connection():
    """Open a connection to the ThreatLens database.

    row_factory makes rows behave like dictionaries, so we can write
    row["verdict"] instead of remembering that verdict is column 3.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create the scans table if it does not already exist.

    Safe to call every time the app starts -- IF NOT EXISTS means an
    existing table with your data is left untouched.
    """
    conn = get_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator      TEXT NOT NULL,
            indicator_type TEXT NOT NULL,
            verdict        TEXT NOT NULL,
            source         TEXT,
            details        TEXT,
            scanned_at     TEXT NOT NULL
        )
        """
    )
    # Index on scanned_at because the dashboard always sorts by newest first.
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_time ON scans (scanned_at DESC)")
    conn.commit()
    conn.close()


def save_scan(indicator, indicator_type, verdict, source=None, details=None):
    """Record one completed scan and return its new row id.

    indicator      -- what was scanned, e.g. "185.220.101.10"
    indicator_type -- "IP", "URL", "EMAIL" or "HASH"
    verdict        -- "MALICIOUS", "SUSPICIOUS" or "CLEAN"
    source         -- which intel service answered, e.g. "AbuseIPDB"
    details        -- optional free-text summary shown to the analyst
    """
    conn = get_connection()
    cursor = conn.execute(
        """
        INSERT INTO scans (indicator, indicator_type, verdict, source, details, scanned_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            indicator,
            indicator_type,
            verdict.upper(),
            source,
            details,
            datetime.now().isoformat(timespec="seconds"),
        ),
    )
    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()
    return scan_id


def get_stats():
    """Return the four headline numbers shown on the dashboard cards.

    A "threat" is anything not clean -- malicious or suspicious -- because
    a SOC analyst needs to look at both.
    """
    conn = get_connection()

    total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]

    threats = conn.execute(
        "SELECT COUNT(*) FROM scans WHERE verdict IN (?, ?)",
        (VERDICT_MALICIOUS, VERDICT_SUSPICIOUS),
    ).fetchone()[0]

    clean = conn.execute(
        "SELECT COUNT(*) FROM scans WHERE verdict = ?", (VERDICT_CLEAN,)
    ).fetchone()[0]

    row = conn.execute("SELECT MAX(scanned_at) FROM scans").fetchone()
    conn.close()

    return {
        "total_scans": total,
        "threats": threats,
        "clean": clean,
        "last_scan": _format_time(row[0]) if row[0] else "Never",
    }


def get_recent_scans(limit=10):
    """Return the most recent scans, newest first, as a list of dicts."""
    conn = get_connection()
    rows = conn.execute(
        """
        SELECT indicator, indicator_type AS type, verdict, source, scanned_at
        FROM scans
        -- id breaks ties: timestamps are second-precision, so two scans in
        -- the same second would otherwise come back in arbitrary order.
        ORDER BY scanned_at DESC, id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()

    scans = []
    for row in rows:
        scan = dict(row)
        scan["scanned_at"] = _format_time(scan["scanned_at"])
        scans.append(scan)
    return scans


def search_scans(indicator_type=None, verdict=None, query=None, limit=300):
    """Return scans matching the given filters, newest first.

    Any filter left as None is ignored, so one function serves both the
    unfiltered history page and every combination of filters.
    """
    sql = [
        "SELECT indicator, indicator_type AS type, verdict, source, details,",
        "       scanned_at",
        "FROM scans",
        "WHERE 1 = 1",
    ]
    params = []

    if indicator_type:
        sql.append("AND indicator_type = ?")
        params.append(indicator_type)

    if verdict:
        sql.append("AND verdict = ?")
        params.append(verdict)

    if query:
        sql.append("AND indicator LIKE ?")
        params.append(f"%{query}%")

    # id breaks ties between scans saved within the same second.
    sql.append("ORDER BY scanned_at DESC, id DESC LIMIT ?")
    params.append(limit)

    conn = get_connection()
    rows = conn.execute(" ".join(sql), params).fetchall()
    conn.close()

    scans = []
    for row in rows:
        scan = dict(row)
        scan["scanned_at"] = _format_time(scan["scanned_at"])
        scans.append(scan)
    return scans


def get_indicator_types():
    """Distinct indicator types present, for populating the filter menu."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT DISTINCT indicator_type FROM scans ORDER BY indicator_type"
    ).fetchall()
    conn.close()
    return [row["indicator_type"] for row in rows]


def get_verdict_breakdown():
    """Count of scans per verdict, for the dashboard's share chart."""
    conn = get_connection()
    rows = conn.execute(
        """
        SELECT verdict, COUNT(*) AS count
        FROM scans
        GROUP BY verdict
        """
    ).fetchall()
    conn.close()

    counts = {row["verdict"]: row["count"] for row in rows}

    # Return a fixed order so the chart's colours never shuffle between loads.
    return [
        {"verdict": v, "count": counts.get(v, 0)}
        for v in (VERDICT_MALICIOUS, VERDICT_SUSPICIOUS, VERDICT_CLEAN)
    ]


def get_type_breakdown():
    """Count of scans per indicator type, highest first."""
    conn = get_connection()
    rows = conn.execute(
        """
        SELECT indicator_type AS type, COUNT(*) AS count
        FROM scans
        GROUP BY indicator_type
        ORDER BY count DESC
        """
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_daily_activity(days=14):
    """Scans per day over the last *days* days, oldest first.

    Days with no scans are filled in with zero so the line does not jump
    across missing dates and imply activity that never happened.
    """
    conn = get_connection()
    rows = conn.execute(
        """
        SELECT substr(scanned_at, 1, 10) AS day, COUNT(*) AS count
        FROM scans
        GROUP BY day
        """
    ).fetchall()
    conn.close()

    counts = {row["day"]: row["count"] for row in rows}

    today = datetime.now().date()
    series = []
    for offset in range(days - 1, -1, -1):
        day = today - timedelta(days=offset)
        key = day.isoformat()
        series.append({
            "day": key,
            "label": day.strftime("%d %b"),
            "count": counts.get(key, 0),
        })
    return series


def _format_time(iso_string):
    """Turn a stored ISO timestamp into something readable on screen."""
    try:
        return datetime.fromisoformat(iso_string).strftime("%d %b %Y, %H:%M")
    except (ValueError, TypeError):
        return iso_string


# Running "python database.py" directly creates the database for you.
if __name__ == "__main__":
    init_db()
    print(f"Database ready at: {DB_PATH}")
