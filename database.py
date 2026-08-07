"""SQLite persistence for ThreatLens.

Every scan run by any module (IP, URL, email, file hash) is recorded here,
giving the dashboard its statistics and an audit trail of past lookups.

Author: Temiloluwa Michael Ogunrinde
"""

import os
import sqlite3
from datetime import datetime
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
        ORDER BY scanned_at DESC
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
