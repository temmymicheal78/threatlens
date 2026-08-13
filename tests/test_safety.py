"""Guard tests -- these protect the real scan history from the test suite.

If conftest.py ever stops redirecting the database, these fail loudly rather
than letting the suite quietly pollute real data.
"""

from pathlib import Path

import database


REAL_DB = Path(__file__).resolve().parent.parent / "threatlens.db"


def test_tests_do_not_use_the_real_database():
    """The suite must never point at the production database file."""
    assert database.DB_PATH != REAL_DB
    assert "pytest" in str(database.DB_PATH)


def test_real_database_is_untouched_by_writes():
    """Writing during a test must not create or alter the real database."""
    before = REAL_DB.stat().st_mtime if REAL_DB.exists() else None

    database.save_scan("203.0.113.1", "IP", "CLEAN", "test", "guard test")

    after = REAL_DB.stat().st_mtime if REAL_DB.exists() else None
    assert before == after
