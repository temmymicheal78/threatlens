"""Shared pytest configuration for ThreatLens.

The single most important thing this file does is redirect the database to a
throwaway file *before* database.py is ever imported. Without it, running the
test suite would write test scans into the real scan history.

pytest loads conftest.py before any test module, so setting the environment
variable here happens early enough for database.DB_PATH to pick it up.
"""

import os
import tempfile
from pathlib import Path

# Must run at import time, before any test imports database.py.
TEST_DB = Path(tempfile.gettempdir()) / "threatlens_pytest.db"
os.environ["THREATLENS_DB"] = str(TEST_DB)

import pytest  # noqa: E402  (import order is deliberate)

import database  # noqa: E402


@pytest.fixture(autouse=True)
def clean_database():
    """Give every test an empty database, and tidy up afterwards."""
    if TEST_DB.exists():
        TEST_DB.unlink()

    database.init_db()
    yield

    if TEST_DB.exists():
        TEST_DB.unlink()


@pytest.fixture
def phishing_email():
    """A raw email exhibiting every phishing indicator the analyzer checks."""
    return (
        "Received: from mail.evil-host.ru (mail.evil-host.ru [185.220.101.10])"
        " by mx.google.com with ESMTP\n"
        "Received: from internal.relay (internal.relay [10.0.0.5])"
        " by mail.evil-host.ru with SMTP\n"
        "Authentication-Results: mx.google.com; spf=fail"
        " smtp.mailfrom=paypa1-secure.xyz; dkim=fail;"
        " dmarc=fail header.from=paypal.com\n"
        'From: "PayPal Support" <support@paypa1-secure.xyz>\n'
        "Return-Path: <bounce@evil-host.ru>\n"
        "Reply-To: <collect@another-domain.tk>\n"
        "Subject: URGENT: Your account will be suspended - verify your account\n"
        "\n"
        "Click http://paypa1-secure.xyz/verify now.\n"
    )


@pytest.fixture
def legitimate_email():
    """A raw email that passes every authentication check."""
    return (
        "Received: from mail-wr1.google.com (mail-wr1.google.com"
        " [209.85.221.41]) by mx.example.com with ESMTPS\n"
        "Authentication-Results: mx.example.com; spf=pass"
        " smtp.mailfrom=github.com; dkim=pass header.d=github.com;"
        " dmarc=pass header.from=github.com\n"
        "From: GitHub <noreply@github.com>\n"
        "Return-Path: <noreply@github.com>\n"
        "Subject: [GitHub] A new sign-in to your account\n"
        "\n"
        "A new device signed in. https://github.com/settings/security\n"
    )
