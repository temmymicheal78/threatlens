"""Configuration and API key loading for ThreatLens.

Keys are read from a .env file that is never committed to git. Copy
.env.example to .env and paste your own keys in there.

Author: Temiloluwa Michael Ogunrinde
"""

import os
from pathlib import Path

from dotenv import load_dotenv

# Load .env from this folder into environment variables.
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


# ----------------------------------------------------------------- API keys
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")


# ---------------------------------------------------------------- endpoints
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses"
VIRUSTOTAL_URL_URL = "https://www.virustotal.com/api/v3/urls"
VIRUSTOTAL_ANALYSIS_URL = "https://www.virustotal.com/api/v3/analyses"
VIRUSTOTAL_FILE_URL = "https://www.virustotal.com/api/v3/files"
OTX_IP_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4"
GEOLOCATION_URL = "http://ip-api.com/json"

# Seconds to wait on any threat intel API before giving up.
REQUEST_TIMEOUT = 10


# --------------------------------------------------------------- thresholds
# An AbuseIPDB confidence score at or above this is treated as malicious.
# Carried over from the dissertation, which validated 50 across 20 trials.
ABUSE_SCORE_MALICIOUS = 50

# Below malicious but at or above this is worth an analyst's attention.
ABUSE_SCORE_SUSPICIOUS = 20

# Number of VirusTotal engines flagging an IP before we call it malicious.
VT_MALICIOUS_ENGINES = 3

# Number of OTX community pulses before an indicator is treated as malicious.
# A single pulse can be one researcher's broad sweep; several independent
# pulses mean the address keeps resurfacing across separate investigations.
OTX_PULSE_MALICIOUS = 3

# How far back AbuseIPDB should look when counting reports.
ABUSE_MAX_AGE_DAYS = 90

# Domain age thresholds, in days. Phishing campaigns overwhelmingly run on
# freshly registered domains, because the old ones have already been burned.
DOMAIN_AGE_HIGH_RISK_DAYS = 7
DOMAIN_AGE_SUSPICIOUS_DAYS = 30

# Words that commonly appear in phishing subject lines. Manufactured urgency
# is the oldest trick in social engineering -- on their own these prove
# nothing, but combined with failed authentication they raise confidence.
PHISHING_KEYWORDS = [
    "urgent", "verify your account", "suspended", "unusual activity",
    "confirm your identity", "click here", "act now", "final notice",
    "your account will be", "security alert", "payment failed",
    "update your payment", "unauthorised login", "unauthorized login",
    "password expires", "immediate action", "limited time",
]


# ------------------------------------------------------------------ helpers
def has_abuseipdb() -> bool:
    """True if an AbuseIPDB key is configured."""
    return bool(ABUSEIPDB_API_KEY)


def has_virustotal() -> bool:
    """True if a VirusTotal key is configured."""
    return bool(VIRUSTOTAL_API_KEY)


def has_otx() -> bool:
    """True if an AlienVault OTX key is configured."""
    return bool(OTX_API_KEY)


def missing_keys() -> list:
    """Return the names of any intel services with no key configured.

    The scanner still runs without them -- it just uses fewer sources and
    says so on screen, rather than crashing.

    OTX is excluded here on purpose: it is an optional third opinion, so a
    missing OTX key should not raise a warning on every scan page.
    """
    missing = []
    if not has_abuseipdb():
        missing.append("AbuseIPDB")
    if not has_virustotal():
        missing.append("VirusTotal")
    return missing
