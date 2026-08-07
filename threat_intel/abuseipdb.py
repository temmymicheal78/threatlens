"""AbuseIPDB client -- crowd-sourced IP reputation.

AbuseIPDB collects abuse reports submitted by sysadmins worldwide and
returns a confidence score from 0 (clean) to 100 (certainly malicious).

Docs: https://docs.abuseipdb.com/#check-endpoint
"""

import requests

import config


def check_ip(ip):
    """Look up *ip* on AbuseIPDB.

    Returns a dict that always contains an "available" key so callers can
    tell a real result from a failure without catching exceptions:

        {"available": True, "abuse_score": 100, "total_reports": 42, ...}
        {"available": False, "error": "No API key configured"}
    """
    if not config.has_abuseipdb():
        return {"available": False, "error": "No API key configured"}

    headers = {
        "Key": config.ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": config.ABUSE_MAX_AGE_DAYS,
    }

    try:
        response = requests.get(
            config.ABUSEIPDB_URL,
            headers=headers,
            params=params,
            timeout=config.REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        return {"available": False, "error": f"Connection failed: {exc}"}

    if response.status_code == 401:
        return {"available": False, "error": "Invalid API key"}
    if response.status_code == 429:
        return {"available": False, "error": "Daily rate limit reached"}
    if response.status_code != 200:
        return {"available": False, "error": f"HTTP {response.status_code}"}

    data = response.json().get("data", {})

    return {
        "available": True,
        "abuse_score": data.get("abuseConfidenceScore", 0),
        "total_reports": data.get("totalReports", 0),
        "distinct_reporters": data.get("numDistinctUsers", 0),
        "country_code": data.get("countryCode"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "usage_type": data.get("usageType"),
        "is_whitelisted": data.get("isWhitelisted", False),
        "is_tor": data.get("isTor", False),
        "last_reported": data.get("lastReportedAt"),
    }
