"""VirusTotal client -- multi-engine reputation for IPs and URLs.

VirusTotal aggregates around 90 security vendors and reports how many of
them classify an indicator as malicious, suspicious or harmless.

Docs: https://developers.virustotal.com/reference/ip-info
      https://developers.virustotal.com/reference/url-info
"""

import base64
import time

import requests

import config


def check_ip(ip):
    """Look up *ip* on VirusTotal.

    Returns a dict with an "available" key, matching the shape used by the
    other intel clients so the scanner can treat them uniformly.
    """
    if not config.has_virustotal():
        return {"available": False, "error": "No API key configured"}

    headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}
    url = f"{config.VIRUSTOTAL_IP_URL}/{ip}"

    try:
        response = requests.get(url, headers=headers, timeout=config.REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        return {"available": False, "error": f"Connection failed: {exc}"}

    if response.status_code == 401:
        return {"available": False, "error": "Invalid API key"}
    if response.status_code == 429:
        return {"available": False, "error": "Rate limit reached (4/min on free tier)"}
    if response.status_code == 404:
        return {"available": False, "error": "IP not found in VirusTotal"}
    if response.status_code != 200:
        return {"available": False, "error": f"HTTP {response.status_code}"}

    attributes = response.json().get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    return {
        "available": True,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "total_engines": malicious + suspicious + harmless + undetected,
        "reputation": attributes.get("reputation", 0),
        "as_owner": attributes.get("as_owner"),
        "country": attributes.get("country"),
    }


# =============================================================== URL checks
def _url_identifier(url):
    """Build VirusTotal's ID for a URL.

    VirusTotal identifies a URL by its unhyphenated, unpadded base64url
    encoding rather than by a hash, so we can look up an already-analysed
    URL without submitting it first.
    """
    encoded = base64.urlsafe_b64encode(url.encode()).decode()
    return encoded.strip("=")


def _parse_url_report(attributes):
    """Turn a VirusTotal URL report into our standard result shape."""
    stats = attributes.get("last_analysis_stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    # Which vendors actually flagged it -- useful detail for an analyst.
    flagged_by = [
        engine
        for engine, res in (attributes.get("last_analysis_results") or {}).items()
        if res.get("category") in ("malicious", "suspicious")
    ]

    return {
        "available": True,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "total_engines": malicious + suspicious + harmless + undetected,
        "reputation": attributes.get("reputation", 0),
        "final_url": attributes.get("last_final_url"),
        "title": attributes.get("title"),
        "flagged_by": flagged_by[:10],
    }


def _submit_url(url, headers):
    """Submit an unseen URL for analysis, then wait for the verdict.

    VirusTotal returns an analysis id immediately but needs a few seconds
    to actually run the engines, so we poll a small number of times.
    """
    try:
        response = requests.post(
            config.VIRUSTOTAL_URL_URL,
            headers=headers,
            data={"url": url},
            timeout=config.REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        return {"available": False, "error": f"Connection failed: {exc}"}

    if response.status_code not in (200, 201):
        return {"available": False, "error": f"Submission failed: HTTP {response.status_code}"}

    analysis_id = response.json().get("data", {}).get("id")
    if not analysis_id:
        return {"available": False, "error": "VirusTotal returned no analysis id"}

    # Poll the analysis endpoint until the scan completes.
    for attempt in range(5):
        time.sleep(3)
        try:
            poll = requests.get(
                f"{config.VIRUSTOTAL_ANALYSIS_URL}/{analysis_id}",
                headers=headers,
                timeout=config.REQUEST_TIMEOUT,
            )
        except requests.RequestException:
            continue

        if poll.status_code != 200:
            continue

        body = poll.json().get("data", {}).get("attributes", {})
        if body.get("status") == "completed":
            stats = body.get("stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            return {
                "available": True,
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total_engines": malicious + suspicious + harmless + undetected,
                "reputation": 0,
                "final_url": None,
                "title": None,
                "flagged_by": [],
                "freshly_scanned": True,
            }

    return {
        "available": False,
        "error": "URL submitted but analysis did not finish in time -- try again shortly",
    }


def check_url(url):
    """Look up *url* on VirusTotal.

    Tries the existing report first. If VirusTotal has never seen the URL,
    submits it for analysis and waits for the result.
    """
    if not config.has_virustotal():
        return {"available": False, "error": "No API key configured"}

    headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}
    lookup_url = f"{config.VIRUSTOTAL_URL_URL}/{_url_identifier(url)}"

    try:
        response = requests.get(lookup_url, headers=headers, timeout=config.REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        return {"available": False, "error": f"Connection failed: {exc}"}

    if response.status_code == 200:
        return _parse_url_report(response.json().get("data", {}).get("attributes", {}))

    if response.status_code == 404:
        # Never analysed before -- submit it and wait.
        return _submit_url(url, headers)

    if response.status_code == 401:
        return {"available": False, "error": "Invalid API key"}
    if response.status_code == 429:
        return {"available": False, "error": "Rate limit reached (4/min on free tier)"}

    return {"available": False, "error": f"HTTP {response.status_code}"}


# ============================================================== File hashes
def check_hash(file_hash):
    """Look up a file hash on VirusTotal.

    Accepts MD5, SHA-1 or SHA-256. Only the hash is sent -- the file itself
    never leaves the machine.
    """
    if not config.has_virustotal():
        return {"available": False, "error": "No API key configured"}

    headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}
    url = f"{config.VIRUSTOTAL_FILE_URL}/{file_hash}"

    try:
        response = requests.get(url, headers=headers, timeout=config.REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        return {"available": False, "error": f"Connection failed: {exc}"}

    if response.status_code == 404:
        return {
            "available": False,
            "not_found": True,
            "error": "VirusTotal has never seen this file. That is not proof "
                     "it is safe -- new or targeted malware is often unknown.",
        }
    if response.status_code == 401:
        return {"available": False, "error": "Invalid API key"}
    if response.status_code == 429:
        return {"available": False, "error": "Rate limit reached (4/min on free tier)"}
    if response.status_code != 200:
        return {"available": False, "error": f"HTTP {response.status_code}"}

    attributes = response.json().get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    flagged_by = [
        engine
        for engine, res in (attributes.get("last_analysis_results") or {}).items()
        if res.get("category") in ("malicious", "suspicious")
    ]

    # VirusTotal's consensus on what family the malware belongs to.
    threat_label = (
        attributes.get("popular_threat_classification", {})
        .get("suggested_threat_label")
    )

    return {
        "available": True,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "total_engines": malicious + suspicious + harmless + undetected,
        "threat_label": threat_label,
        "file_name": attributes.get("meaningful_name"),
        "file_type": attributes.get("type_description"),
        "file_size": attributes.get("size"),
        "md5": attributes.get("md5"),
        "sha1": attributes.get("sha1"),
        "sha256": attributes.get("sha256"),
        "first_seen": attributes.get("first_submission_date"),
        "times_submitted": attributes.get("times_submitted"),
        "reputation": attributes.get("reputation", 0),
        "flagged_by": flagged_by[:12],
    }
