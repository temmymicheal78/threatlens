"""AlienVault OTX client -- community threat intelligence pulses.

OTX differs from AbuseIPDB and VirusTotal in a useful way: instead of a
score, it returns the named campaigns ("pulses") an indicator appears in.
That gives an analyst context -- not just *that* an address is bad, but
which campaign it belongs to.

Docs: https://otx.alienvault.com/api
"""

import requests

import config


def check_ip(ip):
    """Look up *ip* on AlienVault OTX.

    Returns the same dict shape as the other intel clients, so the scanner
    can treat every source uniformly.
    """
    if not config.has_otx():
        return {"available": False, "error": "No API key configured"}

    headers = {"X-OTX-API-KEY": config.OTX_API_KEY}
    url = f"{config.OTX_IP_URL}/{ip}/general"

    try:
        response = requests.get(url, headers=headers, timeout=config.REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        return {"available": False, "error": f"Connection failed: {exc}"}

    if response.status_code in (401, 403):
        return {"available": False, "error": "Invalid API key"}
    if response.status_code == 404:
        return {"available": False, "error": "IP not found in OTX"}
    if response.status_code != 200:
        return {"available": False, "error": f"HTTP {response.status_code}"}

    data = response.json()
    pulse_info = data.get("pulse_info") or {}
    pulses = pulse_info.get("pulses") or []

    # Pulse names describe the campaign an indicator was reported under.
    names = [p.get("name") for p in pulses if p.get("name")]

    # Tags collapse many pulses into a few recurring themes.
    tags = []
    for pulse in pulses:
        for tag in pulse.get("tags") or []:
            if tag not in tags:
                tags.append(tag)

    return {
        "available": True,
        "pulse_count": pulse_info.get("count", len(pulses)),
        "pulse_names": names[:6],
        "tags": tags[:10],
        "reputation": data.get("reputation", 0),
        "country": data.get("country_name"),
        "asn": data.get("asn"),
    }
