"""Geolocation client -- where an IP physically sits, and who owns it.

Uses ip-api.com, which needs no API key on the free tier (45 requests per
minute). Location and ASN are context rather than a verdict: they help an
analyst judge whether traffic from an IP is plausible for their estate.

Docs: https://ip-api.com/docs/api:json
"""

import requests

import config


def lookup(ip):
    """Return geolocation and network ownership details for *ip*."""
    try:
        response = requests.get(
            f"{config.GEOLOCATION_URL}/{ip}",
            timeout=config.REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        return {"available": False, "error": f"Connection failed: {exc}"}

    if response.status_code != 200:
        return {"available": False, "error": f"HTTP {response.status_code}"}

    data = response.json()

    # ip-api reports its own failures in the body, not the status code.
    if data.get("status") != "success":
        return {"available": False, "error": data.get("message", "Lookup failed")}

    return {
        "available": True,
        "country": data.get("country"),
        "country_code": data.get("countryCode"),
        "region": data.get("regionName"),
        "city": data.get("city"),
        "isp": data.get("isp"),
        "org": data.get("org"),
        "asn": data.get("as"),
        "timezone": data.get("timezone"),
        "lat": data.get("lat"),
        "lon": data.get("lon"),
    }
