"""Geolocation client -- where an IP physically sits, and who owns it.

Uses ip-api.com, which needs no API key on the free tier (45 requests per
minute). Location and ASN are context rather than a verdict: they help an
analyst judge whether traffic from an IP is plausible for their estate.

Docs: https://ip-api.com/docs/api:json
"""

import requests

import config

# ip-api's default response leaves out the anonymisation flags, so every
# field is named explicitly. proxy covers VPN, proxy and Tor exits; hosting
# covers data centres and cloud providers. All are free on this tier.
FIELDS = (
    "status,message,country,countryCode,regionName,city,isp,org,as,"
    "timezone,lat,lon,proxy,hosting,mobile"
)


def lookup(ip):
    """Return geolocation and network ownership details for *ip*."""
    try:
        response = requests.get(
            f"{config.GEOLOCATION_URL}/{ip}",
            params={"fields": FIELDS},
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
        "proxy": data.get("proxy"),
        "hosting": data.get("hosting"),
        "mobile": data.get("mobile"),
    }
