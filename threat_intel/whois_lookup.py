"""WHOIS client -- domain registration details, above all the domain's age.

Domain age is one of the strongest phishing signals available. Legitimate
businesses run on domains registered years ago; phishing campaigns run on
domains registered days ago, because older ones have already been blocked.

Requires the python-whois package:  pip install python-whois
"""

from datetime import datetime, timezone

import config

try:
    import whois as whois_lib
    WHOIS_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on local install
    WHOIS_AVAILABLE = False


def _first(value):
    """WHOIS fields are sometimes a list of dates rather than one date."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _age_in_days(created):
    """Days between *created* and now, or None if the date is unusable."""
    if not isinstance(created, datetime):
        return None

    # Some registrars return timezone-aware dates and others do not;
    # normalise to naive UTC so the subtraction cannot raise.
    if created.tzinfo is not None:
        created = created.astimezone(timezone.utc).replace(tzinfo=None)

    return (datetime.utcnow() - created).days


def lookup(domain):
    """Return registration details and age for *domain*."""
    if not WHOIS_AVAILABLE:
        return {
            "available": False,
            "error": "python-whois not installed -- run: pip install python-whois",
        }

    try:
        record = whois_lib.whois(domain)
    except Exception as exc:  # the library raises many different types
        return {"available": False, "error": f"WHOIS lookup failed: {exc}"}

    if not record or not record.get("domain_name"):
        return {"available": False, "error": "No WHOIS record found for this domain"}

    created = _first(record.get("creation_date"))
    expires = _first(record.get("expiration_date"))
    age_days = _age_in_days(created)

    return {
        "available": True,
        "domain": domain,
        "registrar": record.get("registrar"),
        "created": created.strftime("%d %b %Y") if isinstance(created, datetime) else None,
        "expires": expires.strftime("%d %b %Y") if isinstance(expires, datetime) else None,
        "age_days": age_days,
        "age_label": describe_age(age_days),
        "country": record.get("country"),
        "name_servers": _name_servers(record.get("name_servers")),
    }


def _name_servers(servers):
    """Normalise name servers to a short, lowercase, de-duplicated list."""
    if not servers:
        return []
    if isinstance(servers, str):
        servers = [servers]
    return sorted({s.lower() for s in servers})[:4]


def describe_age(age_days):
    """Turn a domain age in days into a human-readable risk label."""
    if age_days is None:
        return "Unknown"
    if age_days < config.DOMAIN_AGE_HIGH_RISK_DAYS:
        return f"{age_days} days old -- very high risk"
    if age_days < config.DOMAIN_AGE_SUSPICIOUS_DAYS:
        return f"{age_days} days old -- recently registered"
    if age_days < 365:
        return f"{age_days} days old"
    return f"{age_days // 365} year(s) old"
