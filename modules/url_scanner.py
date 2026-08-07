"""URL / Domain Scanner -- multi-engine analysis plus domain age checking.

Accepts either a full URL or a bare domain, asks VirusTotal what its ~90
engines think, checks how recently the domain was registered, and combines
both into a single verdict.

Author: Temiloluwa Michael Ogunrinde
"""

import re
from urllib.parse import urlparse

import config
import database
from threat_intel import virustotal, whois_lookup

# A domain label: letters, digits and hyphens, with a final TLD of 2+ letters.
DOMAIN_PATTERN = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$",
    re.IGNORECASE,
)


def validate_url(raw):
    """Check *raw* looks like a usable URL or domain.

    Returns (is_valid, cleaned_url_or_error, domain).

    A bare domain like "example.com" gets http:// prepended, since that is
    what users actually paste and VirusTotal needs a full URL.
    """
    candidate = (raw or "").strip()

    if not candidate:
        return False, "Please enter a URL or domain.", None

    if len(candidate) > 2000:
        return False, "That URL is too long to scan.", None

    # Add a scheme if the user pasted a bare domain.
    if "://" not in candidate:
        candidate = "http://" + candidate

    parsed = urlparse(candidate)

    if parsed.scheme not in ("http", "https"):
        return False, f"Unsupported scheme '{parsed.scheme}' -- use http or https.", None

    # hostname strips any port and lowercases for us.
    domain = parsed.hostname
    if not domain:
        return False, f"Could not read a domain from '{raw.strip()}'.", None

    if not DOMAIN_PATTERN.match(domain):
        return False, f"'{domain}' is not a valid domain name.", None

    return True, candidate, domain


def decide_verdict(vt, whois_data):
    """Combine engine detections and domain age into one verdict.

    Engine detections carry the most weight. Domain age can escalate a
    clean result to suspicious on its own -- a brand new domain with no
    detections yet is exactly what a fresh phishing site looks like.
    """
    reasons = []
    verdict = database.VERDICT_CLEAN

    vt_malicious = vt.get("malicious", 0) if vt.get("available") else None
    vt_suspicious = vt.get("suspicious", 0) if vt.get("available") else None
    age_days = whois_data.get("age_days") if whois_data.get("available") else None

    # ---------------------------------------------------------- malicious
    if vt_malicious is not None and vt_malicious >= config.VT_MALICIOUS_ENGINES:
        verdict = database.VERDICT_MALICIOUS
        reasons.append(
            f"{vt_malicious} of {vt.get('total_engines', '?')} VirusTotal "
            f"engines flag this URL as malicious"
        )
        if vt.get("flagged_by"):
            reasons.append("Flagged by: " + ", ".join(vt["flagged_by"][:6]))

    # --------------------------------------------------------- suspicious
    if verdict != database.VERDICT_MALICIOUS:
        if vt_malicious or vt_suspicious:
            verdict = database.VERDICT_SUSPICIOUS
            flagged = (vt_malicious or 0) + (vt_suspicious or 0)
            reasons.append(f"{flagged} VirusTotal engine(s) flagged this URL")
            if vt.get("flagged_by"):
                reasons.append("Flagged by: " + ", ".join(vt["flagged_by"][:6]))

        if age_days is not None and age_days < config.DOMAIN_AGE_SUSPICIOUS_DAYS:
            verdict = database.VERDICT_SUSPICIOUS
            reasons.append(
                f"Domain registered only {age_days} day(s) ago -- newly "
                f"registered domains are a common phishing indicator"
            )

    # --------------------------------------------------- supporting notes
    if whois_data.get("available"):
        if age_days is not None and age_days >= config.DOMAIN_AGE_SUSPICIOUS_DAYS:
            reasons.append(f"Domain age: {whois_data.get('age_label')}")
        if whois_data.get("registrar"):
            reasons.append(f"Registrar: {whois_data['registrar']}")

    if vt.get("available") and not vt_malicious and not vt_suspicious:
        reasons.append(
            f"No detections across {vt.get('total_engines', 0)} VirusTotal engines"
        )

    if vt.get("final_url") and vt["final_url"] != whois_data.get("submitted_url"):
        reasons.append(f"Final URL after redirects: {vt['final_url']}")

    if not reasons:
        reasons.append("No threat intelligence source flagged this URL")

    return verdict, reasons


def scan(raw_url):
    """Run a full URL scan and persist the result."""
    is_valid, cleaned, domain = validate_url(raw_url)
    if not is_valid:
        return {"ok": False, "error": cleaned}

    vt = virustotal.check_url(cleaned)
    whois_data = whois_lookup.lookup(domain)

    verdict, reasons = decide_verdict(vt, whois_data)

    sources = []
    if vt.get("available"):
        sources.append("VirusTotal")
    if whois_data.get("available"):
        sources.append("WHOIS")
    source_label = ", ".join(sources) if sources else "None"

    database.save_scan(
        indicator=cleaned,
        indicator_type="URL",
        verdict=verdict,
        source=source_label,
        details="; ".join(reasons),
    )

    return {
        "ok": True,
        "url": cleaned,
        "domain": domain,
        "verdict": verdict,
        "reasons": reasons,
        "virustotal": vt,
        "whois": whois_data,
        "sources": source_label,
    }
