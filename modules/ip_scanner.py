"""IP Scanner -- validates an IP, queries every intel source, decides a verdict.

This is the module that turns raw API responses into the single answer a SOC
analyst actually needs: is this address malicious, suspicious, or clean?

Author: Temiloluwa Michael Ogunrinde
"""

import ipaddress
import re

import config
import database
from threat_intel import abuseipdb, geolocation, otx, virustotal


def validate_ip(raw):
    """Check *raw* is a usable public IP address.

    Returns (is_valid, cleaned_ip_or_error_message).

    Private and reserved ranges are rejected deliberately -- threat intel
    services hold no data on 192.168.x.x, so scanning one wastes an API
    call and returns a misleadingly clean result.
    """
    candidate = (raw or "").strip()

    if not candidate:
        return False, "Please enter an IP address."

    try:
        parsed = ipaddress.ip_address(candidate)
    except ValueError:
        return False, f"'{candidate}' is not a valid IP address."

    # Loopback and multicast are checked first: is_private is also true for
    # both, so testing it earlier would give a misleading message.
    if parsed.is_loopback:
        return False, f"{candidate} is a loopback address."
    if parsed.is_multicast:
        return False, f"{candidate} is a multicast address."
    if parsed.is_reserved:
        return False, f"{candidate} is a reserved address."
    if parsed.is_private:
        return False, f"{candidate} is a private address -- no public intel exists for it."

    return True, str(parsed)


def decide_verdict(abuse, vt, otx=None):
    """Combine the intel results into one verdict plus a plain-English reason.

    Rules, in priority order:
      1. Any source calling it malicious outright     -> MALICIOUS
      2. Moderate abuse score, or any engine flagging -> SUSPICIOUS
      3. Nothing flagged                              -> CLEAN

    A single source is enough to escalate. In triage, missing a real threat
    costs far more than investigating a false positive.

    *otx* is optional -- OTX is a third opinion, not a required source.
    """
    otx = otx or {"available": False}

    reasons = []
    verdict = database.VERDICT_CLEAN

    abuse_score = abuse.get("abuse_score", 0) if abuse.get("available") else None
    vt_malicious = vt.get("malicious", 0) if vt.get("available") else None
    vt_suspicious = vt.get("suspicious", 0) if vt.get("available") else None
    otx_pulses = otx.get("pulse_count", 0) if otx.get("available") else None

    # ---------------------------------------------------------- malicious
    if abuse_score is not None and abuse_score >= config.ABUSE_SCORE_MALICIOUS:
        verdict = database.VERDICT_MALICIOUS
        reasons.append(
            f"AbuseIPDB confidence {abuse_score}% "
            f"(threshold {config.ABUSE_SCORE_MALICIOUS}%)"
        )

    if vt_malicious is not None and vt_malicious >= config.VT_MALICIOUS_ENGINES:
        verdict = database.VERDICT_MALICIOUS
        reasons.append(f"{vt_malicious} VirusTotal engines flag this IP as malicious")

    if otx_pulses is not None and otx_pulses >= config.OTX_PULSE_MALICIOUS:
        verdict = database.VERDICT_MALICIOUS
        reasons.append(
            f"Appears in {otx_pulses} OTX threat pulses -- reported across "
            f"multiple independent investigations"
        )

    # --------------------------------------------------------- suspicious
    if verdict != database.VERDICT_MALICIOUS:
        if abuse_score is not None and abuse_score >= config.ABUSE_SCORE_SUSPICIOUS:
            verdict = database.VERDICT_SUSPICIOUS
            reasons.append(f"AbuseIPDB confidence {abuse_score}% is elevated")

        if vt_malicious or vt_suspicious:
            verdict = database.VERDICT_SUSPICIOUS
            flagged = (vt_malicious or 0) + (vt_suspicious or 0)
            reasons.append(f"{flagged} VirusTotal engine(s) flagged this IP")

        if otx_pulses:
            verdict = database.VERDICT_SUSPICIOUS
            reasons.append(f"Appears in {otx_pulses} OTX threat pulse(s)")

    # ------------------------------------------- nothing could be consulted
    # A failed lookup is not a pass. Returning CLEAN when no source answered
    # would tell an analyst an address is safe when nothing actually checked
    # it -- the most dangerous thing a triage tool can do.
    if not any(source.get("available") for source in (abuse, vt, otx)):
        verdict = database.VERDICT_SUSPICIOUS
        reasons.append(
            "No threat intelligence source could be reached, so this address "
            "was never assessed -- this is not a clean result"
        )
        for name, source in (("AbuseIPDB", abuse), ("VirusTotal", vt), ("OTX", otx)):
            if source.get("error"):
                reasons.append(f"{name}: {source['error']}")

    # --------------------------------------------------- supporting notes
    if otx.get("available") and otx.get("pulse_names"):
        reasons.append("OTX campaigns: " + ", ".join(otx["pulse_names"][:3]))

    if abuse.get("available"):
        if abuse.get("is_tor"):
            reasons.append("Listed as a Tor exit node")
        if abuse.get("total_reports"):
            reasons.append(
                f"{abuse['total_reports']} abuse report(s) from "
                f"{abuse.get('distinct_reporters', 0)} reporter(s) "
                f"in the last {config.ABUSE_MAX_AGE_DAYS} days"
            )
        if abuse.get("is_whitelisted"):
            reasons.append("Whitelisted by AbuseIPDB")

    if not reasons:
        reasons.append("No threat intelligence source flagged this address")

    return verdict, reasons


# AbuseIPDB usage types that describe infrastructure rather than a person.
HOSTING_USAGE_TYPES = ("Data Center", "Web Hosting", "Transit",
                       "Content Delivery Network")

# Whole words in OTX pulse tags that point at anonymisation infrastructure.
# Matched as words, not substrings -- "tor" must not match "monitor".
ANONYMISER_TAG_WORDS = {"vpn", "proxy", "proxies", "tor", "anonymizer",
                        "anonymiser", "anonymous"}


def _combine(*answers):
    """Merge yes/no answers from several sources without inventing certainty.

    True if any source said yes. False only if a source actually answered
    no and none said yes. None if no source answered at all -- so an
    unchecked address is shown as unknown, never as a reassuring "No".
    """
    answered = [a for a in answers if a is not None]
    if any(answered):
        return True
    if answered:
        return False
    return None


def assess_anonymisation(abuse, geo, otx=None):
    """Work out whether this address is likely hiding who is really behind it.

    Tor, VPNs, proxies and cloud servers let an attacker borrow someone
    else's location and reputation. Knowing an address is one of these
    changes how an analyst reads everything else -- a login from a hosting
    provider is not somebody at home.

    This is context, never a verdict. Plenty of legitimate traffic comes
    through corporate VPNs and cloud platforms, so the result is reported
    alongside the verdict and is never allowed to change it.
    """
    otx = otx or {"available": False}
    abuse_ok = bool(abuse.get("available"))
    geo_ok = bool(geo.get("available"))

    usage_type = abuse.get("usage_type") if abuse_ok else None
    hosting_by_usage = (
        any(kind in usage_type for kind in HOSTING_USAGE_TYPES)
        if usage_type else None
    )

    tor = _combine(abuse.get("is_tor") if abuse_ok else None)
    proxy = _combine(geo.get("proxy") if geo_ok else None)
    hosting = _combine(geo.get("hosting") if geo_ok else None, hosting_by_usage)
    mobile = _combine(geo.get("mobile") if geo_ok else None)

    otx_tags = []
    if otx.get("available"):
        for tag in otx.get("tags") or []:
            words = set(re.split(r"[^a-z0-9]+", str(tag).lower()))
            if words & ANONYMISER_TAG_WORDS:
                otx_tags.append(tag)

    # Tor is already reported by decide_verdict, so it is not repeated here.
    notes = []
    if proxy:
        notes.append("Flagged as a VPN or proxy exit -- whoever is behind "
                     "this address may be somewhere else entirely")
    if hosting:
        notes.append("Belongs to a hosting or data-centre network rather "
                     "than a home or office connection")
    if mobile:
        notes.append("On a mobile network, where many people share one "
                     "address -- its reputation may reflect other users")
    if otx_tags:
        notes.append("OTX reports tag this address as anonymisation "
                     "infrastructure: " + ", ".join(otx_tags[:4]))

    core = (tor, proxy, hosting)
    flagged = any(v is True for v in core) or bool(otx_tags)

    if flagged:
        found = [label for label, value in
                 (("Tor exit node", tor), ("VPN / proxy", proxy),
                  ("hosting provider", hosting)) if value]
        if otx_tags:
            found.append("OTX anonymiser tags")
        summary = "Anonymisation or infrastructure indicators: " + ", ".join(found)
    elif all(v is False for v in core):
        summary = "No sign of Tor, VPN, proxy or hosting infrastructure"
    elif any(v is False for v in core):
        summary = ("No anonymisation found in the sources that answered, "
                   "but not every source could be checked")
    else:
        summary = "Could not be assessed -- no source answered"

    return {
        "tor": tor,
        "proxy": proxy,
        "hosting": hosting,
        "mobile": mobile,
        "otx_tags": otx_tags,
        "flagged": flagged,
        "summary": summary,
        "notes": notes,
    }


def scan(raw_ip):
    """Run a full IP scan and persist the result.

    Returns a result dict ready to hand straight to the template. On invalid
    input it returns {"ok": False, "error": ...} and touches no APIs.
    """
    is_valid, result = validate_ip(raw_ip)
    if not is_valid:
        return {"ok": False, "error": result}

    ip = result

    # Query all three sources. Each returns a dict rather than raising, so
    # one service being down never takes the whole scan with it.
    abuse = abuseipdb.check_ip(ip)
    vt = virustotal.check_ip(ip)
    otx_result = otx.check_ip(ip)
    geo = geolocation.lookup(ip)

    verdict, reasons = decide_verdict(abuse, vt, otx_result)

    # Anonymisation is context, so it is assessed separately and appended
    # after the verdict is fixed -- it can explain a verdict, never change it.
    anonymisation = assess_anonymisation(abuse, geo, otx_result)
    reasons.extend(anonymisation["notes"])

    # Record which sources actually answered, for the audit trail.
    sources = []
    if abuse.get("available"):
        sources.append("AbuseIPDB")
    if vt.get("available"):
        sources.append("VirusTotal")
    if otx_result.get("available"):
        sources.append("OTX")
    if geo.get("available"):
        sources.append("ip-api")
    source_label = ", ".join(sources) if sources else "None"

    database.save_scan(
        indicator=ip,
        indicator_type="IP",
        verdict=verdict,
        source=source_label,
        details="; ".join(reasons),
    )

    return {
        "ok": True,
        "ip": ip,
        "verdict": verdict,
        "reasons": reasons,
        "abuse": abuse,
        "virustotal": vt,
        "otx": otx_result,
        "geo": geo,
        "anonymisation": anonymisation,
        "sources": source_label,
    }
