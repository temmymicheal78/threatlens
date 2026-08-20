"""IP Scanner -- validates an IP, queries every intel source, decides a verdict.

This is the module that turns raw API responses into the single answer a SOC
analyst actually needs: is this address malicious, suspicious, or clean?

Author: Temiloluwa Michael Ogunrinde
"""

import ipaddress

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
        "sources": source_label,
    }
