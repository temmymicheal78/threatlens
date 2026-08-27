"""Email Analyzer -- phishing detection from raw email headers.

Takes a full raw email (headers plus body), verifies its authentication
results, hunts for the mismatches that indicate spoofing, checks the
originating IP's reputation, and extracts any embedded URLs.

The checks mirror what a SOC analyst does by hand when triaging a reported
phishing email.

Author: Temiloluwa Michael Ogunrinde
"""

import email
import ipaddress
import re
from email.utils import parseaddr

import config
import database
from threat_intel import abuseipdb

# Matches "spf=pass", "dkim = fail", "dmarc=none" in Authentication-Results.
AUTH_PATTERN = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*(\w+)", re.IGNORECASE)

# Any IPv4 address wrapped in brackets or parentheses in a Received header.
RECEIVED_IP_PATTERN = re.compile(r"[\[\(](\d{1,3}(?:\.\d{1,3}){3})[\]\)]")

# Fallback for Received headers that write the IP bare, without brackets.
BARE_IP_PATTERN = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

# "from <host>" and "by <host>" in a Received header.
RECEIVED_FROM_PATTERN = re.compile(r"\bfrom\s+([^\s;()\[\]]+)", re.IGNORECASE)
RECEIVED_BY_PATTERN = re.compile(r"\bby\s+([^\s;()\[\]]+)", re.IGNORECASE)

# Ranges reserved for documentation and examples (RFC 5737). Python's
# ipaddress module reports these as private, which is right for routing but
# hides a useful distinction: an internal relay and a training placeholder
# are not the same thing to an analyst.
DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)

# URLs in the body. Deliberately broad -- we want to see everything.
URL_PATTERN = re.compile(r"https?://[^\s<>\"'\)\]]+", re.IGNORECASE)

# Results that count as a pass for each authentication mechanism.
PASSING = {"pass"}


def parse_email(raw_text):
    """Parse a raw email into a message object.

    Returns (ok, message_or_error). Accepts a headers-only paste as well as
    a full email, since that is often all an analyst is given.
    """
    text = (raw_text or "").strip()

    if not text:
        return False, "Please paste the raw email, including its headers."

    if len(text) < 20:
        return False, "That is too short to be an email. Paste the full headers."

    message = email.message_from_string(text)

    # A real email has at least one of these. Without them we were handed
    # body text rather than headers, and every check below would be blank.
    if not any(message.get(h) for h in ("From", "Received", "Subject", "Return-Path")):
        return False, (
            "No email headers found. Paste the full message source -- in "
            "Gmail use 'Show original', in Outlook use 'View message source'."
        )

    return True, message


def _domain_of(address):
    """Extract the domain from an email address, lowercased."""
    _, addr = parseaddr(address or "")
    if "@" not in addr:
        return None
    return addr.rsplit("@", 1)[1].lower().strip()


def check_authentication(message):
    """Read SPF, DKIM and DMARC results from the message headers.

    Mail servers record their verdict in Authentication-Results. Some also
    write a separate Received-SPF header, which we fall back to.
    """
    results = {"spf": None, "dkim": None, "dmarc": None}

    headers = message.get_all("Authentication-Results") or []
    headers += message.get_all("ARC-Authentication-Results") or []

    for header in headers:
        for mechanism, verdict in AUTH_PATTERN.findall(header):
            mechanism = mechanism.lower()
            # Keep the first verdict seen -- that is the receiving server's.
            if results.get(mechanism) is None:
                results[mechanism] = verdict.lower()

    # Fall back to the older Received-SPF header if SPF was not recorded.
    if results["spf"] is None:
        received_spf = message.get("Received-SPF")
        if received_spf:
            results["spf"] = received_spf.strip().split()[0].lower()

    return results


def check_spoofing(message):
    """Look for the address mismatches that indicate a spoofed sender.

    Legitimate bulk mail can trip these too, which is why they raise
    suspicion rather than deciding the verdict alone.
    """
    findings = []

    from_header = message.get("From", "")
    display_name, from_addr = parseaddr(from_header)

    from_domain = _domain_of(from_header)
    return_domain = _domain_of(message.get("Return-Path", ""))
    reply_domain = _domain_of(message.get("Reply-To", ""))

    if from_domain and return_domain and from_domain != return_domain:
        findings.append(
            f"From domain ({from_domain}) does not match Return-Path "
            f"({return_domain}) -- bounces would go elsewhere"
        )

    if from_domain and reply_domain and from_domain != reply_domain:
        findings.append(
            f"Reply-To domain ({reply_domain}) differs from From domain "
            f"({from_domain}) -- replies would go to a third party"
        )

    # A display name containing an email address that isn't the real sender
    # is a classic client-display trick.
    if "@" in display_name and from_addr and display_name.strip() != from_addr:
        embedded = _domain_of(display_name)
        if embedded and embedded != from_domain:
            findings.append(
                f"Display name shows '{display_name}' but the real sender is "
                f"{from_addr}"
            )

    return {
        "display_name": display_name or None,
        "from_address": from_addr or None,
        "from_domain": from_domain,
        "return_path_domain": return_domain,
        "reply_to_domain": reply_domain,
        "findings": findings,
    }


def extract_origin_ip(message):
    """Find the IP the message originated from.

    Received headers stack newest-first, so the *last* one is the earliest
    hop -- closest to the true sender. Private IPs are skipped because they
    are internal relays, not the originator.
    """
    received = message.get_all("Received") or []

    for header in reversed(received):
        for candidate in RECEIVED_IP_PATTERN.findall(header):
            try:
                parsed = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if parsed.is_private or parsed.is_loopback or parsed.is_reserved:
                continue
            return candidate

    return None


def classify_ip(address):
    """Describe what kind of address this is, in an analyst's terms.

    Returns one of: 'public', 'internal', 'documentation', 'loopback'.
    Documentation ranges are separated out because Python reports them as
    private, which would otherwise hide them among genuine internal relays.
    """
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return "unknown"

    if parsed.is_loopback:
        return "loopback"
    if any(parsed in network for network in DOCUMENTATION_NETWORKS):
        return "documentation"
    if parsed.is_private or parsed.is_reserved:
        return "internal"
    return "public"


def extract_mail_path(message):
    """Rebuild the journey the message took, oldest hop first.

    Received headers are added by each server as the message passes through,
    newest on top. Reversing them gives the path in the order it actually
    happened, which is how an analyst reads it: origin at hop 1, recipient's
    own infrastructure at the end.

    Every hop is returned, including internal ones. extract_origin_ip picks a
    single address for reputation lookups; this shows the whole chain so the
    analyst can see the route and spot anomalies in it.
    """
    received = message.get_all("Received") or []
    hops = []

    for position, header in enumerate(reversed(received), start=1):
        text = " ".join(header.split())          # unfold and normalise spacing

        ip = None
        match = RECEIVED_IP_PATTERN.search(text)
        if match:
            ip = match.group(1)
        else:
            bare = BARE_IP_PATTERN.search(text)
            if bare:
                ip = bare.group(1)

        from_match = RECEIVED_FROM_PATTERN.search(text)
        by_match = RECEIVED_BY_PATTERN.search(text)

        # The timestamp is conventionally the last semicolon-separated field.
        timestamp = None
        if ";" in text:
            candidate = text.rsplit(";", 1)[1].strip()
            if candidate:
                timestamp = candidate

        hops.append({
            "position": position,
            "from_host": from_match.group(1) if from_match else None,
            "by_host": by_match.group(1) if by_match else None,
            "ip": ip,
            "ip_kind": classify_ip(ip) if ip else None,
            "timestamp": timestamp,
        })

    return hops


def extract_urls(raw_text, limit=15):
    """Pull every URL out of the raw message, de-duplicated."""
    found = []
    seen = set()

    for url in URL_PATTERN.findall(raw_text or ""):
        cleaned = url.rstrip(".,;:!?>")
        if cleaned.lower() in seen:
            continue
        seen.add(cleaned.lower())
        found.append(cleaned)
        if len(found) >= limit:
            break

    return found


def check_subject_keywords(message):
    """Return any phishing-style urgency keywords found in the subject."""
    subject = (message.get("Subject") or "").lower()
    return [word for word in config.PHISHING_KEYWORDS if word in subject]


def decide_verdict(auth, spoofing, origin_reputation, keywords, urls):
    """Combine every signal into one verdict.

    Authentication is the backbone: DMARC exists precisely to say whether a
    message genuinely came from the domain it claims. A DMARC failure is
    treated as conclusive. Everything else builds a suspicion case.
    """
    reasons = []
    verdict = database.VERDICT_CLEAN

    spf = auth.get("spf")
    dkim = auth.get("dkim")
    dmarc = auth.get("dmarc")

    failed = [
        name for name, value in (("SPF", spf), ("DKIM", dkim), ("DMARC", dmarc))
        if value is not None and value not in PASSING
    ]

    # ---------------------------------------------------------- malicious
    if dmarc is not None and dmarc not in PASSING:
        verdict = database.VERDICT_MALICIOUS
        reasons.append(
            f"DMARC {dmarc.upper()} -- the sending domain's own policy says "
            f"this message is not authentic"
        )

    if spf is not None and dkim is not None and spf not in PASSING and dkim not in PASSING:
        verdict = database.VERDICT_MALICIOUS
        reasons.append(f"Both SPF ({spf}) and DKIM ({dkim}) failed")

    if origin_reputation.get("available") and origin_reputation.get(
        "abuse_score", 0
    ) >= config.ABUSE_SCORE_MALICIOUS:
        verdict = database.VERDICT_MALICIOUS
        reasons.append(
            f"Sending IP has an AbuseIPDB confidence score of "
            f"{origin_reputation['abuse_score']}%"
        )

    # --------------------------------------------------------- suspicious
    if verdict != database.VERDICT_MALICIOUS:
        if failed:
            verdict = database.VERDICT_SUSPICIOUS
            reasons.append(f"Failed authentication: {', '.join(failed)}")

        if spoofing["findings"]:
            verdict = database.VERDICT_SUSPICIOUS
            reasons.extend(spoofing["findings"])

        if origin_reputation.get("available") and origin_reputation.get(
            "abuse_score", 0
        ) >= config.ABUSE_SCORE_SUSPICIOUS:
            verdict = database.VERDICT_SUSPICIOUS
            reasons.append(
                f"Sending IP has an elevated abuse score of "
                f"{origin_reputation['abuse_score']}%"
            )

        if keywords and (failed or spoofing["findings"]):
            reasons.append(
                f"Subject uses urgency language: {', '.join(keywords[:3])}"
            )

    # --------------------------------------------------- supporting notes
    # Spoofing evidence is reported even when the verdict is already
    # decided -- an analyst writing this up needs every indicator, not just
    # the one that tipped the balance.
    if verdict == database.VERDICT_MALICIOUS and spoofing["findings"]:
        reasons.extend(spoofing["findings"])

    if verdict == database.VERDICT_MALICIOUS and keywords:
        reasons.append(f"Subject uses urgency language: {', '.join(keywords[:3])}")

    missing = [
        name for name, value in (("SPF", spf), ("DKIM", dkim), ("DMARC", dmarc))
        if value is None
    ]
    if missing:
        reasons.append(
            f"No {', '.join(missing)} result recorded -- the receiving server "
            f"did not check, so authenticity is unproven"
        )

    if keywords and verdict == database.VERDICT_CLEAN:
        reasons.append(
            f"Subject uses urgency language ({', '.join(keywords[:3])}), but "
            f"authentication passed"
        )

    if urls:
        reasons.append(f"{len(urls)} URL(s) embedded in the message body")

    if not reasons:
        reasons.append("All authentication checks passed with no anomalies")

    return verdict, reasons


def analyze(raw_text):
    """Run the full email analysis and persist the result."""
    ok, parsed = parse_email(raw_text)
    if not ok:
        return {"ok": False, "error": parsed}

    message = parsed

    auth = check_authentication(message)
    spoofing = check_spoofing(message)
    origin_ip = extract_origin_ip(message)
    mail_path = extract_mail_path(message)
    urls = extract_urls(raw_text)
    keywords = check_subject_keywords(message)

    # Reuse the Week 2 AbuseIPDB client for the sending server's reputation.
    origin_reputation = (
        abuseipdb.check_ip(origin_ip) if origin_ip else {"available": False,
                                                         "error": "No originating IP found in headers"}
    )

    verdict, reasons = decide_verdict(auth, spoofing, origin_reputation, keywords, urls)

    sender = spoofing.get("from_address") or "unknown sender"

    sources = ["Header analysis"]
    if origin_reputation.get("available"):
        sources.append("AbuseIPDB")

    database.save_scan(
        indicator=sender,
        indicator_type="EMAIL",
        verdict=verdict,
        source=", ".join(sources),
        details="; ".join(reasons),
    )

    return {
        "ok": True,
        "verdict": verdict,
        "reasons": reasons,
        "auth": auth,
        "spoofing": spoofing,
        "origin_ip": origin_ip,
        "origin_reputation": origin_reputation,
        "mail_path": mail_path,
        "urls": urls,
        "keywords": keywords,
        "subject": message.get("Subject"),
        "from_header": message.get("From"),
        "date": message.get("Date"),
        "sources": ", ".join(sources),
    }
