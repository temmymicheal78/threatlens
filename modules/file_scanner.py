"""File Hash Scanner -- malware detection by hash reputation.

Accepts either a hash the analyst already has, or a file to fingerprint
locally. When a file is supplied it is hashed in memory and only the hash
is sent to VirusTotal -- the file itself never leaves the machine, which
matters when the sample may contain confidential data.

Author: Temiloluwa Michael Ogunrinde
"""

import hashlib
import re
from datetime import datetime

import config
import database
from threat_intel import virustotal

# Hash lengths are fixed, so the length alone identifies the algorithm.
HASH_TYPES = {
    32: "MD5",
    40: "SHA-1",
    64: "SHA-256",
}

HEX_PATTERN = re.compile(r"^[a-fA-F0-9]+$")

# Read uploaded files in chunks so a large file never lands in memory whole.
CHUNK_SIZE = 65536


def validate_hash(raw):
    """Check *raw* is a well-formed MD5, SHA-1 or SHA-256 hash.

    Returns (is_valid, cleaned_hash_or_error, hash_type).
    """
    candidate = (raw or "").strip().lower()

    if not candidate:
        return False, "Please enter a file hash or choose a file.", None

    if not HEX_PATTERN.match(candidate):
        return False, "A hash contains only the characters 0-9 and a-f.", None

    hash_type = HASH_TYPES.get(len(candidate))
    if not hash_type:
        return False, (
            f"That is {len(candidate)} characters long. A hash must be 32 "
            f"(MD5), 40 (SHA-1) or 64 (SHA-256) characters."
        ), None

    return True, candidate, hash_type


def hash_file(file_storage):
    """Compute MD5, SHA-1 and SHA-256 for an uploaded file.

    Hashing happens here, locally, in chunks. Nothing is written to disk and
    nothing is uploaded anywhere.
    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    size = 0

    file_storage.stream.seek(0)
    while True:
        chunk = file_storage.stream.read(CHUNK_SIZE)
        if not chunk:
            break
        size += len(chunk)
        md5.update(chunk)
        sha1.update(chunk)
        sha256.update(chunk)

    return {
        "filename": file_storage.filename,
        "size": size,
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def decide_verdict(vt):
    """Turn engine detections into a verdict.

    An unknown file is reported as SUSPICIOUS rather than CLEAN. Absence of
    evidence is not evidence of absence -- targeted malware is unknown to
    VirusTotal by design, and calling it clean would be actively misleading.
    """
    reasons = []

    if vt.get("not_found"):
        return database.VERDICT_SUSPICIOUS, [
            "VirusTotal has no record of this file",
            "An unknown hash is not proof of safety -- newly built or "
            "targeted malware is unknown by design",
        ]

    if not vt.get("available"):
        # A failed lookup tells us nothing about the file, so it must not be
        # reported as clean. Unknown is the honest answer.
        return database.VERDICT_SUSPICIOUS, [
            f"Could not complete the lookup: {vt.get('error')}",
            "No verdict could be reached -- this is not a clean result, "
            "just an unanswered question. Try again once the issue clears.",
        ]

    malicious = vt.get("malicious", 0)
    suspicious = vt.get("suspicious", 0)
    total = vt.get("total_engines", 0)

    if malicious >= config.VT_MALICIOUS_ENGINES:
        verdict = database.VERDICT_MALICIOUS
        reasons.append(f"{malicious} of {total} engines detect this file as malicious")
    elif malicious or suspicious:
        verdict = database.VERDICT_SUSPICIOUS
        reasons.append(f"{malicious + suspicious} of {total} engine(s) flagged this file")
    else:
        verdict = database.VERDICT_CLEAN
        reasons.append(f"No detections across {total} engines")

    if vt.get("threat_label"):
        reasons.append(f"Threat classification: {vt['threat_label']}")

    if vt.get("flagged_by"):
        reasons.append("Detected by: " + ", ".join(vt["flagged_by"][:6]))

    if vt.get("file_type"):
        reasons.append(f"File type: {vt['file_type']}")

    if vt.get("times_submitted"):
        reasons.append(f"Submitted to VirusTotal {vt['times_submitted']} time(s)")

    return verdict, reasons


def format_first_seen(timestamp):
    """Convert VirusTotal's Unix timestamp into a readable date."""
    if not timestamp:
        return None
    try:
        return datetime.fromtimestamp(timestamp).strftime("%d %b %Y")
    except (ValueError, OSError, TypeError):
        return None


def format_size(num_bytes):
    """Render a byte count in the largest sensible unit."""
    if not num_bytes:
        return None
    for unit in ("B", "KB", "MB", "GB"):
        if num_bytes < 1024 or unit == "GB":
            return f"{num_bytes:.0f} {unit}" if unit == "B" else f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024
    return None


def scan(raw_hash=None, uploaded_file=None):
    """Scan either a pasted hash or an uploaded file.

    When a file is given it is hashed locally and its SHA-256 is the value
    actually looked up.
    """
    local_hashes = None

    if uploaded_file is not None and uploaded_file.filename:
        local_hashes = hash_file(uploaded_file)
        file_hash = local_hashes["sha256"]
        hash_type = "SHA-256"
    else:
        is_valid, result, hash_type = validate_hash(raw_hash)
        if not is_valid:
            return {"ok": False, "error": result}
        file_hash = result

    vt = virustotal.check_hash(file_hash)
    verdict, reasons = decide_verdict(vt)

    if local_hashes:
        reasons.insert(
            0,
            f"Hashed locally from '{local_hashes['filename']}' "
            f"({format_size(local_hashes['size'])}) -- the file was not uploaded",
        )

    database.save_scan(
        indicator=file_hash,
        indicator_type="HASH",
        verdict=verdict,
        source="VirusTotal" if vt.get("available") else "None",
        details="; ".join(reasons),
    )

    return {
        "ok": True,
        "hash": file_hash,
        "hash_type": hash_type,
        "verdict": verdict,
        "reasons": reasons,
        "virustotal": vt,
        "local": local_hashes,
        "first_seen": format_first_seen(vt.get("first_seen")),
        "size_label": format_size(vt.get("file_size")),
        "sources": "VirusTotal" if vt.get("available") else "None",
    }
