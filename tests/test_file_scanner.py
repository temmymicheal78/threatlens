"""Tests for hash validation, local file hashing and malware verdicts."""

import io

import pytest

import database
from modules.file_scanner import (
    decide_verdict,
    format_size,
    hash_file,
    validate_hash,
)


class FakeUpload:
    """Stands in for Werkzeug's FileStorage, which only needs .stream/.filename."""

    def __init__(self, data, filename="sample.bin"):
        self.stream = io.BytesIO(data)
        self.filename = filename


# ---------------------------------------------------------------- validation
@pytest.mark.parametrize("digest,expected", [
    ("44d88612fea8a8f36de82e1278abb02f", "MD5"),
    ("3395856ce81f2b7382dee72602f798b642f14140", "SHA-1"),
    ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "SHA-256"),
])
def test_each_hash_length_identifies_its_algorithm(digest, expected):
    ok, cleaned, hash_type = validate_hash(digest)
    assert ok
    assert hash_type == expected
    assert cleaned == digest


def test_uppercase_and_whitespace_are_normalised():
    ok, cleaned, hash_type = validate_hash("  44D88612FEA8A8F36DE82E1278ABB02F  ")
    assert ok
    assert cleaned == "44d88612fea8a8f36de82e1278abb02f"
    assert hash_type == "MD5"


def test_non_hex_characters_are_rejected():
    ok, message, _ = validate_hash("zzzz8612fea8a8f36de82e1278abb02f")
    assert not ok
    assert "0-9" in message


def test_wrong_length_is_rejected_with_the_valid_lengths():
    ok, message, _ = validate_hash("abc123")
    assert not ok
    assert "32" in message and "40" in message and "64" in message


@pytest.mark.parametrize("junk", ["", "   "])
def test_empty_input_is_rejected(junk):
    ok, message, _ = validate_hash(junk)
    assert not ok
    assert message


# ------------------------------------------------------------ local hashing
def test_hashes_match_known_values():
    """Checked against the published digests for the bytes 'hello world'."""
    result = hash_file(FakeUpload(b"hello world", "test.txt"))
    assert result["md5"] == "5eb63bbbe01eeed093cb22bb8f5acdc3"
    assert result["sha1"] == "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
    assert result["sha256"] == (
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    )


def test_file_size_and_name_are_recorded():
    result = hash_file(FakeUpload(b"x" * 500, "payload.exe"))
    assert result["size"] == 500
    assert result["filename"] == "payload.exe"


def test_empty_file_hashes_without_error():
    result = hash_file(FakeUpload(b"", "empty.txt"))
    assert result["size"] == 0
    assert result["md5"] == "d41d8cd98f00b204e9800998ecf8427e"


def test_file_larger_than_one_chunk_hashes_correctly():
    """Chunked reading must not corrupt the digest at buffer boundaries."""
    import hashlib
    data = b"A" * 200_000          # comfortably more than the 65536 chunk size
    result = hash_file(FakeUpload(data))
    assert result["sha256"] == hashlib.sha256(data).hexdigest()


# ------------------------------------------------------------------ verdicts
def vt(malicious=0, suspicious=0, engines=72, **extra):
    return {"available": True, "malicious": malicious, "suspicious": suspicious,
            "total_engines": engines, **extra}


def test_many_detections_is_malicious():
    verdict, reasons = decide_verdict(vt(malicious=60, threat_label="trojan.emotet"))
    assert verdict == database.VERDICT_MALICIOUS
    assert any("trojan.emotet" in r for r in reasons)


def test_single_detection_is_only_suspicious():
    verdict, _ = decide_verdict(vt(malicious=1))
    assert verdict == database.VERDICT_SUSPICIOUS


def test_no_detections_is_clean():
    verdict, _ = decide_verdict(vt())
    assert verdict == database.VERDICT_CLEAN


def test_unknown_file_is_suspicious_not_clean():
    """Absence of evidence is not evidence of absence.

    Targeted malware is unknown to VirusTotal by design, so reporting an
    unknown hash as clean would be actively misleading.
    """
    verdict, reasons = decide_verdict({"available": False, "not_found": True,
                                       "error": "never seen"})
    assert verdict == database.VERDICT_SUSPICIOUS
    assert any("not proof of safety" in r for r in reasons)


def test_failed_lookup_is_suspicious_not_clean():
    """A rate limit or network error answers nothing -- it is not a pass."""
    verdict, reasons = decide_verdict({"available": False,
                                       "error": "Rate limit reached"})
    assert verdict == database.VERDICT_SUSPICIOUS
    assert any("not a clean result" in r for r in reasons)


# ------------------------------------------------------------------ helpers
@pytest.mark.parametrize("size,expected", [
    (0, None),
    (500, "500 B"),
    (2048, "2.0 KB"),
    (5 * 1024 * 1024, "5.0 MB"),
])
def test_size_formatting(size, expected):
    assert format_size(size) == expected
