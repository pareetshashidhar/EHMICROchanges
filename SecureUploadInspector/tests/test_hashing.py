"""
SecureUpload Inspector - Cryptographic Hashing Unit Tests
=========================================================
Tests incremental SHA-256 calculation, stream handling, and constant-time comparison.
"""

import io
import hashlib
from pathlib import Path
from inspector.hashing import (
    compute_sha256_bytes,
    compute_sha256_stream,
    compute_sha256_file,
    compare_hashes,
)

KNOWN_EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

def test_hash_empty_bytes():
    """Verify standard empty payload produces canonical empty SHA-256 digest."""
    digest = compute_sha256_bytes(b"")
    assert digest == KNOWN_EMPTY_SHA256

def test_hash_sample_text():
    """Verify known string produces correct SHA-256."""
    text = b"Cybersecurity SecureUpload Inspection Test"
    expected = hashlib.sha256(text).hexdigest().lower()
    digest = compute_sha256_bytes(text)
    assert digest == expected

def test_hash_stream_incremental():
    """Verify streaming hash matches whole bytes calculation."""
    large_payload = b"A" * (128 * 1024)  # 128 KB
    stream = io.BytesIO(large_payload)
    stream_hash = compute_sha256_stream(stream, chunk_size=16384)
    direct_hash = compute_sha256_bytes(large_payload)
    assert stream_hash == direct_hash

def test_hash_file_on_disk(tmp_path: Path):
    """Verify file-based hashing reads disk content correctly."""
    temp_file = tmp_path / "test_file.bin"
    payload = b"Sample File Content For Hashing"
    temp_file.write_bytes(payload)
    file_hash = compute_sha256_file(temp_file)
    expected_hash = hashlib.sha256(payload).hexdigest().lower()
    assert file_hash == expected_hash

def test_compare_hashes_exact_match():
    """Verify hash comparison succeeds with identical hashes."""
    h1 = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
    h2 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    res = compare_hashes(h1, h2)
    assert res["match"] is True
    assert "exact bitwise match" in res["explanation"].lower()
    assert "security_disclaimer" in res

def test_compare_hashes_mismatch():
    """Verify mismatch is properly reported."""
    h1 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    h2 = "1111111111111111111111111111111111111111111111111111111111111111"
    res = compare_hashes(h1, h2)
    assert res["match"] is False
    assert "do not match" in res["explanation"].lower()
