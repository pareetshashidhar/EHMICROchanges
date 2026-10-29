"""
SecureUpload Inspector - Cryptographic Hashing Module
=====================================================
Provides memory-efficient incremental SHA-256 hashing and constant-time hash comparison.

SECURITY NOTE:
Cryptographic hashing guarantees file integrity and allows verification against
known threat intelligence or baseline references. However, a hash DOES NOT establish
that a file is safe or benign. Malicious files have valid SHA-256 digests.
"""

import hashlib
import hmac
from pathlib import Path
from typing import BinaryIO, Union

DEFAULT_CHUNK_SIZE = 64 * 1024  # 64 KB chunk size for memory-bounded processing

def compute_sha256_stream(stream: BinaryIO, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """
    Incrementally compute SHA-256 digest from a readable binary stream.
    
    Ensures memory bounded operations regardless of file size.
    The stream position is reset to start if seekable.
    
    Args:
        stream: Binary file-like object supporting read()
        chunk_size: Size of chunks in bytes (default 64KB)
        
    Returns:
        Lowercase hexadecimal SHA-256 string (64 characters).
    """
    hasher = hashlib.sha256()
    
    # Store initial position if seekable
    initial_pos = None
    if hasattr(stream, "seekable") and stream.seekable():
        try:
            initial_pos = stream.tell()
            stream.seek(0)
        except (OSError, ValueError):
            initial_pos = None

    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        hasher.update(chunk)

    # Restore position if possible
    if initial_pos is not None and hasattr(stream, "seek"):
        try:
            stream.seek(initial_pos)
        except (OSError, ValueError):
            pass

    return hasher.hexdigest().lower()

def compute_sha256_file(file_path: Union[str, Path], chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """
    Incrementally compute SHA-256 digest from a file on disk.
    
    Args:
        file_path: Path to the target file
        chunk_size: Chunk size in bytes (default 64KB)
        
    Returns:
        Lowercase hexadecimal SHA-256 string.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)

    return hasher.hexdigest().lower()

def compute_sha256_bytes(data: bytes) -> str:
    """
    Compute SHA-256 digest of in-memory bytes.
    
    Args:
        data: Raw bytes to hash
        
    Returns:
        Lowercase hexadecimal SHA-256 string.
    """
    return hashlib.sha256(data).hexdigest().lower()

def compare_hashes(hash_a: str, hash_b: str) -> dict[str, Union[bool, str]]:
    """
    Perform constant-time comparison between two cryptographic hashes.
    
    Protects against timing attacks when comparing sensitive digests.
    Normalizes inputs to lowercase before comparison.
    
    Args:
        hash_a: First hash string
        hash_b: Second hash string
        
    Returns:
        Dictionary containing match status, normalized hashes, and analytical explanation.
    """
    norm_a = (hash_a or "").strip().lower()
    norm_b = (hash_b or "").strip().lower()
    
    is_match = False
    if norm_a and norm_b and len(norm_a) == len(norm_b):
        is_match = hmac.compare_digest(norm_a, norm_b)
        
    explanation = (
        "Hash comparison verified exact bitwise match between digests."
        if is_match
        else "Hashes do not match or one of the inputs was invalid/empty."
    )
    
    return {
        "match": is_match,
        "hash_a": norm_a,
        "hash_b": norm_b,
        "explanation": explanation,
        "security_disclaimer": (
            "Cryptographic hash matching establishes file identity against a known sample, "
            "but does NOT guarantee that the referenced file is safe or free of vulnerabilities."
        )
    }
