"""
SecureUpload Inspector - File Signature Detection Module
=========================================================
Reads a bounded amount of file header data to identify file formats
using magic bytes and cautious heuristic analysis.

SPECIFICATION COMPLIANCE:
- PDF: starts with b'%PDF-'
- PNG: official 8-byte signature b'\\x89PNG\\r\\n\\x1a\\n'
- JPEG: SOI marker b'\\xff\\xd8\\xff'
- Probable text: cautious text classification (NOT conclusively verified)
- Unknown: explicit unknown or unsupported result
"""

from dataclasses import dataclass, asdict
from typing import BinaryIO, Union
import string

# Bounded buffer size: we never load unbounded file content for signature inspection
MAX_HEADER_SAMPLE_SIZE = 4096

# Canonical magic byte signatures
SIGNATURE_PNG = b"\x89PNG\r\n\x1a\n"
SIGNATURE_PDF_PREFIX = b"%PDF-"
SIGNATURE_JPEG_PREFIX = b"\xff\xd8\xff"

# Binary signatures of common executable formats (for forensic identification when unknown)
DANGEROUS_SIGNATURES = {
    b"MZ": ("windows_executable_pe", "Windows Portable Executable (EXE/DLL)"),
    b"\x7fELF": ("linux_executable_elf", "Linux Executable and Linkable Format (ELF)"),
    b"\xca\xfe\xba\xbe": ("mach_o_or_java", "Mach-O Universal Binary or Java Class"),
    b"PK\x03\x04": ("zip_archive", "ZIP Archive or OOXML container"),
    b"Rar!\x1a\x07": ("rar_archive", "RAR Archive"),
    b"\x1f\x8b\x08": ("gzip_compressed", "GZIP Compressed Archive"),
}

@dataclass
class SignatureResult:
    """Structured result of file signature inspection."""
    detected_type: str          # 'pdf', 'png', 'jpeg', 'probable_text', 'unknown', or specific danger
    signature_valid: bool       # True if a recognized format signature or heuristic matched
    detection_method: str       # 'magic_bytes', 'heuristic_text_analysis', 'none'
    certainty: str              # 'high', 'medium', 'low', 'none'
    explanation: str            # Detailed analytical rationale
    magic_bytes_hex: str = ""   # Hex representation of initial header bytes
    header_preview: str = ""    # Safe sanitized text preview if printable

    def to_dict(self) -> dict:
        return asdict(self)


def _safe_header_preview(header_sample: bytes, max_len: int = 64) -> str:
    """Produce a safe ASCII-printable representation of header bytes."""
    preview = []
    for b in header_sample[:max_len]:
        if 32 <= b <= 126:
            preview.append(chr(b))
        else:
            preview.append(".")
    return "".join(preview)


def _is_probable_text(sample: bytes) -> tuple[bool, str, str]:
    """
    Cautiously evaluate whether a bounded byte sample is probable text.
    
    A text file has NO single definitive magic signature.
    We classify it as probable text only if it strictly decodes as UTF-8/ASCII
    and contains no null bytes or prohibited control codes.
    
    Returns:
        (is_probable_text, certainty, explanation)
    """
    if not sample:
        return False, "none", "Empty sample cannot be classified as text."

    # Immediate rejection if null bytes are present (null bytes are characteristic of binary)
    if b"\x00" in sample:
        return False, "high", "Sample contains null bytes (\\x00); file is binary, not plain text."

    # Attempt UTF-8 decoding
    try:
        decoded_text = sample.decode("utf-8")
    except UnicodeDecodeError:
        try:
            # Fallback check for Latin-1 / ASCII
            decoded_text = sample.decode("ascii")
        except UnicodeDecodeError:
            return False, "high", "Sample fails UTF-8 and ASCII decoding; file contains non-text byte sequences."

    # Inspect character distribution
    # Allowed control chars in text: tab (9), newline (10), carriage return (13)
    allowed_whitespace_ord = {9, 10, 13}
    control_char_count = 0
    printable_count = 0

    for char in decoded_text:
        codepoint = ord(char)
        if char in string.printable or codepoint in allowed_whitespace_ord or codepoint > 127:
            printable_count += 1
        else:
            control_char_count += 1

    total_chars = len(decoded_text)
    if total_chars == 0:
        return False, "none", "Sample contains zero decodable characters."

    control_ratio = control_char_count / total_chars
    if control_ratio > 0.02:
        return False, "high", f"Sample contains excessive unprintable control characters ({control_char_count}); binary payload indicated."

    # High printable ratio without null bytes: cautious probable text
    return (
        True,
        "medium",
        "Sample decoded cleanly as UTF-8 with standard printable text and whitespace. "
        "Classified cautiously as probable text (text files lack definitive magic byte signatures)."
    )


def detect_file_signature(source: Union[bytes, BinaryIO], sample_size: int = MAX_HEADER_SAMPLE_SIZE) -> SignatureResult:
    """
    Inspect file header bytes and return structured signature validation.
    
    Accepts either raw bytes or a binary stream. Reads at most sample_size bytes.
    If a stream is passed, its read position is preserved if seekable.
    
    Args:
        source: Bytes or binary stream
        sample_size: Maximum bytes to read from the header (default 4096)
        
    Returns:
        SignatureResult containing detection status, certainty, and rationale.
    """
    header_bytes: bytes = b""

    if isinstance(source, bytes):
        header_bytes = source[:sample_size]
    elif hasattr(source, "read"):
        initial_pos = None
        if hasattr(source, "seekable") and source.seekable():
            try:
                initial_pos = source.tell()
                source.seek(0)
            except (OSError, ValueError):
                initial_pos = None

        header_bytes = source.read(sample_size)

        if initial_pos is not None and hasattr(source, "seek"):
            try:
                source.seek(initial_pos)
            except (OSError, ValueError):
                pass
    else:
        raise TypeError("Source must be bytes or a binary readable stream")

    if not header_bytes:
        return SignatureResult(
            detected_type="empty",
            signature_valid=False,
            detection_method="none",
            certainty="high",
            explanation="File contains 0 bytes; zero-byte files have no signature and fail validation policy.",
            magic_bytes_hex="",
            header_preview=""
        )

    magic_hex = header_bytes[:16].hex()
    preview = _safe_header_preview(header_bytes[:64])

    # 1. Check PNG Signature (Exact 8 bytes: 89 50 4E 47 0D 0A 1A 0A)
    if header_bytes.startswith(SIGNATURE_PNG):
        return SignatureResult(
            detected_type="png",
            signature_valid=True,
            detection_method="magic_bytes",
            certainty="high",
            explanation="Official 8-byte PNG file signature (\\x89PNG\\r\\n\\x1a\\n) verified at offset 0.",
            magic_bytes_hex=magic_hex,
            header_preview=preview
        )

    # 2. Check JPEG Signature (FF D8 FF)
    if header_bytes.startswith(SIGNATURE_JPEG_PREFIX):
        return SignatureResult(
            detected_type="jpeg",
            signature_valid=True,
            detection_method="magic_bytes",
            certainty="high",
            explanation="JPEG Start-of-Image (SOI) marker (FF D8 FF) verified at offset 0.",
            magic_bytes_hex=magic_hex,
            header_preview=preview
        )

    # 3. Check PDF Signature (%PDF-)
    if header_bytes.startswith(SIGNATURE_PDF_PREFIX):
        # Extract version if present (e.g., %PDF-1.4, %PDF-1.7, %PDF-2.0)
        first_line = header_bytes.split(b"\n")[0].split(b"\r")[0]
        version_str = first_line.decode("latin1", errors="replace")
        return SignatureResult(
            detected_type="pdf",
            signature_valid=True,
            detection_method="magic_bytes",
            certainty="high",
            explanation=f"Standard PDF header signature (%PDF-) verified at offset 0 ({version_str}).",
            magic_bytes_hex=magic_hex,
            header_preview=preview
        )

    # 4. Check for known dangerous binary executable/archive signatures
    for sig, (ftype, desc) in DANGEROUS_SIGNATURES.items():
        if header_bytes.startswith(sig):
            return SignatureResult(
                detected_type=ftype,
                signature_valid=False,
                detection_method="magic_bytes",
                certainty="high",
                explanation=f"Header matches prohibited binary/executable signature: {desc}.",
                magic_bytes_hex=magic_hex,
                header_preview=preview
            )

    # 5. Check Probable Text (Cautious heuristic classification)
    is_text, text_certainty, text_explanation = _is_probable_text(header_bytes)
    if is_text:
        return SignatureResult(
            detected_type="probable_text",
            signature_valid=True,
            detection_method="heuristic_text_analysis",
            certainty=text_certainty,
            explanation=text_explanation,
            magic_bytes_hex=magic_hex,
            header_preview=preview
        )

    # 6. Explicit Unknown or Unsupported Result
    return SignatureResult(
        detected_type="unknown",
        signature_valid=False,
        detection_method="none",
        certainty="high",
        explanation="Header does not match any allowed file signatures (%PDF-, PNG, JPEG) and failed text heuristics.",
        magic_bytes_hex=magic_hex,
        header_preview=preview
    )
