"""
SecureUpload Inspector - File Signature Unit Tests
==================================================
Tests byte-level signature detection for PDF, PNG, JPEG, text, and prohibited binaries.
"""

import io
from inspector.file_signatures import detect_file_signature, SignatureResult

def test_detect_pdf_signature(sample_pdf_bytes):
    """Verify %PDF- magic bytes detection and high certainty."""
    result = detect_file_signature(sample_pdf_bytes)
    assert result.detected_type == "pdf"
    assert result.signature_valid is True
    assert result.detection_method == "magic_bytes"
    assert result.certainty == "high"
    assert "%PDF-" in result.explanation

def test_detect_png_signature(sample_png_bytes):
    """Verify official 8-byte PNG signature detection."""
    result = detect_file_signature(sample_png_bytes)
    assert result.detected_type == "png"
    assert result.signature_valid is True
    assert result.detection_method == "magic_bytes"
    assert result.certainty == "high"
    assert "PNG" in result.explanation

def test_detect_jpeg_signature(sample_jpeg_bytes):
    """Verify JPEG SOI FF D8 FF marker detection."""
    result = detect_file_signature(sample_jpeg_bytes)
    assert result.detected_type == "jpeg"
    assert result.signature_valid is True
    assert result.detection_method == "magic_bytes"
    assert result.certainty == "high"

def test_detect_probable_text(sample_text_bytes):
    """
    Verify plain text is cautiously labeled as probable_text.
    Specification Rule: Text files lack definitive magic signatures.
    """
    result = detect_file_signature(sample_text_bytes)
    assert result.detected_type == "probable_text"
    assert result.signature_valid is True
    assert result.detection_method == "heuristic_text_analysis"
    assert result.certainty == "medium"
    assert "probable text" in result.explanation.lower()

def test_binary_with_null_bytes_fails_text_heuristic(sample_binary_with_nulls):
    """Verify binary data with null bytes is rejected by text heuristics."""
    result = detect_file_signature(sample_binary_with_nulls)
    # Since it starts with 'RawHeader\x00', it fails text heuristic and is unknown
    assert result.detected_type == "unknown"
    assert result.signature_valid is False

def test_executable_pe_signature_identified(sample_exe_bytes):
    """Verify dangerous MZ/PE headers are intercepted."""
    result = detect_file_signature(sample_exe_bytes)
    assert result.detected_type == "windows_executable_pe"
    assert result.signature_valid is False
    assert result.certainty == "high"

def test_zero_byte_input_returns_empty():
    """Verify 0-byte input produces empty/invalid signature result."""
    result = detect_file_signature(b"")
    assert result.detected_type == "empty"
    assert result.signature_valid is False
    assert "0 bytes" in result.explanation

def test_unknown_arbitrary_signature():
    """Verify unsupported random bytes produce explicit unknown result."""
    random_binary = bytes([0x12, 0x34, 0x56, 0x78, 0x90, 0xAB])
    result = detect_file_signature(random_binary)
    assert result.detected_type == "unknown"
    assert result.signature_valid is False

def test_stream_reading_preserves_position(sample_pdf_bytes):
    """Verify stream position is reset after bounded header read."""
    stream = io.BytesIO(sample_pdf_bytes)
    stream.seek(0)
    result = detect_file_signature(stream)
    assert result.detected_type == "pdf"
    assert stream.tell() == 0  # Position restored
