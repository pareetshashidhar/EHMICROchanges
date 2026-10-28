"""
SecureUpload Inspector - Filename Validation Unit Tests
=======================================================
Tests path traversal detection, length bounds, prohibited characters,
and double extension evasion heuristics.
"""

from inspector.filename_validation import validate_filename

ALLOWED_TEST_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".txt"}

def test_valid_filename():
    """Verify normal compliant filenames pass validation."""
    result = validate_filename("annual_report_2026.pdf", allowed_extensions=ALLOWED_TEST_EXTENSIONS)
    assert result.is_valid is True
    assert result.cleaned_basename == "annual_report_2026.pdf"
    assert result.extension == ".pdf"
    assert len(result.issues) == 0

def test_empty_filename_rejected():
    """Verify empty filename is rejected."""
    result = validate_filename("", allowed_extensions=ALLOWED_TEST_EXTENSIONS)
    assert result.is_valid is False
    assert "Empty filename" in result.rejection_reason

def test_whitespace_filename_rejected():
    """Verify whitespace-only filename is rejected."""
    result = validate_filename("   ", allowed_extensions=ALLOWED_TEST_EXTENSIONS)
    assert result.is_valid is False

def test_path_traversal_relative_rejected():
    """Verify relative traversal sequences are flagged and rejected."""
    result = validate_filename("../../../etc/passwd.txt", allowed_extensions=ALLOWED_TEST_EXTENSIONS)
    assert result.is_valid is False
    assert result.is_path_traversal is True
    assert "Path traversal" in result.rejection_reason

def test_path_traversal_windows_backslash_rejected():
    """Verify Windows backslash traversal sequences are flagged."""
    result = validate_filename(r"..\..\Windows\System32\cmd.exe", allowed_extensions=ALLOWED_TEST_EXTENSIONS)
    assert result.is_valid is False
    assert result.is_path_traversal is True

def test_absolute_path_rejected():
    """Verify absolute paths are rejected directly rather than normalized."""
    result = validate_filename("/var/log/sensitive.txt", allowed_extensions=ALLOWED_TEST_EXTENSIONS)
    assert result.is_valid is False
    assert result.is_path_traversal is True

def test_excessive_length_rejected():
    """Verify filenames exceeding maximum threshold are rejected."""
    long_name = "a" * 260 + ".pdf"
    result = validate_filename(long_name, max_length=255, allowed_extensions=ALLOWED_TEST_EXTENSIONS)
    assert result.is_valid is False
    assert any("exceeds maximum allowed limit" in issue for issue in result.issues)

def test_null_byte_injection_rejected():
    """Verify null bytes in filename trigger immediate rejection."""
    result = validate_filename("exploit.pdf\x00.exe", allowed_extensions=ALLOWED_TEST_EXTENSIONS)
    assert result.is_valid is False
    assert "null byte" in result.rejection_reason.lower()

def test_prohibited_characters_rejected():
    """Verify shell/filesystem metacharacters are rejected."""
    result = validate_filename("test<payload>|script.txt", allowed_extensions=ALLOWED_TEST_EXTENSIONS)
    assert result.is_valid is False
    assert any("prohibited or unsafe characters" in issue for issue in result.issues)

def test_suspicious_double_extension_executable():
    """
    Verify dangerous executable double extensions are identified.
    Rule: secondary or final extension with executable type is SUSPICIOUS_EXECUTABLE.
    """
    result = validate_filename("invoice.pdf.exe", allowed_extensions=ALLOWED_TEST_EXTENSIONS)
    assert result.is_valid is False
    assert result.is_double_extension is True
    assert result.double_extension_risk == "SUSPICIOUS_EXECUTABLE"
    assert "Executable double extension" in result.rejection_reason

def test_suspicious_double_extension_php_disguise():
    """Verify disguised script extension like photo.png.php is rejected."""
    result = validate_filename("photo.png.php", allowed_extensions=ALLOWED_TEST_EXTENSIONS)
    assert result.is_valid is False
    assert result.double_extension_risk == "SUSPICIOUS_EXECUTABLE"

def test_benign_compound_extension_allowed():
    """
    Verify benign compound extensions are classified properly.
    Rule: non-executable compound segments (e.g. data.backup.txt) are BENIGN_COMPOUND.
    """
    result = validate_filename("financial_report.2026.pdf", allowed_extensions=ALLOWED_TEST_EXTENSIONS)
    assert result.is_valid is True
    assert result.is_double_extension is True
    assert result.double_extension_risk == "BENIGN_COMPOUND"

def test_disallowed_extension_rejected():
    """Verify non-allowlisted extension is rejected."""
    result = validate_filename("script.sh", allowed_extensions=ALLOWED_TEST_EXTENSIONS)
    assert result.is_valid is False
    assert "prohibited by policy" in result.rejection_reason.lower()

def test_missing_extension_rejected():
    """Verify extensionless files are rejected."""
    result = validate_filename("README", allowed_extensions=ALLOWED_TEST_EXTENSIONS)
    assert result.is_valid is False
    assert "prohibited by policy" in result.rejection_reason.lower()
