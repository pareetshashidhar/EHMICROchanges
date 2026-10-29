"""
SecureUpload Inspector - Pytest Fixtures & Test Setup
=====================================================
Provides reusable binary samples, mock uploads, and an isolated Flask test client.
"""

import io
import pytest
from pathlib import Path

from config import TestingConfig
from app import create_app
from storage.database import init_db, save_inspection

@pytest.fixture
def sample_pdf_bytes() -> bytes:
    """Standard valid PDF header and dummy content."""
    return b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<< /Title (Test Document) >>\nendobj\ntrailer\n<<>>\n%%EOF"

@pytest.fixture
def sample_png_bytes() -> bytes:
    """Standard valid 8-byte PNG header and IHDR chunk."""
    return b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc`\x00\x00\x00\x02\x00\x01H\xaf\xa4q\x00\x00\x00\x00IEND\xaeB`\x82"

@pytest.fixture
def sample_jpeg_bytes() -> bytes:
    """Standard valid JPEG SOI marker and JFIF header."""
    return b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\xff\xd9"

@pytest.fixture
def sample_text_bytes() -> bytes:
    """Valid UTF-8 plain text data."""
    return "This is a legitimate academic cybersecurity text report.\nValidation test line 2.\n".encode("utf-8")

@pytest.fixture
def sample_binary_with_nulls() -> bytes:
    """Non-text binary payload with interspersed null bytes."""
    return b"RawHeader\x00\x01\x02\x03\x00\xff\xfe\x00BinaryPayload"

@pytest.fixture
def sample_exe_bytes() -> bytes:
    """Simulated PE/MZ executable header."""
    return b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00This program cannot be run in DOS mode."

@pytest.fixture
def sample_zero_bytes() -> bytes:
    """Empty 0-byte payload."""
    return b""

@pytest.fixture
def test_app(tmp_path: Path):
    """Flask application configured for testing with isolated directories."""
    test_db = str(tmp_path / "test_secureupload.db")
    test_accepted = str(tmp_path / "accepted_storage")
    test_quarantine = str(tmp_path / "quarantine")
    test_audit = str(tmp_path / "audit.log")

    class CustomTestingConfig(TestingConfig):
        DATABASE_PATH = test_db
        ACCEPTED_STORAGE_DIR = test_accepted
        QUARANTINE_DIR = test_quarantine
        AUDIT_LOG_PATH = test_audit
        WTF_CSRF_ENABLED = False

    app = create_app(CustomTestingConfig)
    yield app

@pytest.fixture
def client(test_app):
    """Flask test client for issuing HTTP requests."""
    return test_app.test_client()

@pytest.fixture
def client_with_csrf(tmp_path: Path):
    """Flask test client with CSRF protection strictly enabled."""
    test_db = str(tmp_path / "test_csrf_secureupload.db")
    test_accepted = str(tmp_path / "accepted_storage_csrf")
    test_quarantine = str(tmp_path / "quarantine_csrf")
    test_audit = str(tmp_path / "audit_csrf.log")

    class CsrfTestingConfig(TestingConfig):
        DATABASE_PATH = test_db
        ACCEPTED_STORAGE_DIR = test_accepted
        QUARANTINE_DIR = test_quarantine
        AUDIT_LOG_PATH = test_audit
        WTF_CSRF_ENABLED = True

    app = create_app(CsrfTestingConfig)
    return app.test_client()

@pytest.fixture
def seeded_db(test_app):
    """Pre-populated SQLite database with representative inspections."""
    db_path = test_app.config["DATABASE_PATH"]
    records = [
        {
            "id": "test-accepted-uuid-001",
            "created_at": "2026-10-12T10:00:00Z",
            "timestamp": "2026-10-12T10:00:00Z",
            "original_filename": "whitepaper.pdf",
            "sanitized_filename": "whitepaper.pdf",
            "file_size": 2048,
            "sha256_hash": "a" * 64,
            "detected_type": "pdf",
            "extension": ".pdf",
            "declared_mime_type": "application/pdf",
            "browser_mime": "application/pdf",
            "decision": "ACCEPTED",
            "risk_score": 0,
            "risk_level": "LOW",
            "findings_json": '[{"rule_id":"POL-EXT-001","title":"Extension Allowlist","severity":"INFO","status":"PASS","evidence":".pdf is allowed","explanation":"Complies with policy","recommendation":"None"}]',
            "summary": "Valid PDF file.",
            "storage_path": "instance/accepted_uploads/test-accepted-uuid-001.accepted",
            "client_ip": "127.0.0.1"
        },
        {
            "id": "test-rejected-uuid-002",
            "created_at": "2026-10-12T11:00:00Z",
            "timestamp": "2026-10-12T11:00:00Z",
            "original_filename": "malware.pdf.exe",
            "sanitized_filename": "malware.pdf.exe",
            "file_size": 4096,
            "sha256_hash": "b" * 64,
            "detected_type": "windows_executable_pe",
            "extension": ".exe",
            "declared_mime_type": "application/x-msdownload",
            "browser_mime": "application/x-msdownload",
            "decision": "REJECTED",
            "risk_score": 95,
            "risk_level": "CRITICAL",
            "findings_json": '[{"rule_id":"POL-NAME-003","title":"Executable Double Extension","severity":"CRITICAL","status":"FAIL","evidence":"malware.pdf.exe","explanation":"Double extension","recommendation":"Reject"}]',
            "summary": "Disguised executable payload.",
            "storage_path": "instance/quarantine/test-rejected-uuid-002.quarantine",
            "client_ip": "192.168.1.100"
        },
        {
            "id": "test-review-uuid-003",
            "created_at": "2026-10-12T12:00:00Z",
            "timestamp": "2026-10-12T12:00:00Z",
            "original_filename": "notes.txt",
            "sanitized_filename": "notes.txt",
            "file_size": 128,
            "sha256_hash": "c" * 64,
            "detected_type": "probable_text",
            "extension": ".txt",
            "declared_mime_type": "text/plain",
            "browser_mime": "text/plain",
            "decision": "REVIEW_REQUIRED",
            "risk_score": 25,
            "risk_level": "MEDIUM",
            "findings_json": '[{"rule_id":"POL-SIG-001","title":"Probable Text Heuristic","severity":"LOW","status":"WARN","evidence":"Decoded text","explanation":"Probable text","recommendation":"Review"}]',
            "summary": "Probable text requiring review.",
            "storage_path": "instance/quarantine/test-review-uuid-003.quarantine",
            "client_ip": "127.0.0.1"
        }
    ]
    for r in records:
        save_inspection(db_path, r)
    return db_path
