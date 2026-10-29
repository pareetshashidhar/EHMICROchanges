"""
SecureUpload Inspector - Part 3 Demonstration Scenarios (TEST A through TEST J)
================================================================================
Comprehensive verification of all 10 academic faculty demonstration scenarios:
- TEST A: Valid PDF upload -> ACCEPTED
- TEST B: Extension/signature mismatch (PNG renamed to .pdf) -> REJECTED
- TEST C: Prohibited extension (.exe) -> REJECTED
- TEST D: Oversized upload exceeding limit -> REJECTED / 413
- TEST E: SHA-256 cryptographic hash integrity verification
- TEST F: Unknown/unsupported file signature -> REJECTED or REVIEW_REQUIRED (never safe)
- TEST G: Inspection history, text audit report, and JSON export consistency
- TEST H: Storage safety (quarantine isolation & blocked public static access)
- TEST I: Input security (path traversal defense and HTML injection immunity)
- TEST J: Empty database handling with zero-state stability
"""

import io
import json
import pytest
from pathlib import Path

from inspector.hashing import compute_sha256_bytes
from storage.database import (
    get_dashboard_statistics,
    get_inspection_by_id,
    list_inspections_paginated,
    init_db
)
from app import create_app
from config import TestingConfig

def test_scenario_a_valid_pdf(client, sample_pdf_bytes, test_app):
    """
    TEST A — Valid PDF
    Upload a genuine, small PDF.
    Expected: ACCEPTED when all configured rules pass.
    """
    data = {
        "file": (io.BytesIO(sample_pdf_bytes), "academic_paper.pdf", "application/pdf")
    }
    response = client.post("/upload", data=data, content_type="multipart/form-data")
    assert response.status_code == 302
    inspection_id = response.headers["Location"].split("/")[-1]

    # Verify database record
    record = get_inspection_by_id(test_app.config["DATABASE_PATH"], inspection_id)
    assert record is not None
    assert record["decision"] == "ACCEPTED"
    assert record["detected_type"] == "pdf"
    assert record["file_size"] == len(sample_pdf_bytes)

    # Verify physical file is stored in accepted vault
    accepted_dir = Path(test_app.config["ACCEPTED_STORAGE_DIR"])
    assert (accepted_dir / f"{inspection_id}.accepted").is_file()

    # Verify results page renders ACCEPTED with icon and disclaimer
    results_resp = client.get(f"/results/{inspection_id}")
    assert results_resp.status_code == 200
    assert "ACCEPTED" in results_resp.text
    assert "Passing file validation does not guarantee that a file is free of malware" in results_resp.text


def test_scenario_b_extension_signature_mismatch(client, sample_png_bytes, test_app):
    """
    TEST B — Extension/signature mismatch
    Use a harmless PNG image renamed with a .pdf extension.
    Expected: REJECTED under the default mismatch policy.
    """
    # Supply PNG bytes with .pdf extension and declared PDF mime
    data = {
        "file": (io.BytesIO(sample_png_bytes), "spoofed_image.pdf", "application/pdf")
    }
    response = client.post("/upload", data=data, content_type="multipart/form-data")
    assert response.status_code == 302
    inspection_id = response.headers["Location"].split("/")[-1]

    record = get_inspection_by_id(test_app.config["DATABASE_PATH"], inspection_id)
    assert record is not None
    assert record["decision"] == "REJECTED"
    assert record["detected_type"] == "png"
    assert record["extension"] == ".pdf"

    # Verify finding notes the mismatch
    findings = record["findings"]
    mismatch_findings = [f for f in findings if f["rule_id"] == "POL-AGREE-001"]
    assert len(mismatch_findings) > 0
    assert mismatch_findings[0]["status"] == "FAIL"

    # Verify file NEVER entered accepted storage
    accepted_path = Path(test_app.config["ACCEPTED_STORAGE_DIR"]) / f"{inspection_id}.accepted"
    assert not accepted_path.exists()


def test_scenario_c_prohibited_extension(client, sample_text_bytes, test_app):
    """
    TEST C — Prohibited extension
    Upload a harmless text file renamed to .exe.
    Expected: REJECTED because the extension is not permitted.
    """
    data = {
        "file": (io.BytesIO(sample_text_bytes), "installer.exe", "application/x-msdownload")
    }
    response = client.post("/upload", data=data, content_type="multipart/form-data")
    assert response.status_code == 302
    inspection_id = response.headers["Location"].split("/")[-1]

    record = get_inspection_by_id(test_app.config["DATABASE_PATH"], inspection_id)
    assert record is not None
    assert record["decision"] == "REJECTED"
    assert record["extension"] == ".exe"

    # Verify allowlist failure finding
    findings = record["findings"]
    ext_findings = [f for f in findings if f["rule_id"] == "POL-EXT-001"]
    assert len(ext_findings) > 0
    assert ext_findings[0]["status"] == "FAIL"
    assert "not in allowed extensions" in ext_findings[0]["evidence"].lower()


def test_scenario_d_oversized_upload(client, test_app):
    """
    TEST D — Oversized upload
    Submit a file exceeding the configured limit.
    Expected: REJECTED with a clear error message.
    """
    # Create payload exceeding 10MB limit (10MB + 128 bytes)
    oversized_size = 10 * 1024 * 1024 + 128
    # Prefix with valid PDF signature so size rule triggers distinctly
    oversized_bytes = b"%PDF-1.4\n" + (b"A" * (oversized_size - 9))

    data = {
        "file": (io.BytesIO(oversized_bytes), "oversized_paper.pdf", "application/pdf")
    }
    response = client.post("/upload", data=data, content_type="multipart/form-data")

    # In our app, if within Flask MAX_CONTENT_LENGTH (12MB) it inspects and rejects via policy engine
    assert response.status_code == 302
    inspection_id = response.headers["Location"].split("/")[-1]
    record = get_inspection_by_id(test_app.config["DATABASE_PATH"], inspection_id)
    assert record is not None
    assert record["decision"] == "REJECTED"
    size_findings = [f for f in record["findings"] if f["rule_id"] == "POL-SIZE-002"]
    assert len(size_findings) > 0
    assert size_findings[0]["status"] == "FAIL"


def test_scenario_e_hash_integrity():
    """
    TEST E — Hash integrity
    Calculate the SHA-256 hash of a test text file. Modify the file and calculate its hash again.
    Expected: The hashes differ.
    """
    original_content = b"Cybersecurity audit baseline specification v1.0\nIntegrity check line.\n"
    modified_content = b"Cybersecurity audit baseline specification v1.0\nIntegrity check line modified.\n"

    hash_original = compute_sha256_bytes(original_content)
    hash_modified = compute_sha256_bytes(modified_content)

    assert len(hash_original) == 64
    assert len(hash_modified) == 64
    assert hash_original != hash_modified

    # Even a 1-bit difference must produce an entirely different digest
    tampered_by_one_byte = original_content[:-1] + b"!"
    hash_tampered = compute_sha256_bytes(tampered_by_one_byte)
    assert hash_tampered != hash_original


def test_scenario_f_unknown_file_type(client, test_app):
    """
    TEST F — Unknown file type
    Upload a harmless file whose signature is not supported.
    Expected: REVIEW REQUIRED or REJECTED according to documented policy.
    It must never be automatically declared safe.
    """
    # Random unmapped binary payload with null bytes
    unsupported_payload = b"\x1b\x03\x5a\x7f\x00\xaa\xbb\xcc\xdd\xee\xff\x99\x88\x77"
    data = {
        "file": (io.BytesIO(unsupported_payload), "custom_data.txt", "text/plain")
    }
    response = client.post("/upload", data=data, content_type="multipart/form-data")
    assert response.status_code == 302
    inspection_id = response.headers["Location"].split("/")[-1]

    record = get_inspection_by_id(test_app.config["DATABASE_PATH"], inspection_id)
    assert record is not None
    # Crucial security guarantee: It must NEVER be ACCEPTED
    assert record["decision"] in ("REJECTED", "REVIEW_REQUIRED")
    assert record["decision"] != "ACCEPTED"
    assert record["detected_type"] != "pdf"


def test_scenario_g_history_and_reporting(client, sample_pdf_bytes, test_app):
    """
    TEST G — History and reporting
    Complete an inspection, open its history entry, view its report, and export JSON.
    Expected: The stored values and report match the original inspection.
    """
    # 1. Upload valid file
    data = {
        "file": (io.BytesIO(sample_pdf_bytes), "forensic_analysis.pdf", "application/pdf")
    }
    upload_resp = client.post("/upload", data=data, content_type="multipart/form-data")
    insp_id = upload_resp.headers["Location"].split("/")[-1]

    # 2. Check history page
    hist_resp = client.get("/history")
    assert hist_resp.status_code == 200
    assert "forensic_analysis.pdf" in hist_resp.text
    assert insp_id in hist_resp.text

    # 3. Check plain text report
    report_resp = client.get(f"/inspection/{insp_id}/report")
    assert report_resp.status_code == 200
    assert report_resp.mimetype == "text/plain"
    report_text = report_resp.data.decode("utf-8")
    assert f"Inspection ID:     {insp_id}" in report_text
    assert "forensic_analysis.pdf" in report_text
    assert "VERDICT & RISK POSTURE:" in report_text
    assert "CYBERSECURITY DISCLAIMER:" in report_text
    assert "Passing file validation does not guarantee that a file is free of malware" in report_text

    # 4. Check JSON export
    json_resp = client.get(f"/inspection/{insp_id}/report.json")
    assert json_resp.status_code == 200
    assert json_resp.mimetype == "application/json"
    json_data = json.loads(json_resp.data)
    assert json_data["inspection_summary"]["id"] == insp_id
    assert json_data["inspection_summary"]["original_filename"] == "forensic_analysis.pdf"
    assert json_data["inspection_summary"]["final_decision"] == "ACCEPTED"
    assert "checks_summary" in json_data
    assert "academic_disclaimer" in json_data
    assert "malware" in json_data["academic_disclaimer"].lower()


def test_scenario_h_storage_safety(client, sample_png_bytes, test_app):
    """
    TEST H — Storage safety
    Verify that rejected files do not enter accepted storage and that
    uploaded files cannot be accessed through public static URLs.
    """
    # 1. Upload rejected file (mismatch)
    data = {
        "file": (io.BytesIO(sample_png_bytes), "trojan_disguised.pdf", "application/pdf")
    }
    post_res = client.post("/upload", data=data, content_type="multipart/form-data")
    insp_id = post_res.headers["Location"].split("/")[-1]

    # Accepted vault check: file MUST NOT exist there
    accepted_dir = Path(test_app.config["ACCEPTED_STORAGE_DIR"])
    assert not (accepted_dir / f"{insp_id}.accepted").exists()

    # Public static URL direct access check: verify uploads are blocked from public serving
    static_attempt1 = client.get(f"/static/accepted_uploads/{insp_id}.accepted")
    assert static_attempt1.status_code == 404

    static_attempt2 = client.get(f"/static/quarantine/{insp_id}.quarantine")
    assert static_attempt2.status_code == 404

    direct_attempt = client.get(f"/accepted_uploads/{insp_id}.accepted")
    assert direct_attempt.status_code == 404


def test_scenario_i_input_security(client, sample_pdf_bytes, test_app):
    """
    TEST I — Input security
    Verify that path traversal attempts, malformed input, and HTML-like
    filenames cannot cause filesystem access or HTML injection.
    """
    # 1. Path traversal attempt in filename
    traversal_data = {
        "file": (io.BytesIO(sample_pdf_bytes), "../../../../etc/passwd.pdf", "application/pdf")
    }
    res_trav = client.post("/upload", data=traversal_data, content_type="multipart/form-data")
    assert res_trav.status_code == 302
    insp_id_trav = res_trav.headers["Location"].split("/")[-1]
    rec_trav = get_inspection_by_id(test_app.config["DATABASE_PATH"], insp_id_trav)
    assert rec_trav["decision"] == "REJECTED"
    trav_findings = [f for f in rec_trav["findings"] if f["rule_id"] == "POL-NAME-001"]
    assert len(trav_findings) > 0
    assert trav_findings[0]["status"] == "FAIL"

    # 2. XSS / HTML injection in filename
    xss_payload_name = "<script>alert('XSS')</script>.pdf"
    xss_data = {
        "file": (io.BytesIO(sample_pdf_bytes), xss_payload_name, "application/pdf")
    }
    res_xss = client.post("/upload", data=xss_data, content_type="multipart/form-data")
    assert res_xss.status_code == 302
    insp_id_xss = res_xss.headers["Location"].split("/")[-1]

    # View results page - script tag must NOT render raw (must be escaped or sanitized)
    detail_res = client.get(f"/inspection/{insp_id_xss}")
    assert detail_res.status_code == 200
    # In Jinja2 auto-escaped output:
    assert "<script>alert('XSS')</script>" not in detail_res.data.decode("utf-8") or "&lt;script&gt;" in detail_res.data.decode("utf-8")


def test_scenario_j_empty_database(tmp_path: Path):
    """
    TEST J — Empty database
    Start the application with a fresh, empty database.
    Expected: Dashboard displays valid zero-state statistics without crashing.
    """
    fresh_db = str(tmp_path / "fresh_zero_state.db")
    class FreshTestingConfig(TestingConfig):
        DATABASE_PATH = fresh_db
        WTF_CSRF_ENABLED = False

    app = create_app(FreshTestingConfig)
    fresh_client = app.test_client()

    # Database metrics verification directly
    stats = get_dashboard_statistics(fresh_db)
    assert stats["total_inspected"] == 0
    assert stats["accepted_count"] == 0
    assert stats["rejected_count"] == 0
    assert stats["review_count"] == 0
    assert stats["type_distribution"] == {}
    assert stats["recent_inspections"] == []
    assert stats["recent_findings"] == []

    # GET / renders 200 without ZeroDivisionError
    dash_resp = fresh_client.get("/")
    assert dash_resp.status_code == 200
    html = dash_resp.data.decode("utf-8")
    assert "No inspections recorded yet" in html
    assert "No format distribution data yet" in html
