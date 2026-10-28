"""
SecureUpload Inspector - Security Reports Unit Tests
====================================================
Tests plain text compliance summaries and JSON audit report endpoints.
"""

import json
from services.report_service import generate_inspection_report, export_json_report

def test_generate_text_report_contains_mandatory_disclaimer():
    """Verify generated text report contains disclaimers, hashes, and findings."""
    mock_record = {
        "id": "uuid-test-report-01",
        "created_at": "2026-10-12T12:00:00Z",
        "timestamp": "2026-10-12T12:00:00Z",
        "original_filename": "financial_audit.pdf",
        "sanitized_filename": "financial_audit.pdf",
        "file_size": 10240,
        "declared_mime_type": "application/pdf",
        "browser_mime": "application/pdf",
        "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "detected_type": "pdf",
        "decision": "ACCEPTED",
        "risk_score": 0,
        "risk_level": "LOW",
        "summary": "Valid PDF file.",
        "findings": [
            {
                "rule_id": "POL-EXT-001",
                "title": "Extension Allowlist",
                "status": "PASS",
                "severity": "INFO",
                "evidence": ".pdf is allowed",
                "explanation": "Complies with policy",
                "recommendation": "None"
            }
        ]
    }
    report = generate_inspection_report(mock_record)
    assert "SECUREUPLOAD INSPECTOR" in report
    assert "financial_audit.pdf" in report
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in report
    assert "ACCEPTED" in report
    assert "Total Checks Performed: 1" in report
    assert "Passed Checks:          1" in report
    assert "CYBERSECURITY DISCLAIMER" in report
    assert "DO NOT establish that the file is free of zero-day malware" in report

def test_export_json_report_structure():
    """Verify JSON report parses properly and contains schema keys."""
    mock_record = {
        "id": "uuid-test-json-02",
        "created_at": "2026-10-12T13:00:00Z",
        "timestamp": "2026-10-12T13:00:00Z",
        "original_filename": "image.png",
        "sanitized_filename": "image.png",
        "file_size": 512,
        "declared_mime_type": "image/png",
        "browser_mime": "image/png",
        "sha256_hash": "a" * 64,
        "detected_type": "png",
        "decision": "ACCEPTED",
        "risk_score": 0,
        "risk_level": "LOW",
        "summary": "Clean PNG image.",
        "findings": [
            {
                "rule_id": "POL-SIG-001",
                "title": "PNG Signature",
                "status": "PASS",
                "severity": "INFO",
                "evidence": "89PNG",
                "explanation": "Valid signature",
                "recommendation": "None"
            }
        ]
    }
    json_str = export_json_report(mock_record)
    parsed = json.loads(json_str)

    assert "report_metadata" in parsed
    assert "inspection_summary" in parsed
    assert parsed["inspection_summary"]["id"] == "uuid-test-json-02"
    assert parsed["inspection_summary"]["file_size"] == 512
    assert parsed["inspection_summary"]["declared_mime_type"] == "image/png"
    assert parsed["inspection_summary"]["final_decision"] == "ACCEPTED"
    assert "checks_summary" in parsed
    assert parsed["checks_summary"]["total_checks_performed"] == 1
    assert parsed["checks_summary"]["passed_checks_count"] == 1
    assert "passed_checks" in parsed
    assert "failed_checks" in parsed
    assert "warnings" in parsed
    assert "academic_disclaimer" in parsed
    assert "malware" in parsed["academic_disclaimer"].lower()

def test_report_routes_http(client, seeded_db):
    """Verify HTTP download endpoints for text, JSON, and report.json."""
    # Text report
    res_text = client.get("/inspection/test-accepted-uuid-001/report")
    assert res_text.status_code == 200
    assert res_text.mimetype == "text/plain"
    assert b"whitepaper.pdf" in res_text.data

    # Standard report.json endpoint
    res_json_std = client.get("/inspection/test-accepted-uuid-001/report.json")
    assert res_json_std.status_code == 200
    assert res_json_std.mimetype == "application/json"
    parsed_std = json.loads(res_json_std.data)
    assert parsed_std["inspection_summary"]["id"] == "test-accepted-uuid-001"
    assert "checks_summary" in parsed_std

    # Backward-compatible .json endpoint
    res_json = client.get("/inspection/test-accepted-uuid-001/json")
    assert res_json.status_code == 200
    assert res_json.mimetype == "application/json"
