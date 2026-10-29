"""
SecureUpload Inspector - Upload Policy Engine Unit Tests
========================================================
Tests rule evaluations, mandatory rejection thresholds, findings structures,
and risk score calculation formulas.
"""

from inspector.policy_engine import (
    evaluate_file_policy,
    DECISION_ACCEPTED,
    DECISION_REJECTED,
    DECISION_REVIEW_REQUIRED,
    rule_check_file_size,
    rule_check_extension_allowlist,
)
from inspector.risk_assessment import calculate_risk_score

def test_valid_pdf_accepted(sample_pdf_bytes):
    """Verify clean PDF passes all policy rules and receives ACCEPTED verdict."""
    result = evaluate_file_policy(
        file_bytes=sample_pdf_bytes,
        filename="project_spec.pdf",
        browser_mime="application/pdf"
    )
    assert result.decision == DECISION_ACCEPTED
    assert result.allowed_by_policy is True
    assert result.risk_assessment.score == 0
    assert result.risk_assessment.level == "LOW"
    assert result.signature_result.detected_type == "pdf"

def test_valid_png_accepted(sample_png_bytes):
    """Verify genuine PNG is accepted."""
    result = evaluate_file_policy(
        file_bytes=sample_png_bytes,
        filename="diagram.png",
        browser_mime="image/png"
    )
    assert result.decision == DECISION_ACCEPTED
    assert result.allowed_by_policy is True

def test_zero_byte_file_rejected(sample_zero_bytes):
    """Verify 0-byte file triggers mandatory rejection under POL-SIZE-001."""
    result = evaluate_file_policy(
        file_bytes=sample_zero_bytes,
        filename="empty.pdf",
        browser_mime="application/pdf"
    )
    assert result.decision == DECISION_REJECTED
    assert result.allowed_by_policy is False
    assert any(f.rule_id == "POL-SIZE-001" and f.status == "FAIL" for f in result.findings)

def test_oversized_file_rejected(sample_png_bytes):
    """Verify file exceeding max_file_size threshold is rejected under POL-SIZE-002."""
    result = evaluate_file_policy(
        file_bytes=sample_png_bytes,
        filename="large.png",
        max_file_size=10  # 10 bytes limit
    )
    assert result.decision == DECISION_REJECTED
    assert any(f.rule_id == "POL-SIZE-002" and f.status == "FAIL" for f in result.findings)

def test_path_traversal_filename_rejected(sample_pdf_bytes):
    """Verify path traversal attempt triggers mandatory rejection under POL-NAME-001."""
    result = evaluate_file_policy(
        file_bytes=sample_pdf_bytes,
        filename="../../system_config.pdf"
    )
    assert result.decision == DECISION_REJECTED
    assert any(f.rule_id == "POL-NAME-001" and f.status == "FAIL" for f in result.findings)

def test_disallowed_extension_rejected(sample_pdf_bytes):
    """Verify disallowed extension is rejected under POL-EXT-001."""
    result = evaluate_file_policy(
        file_bytes=sample_pdf_bytes,
        filename="document.docx"
    )
    assert result.decision == DECISION_REJECTED
    assert any(f.rule_id == "POL-EXT-001" and f.status == "FAIL" for f in result.findings)

def test_signature_mismatch_rejected(sample_png_bytes):
    """Verify extension/signature mismatch (.pdf with PNG magic bytes) is rejected."""
    result = evaluate_file_policy(
        file_bytes=sample_png_bytes,  # PNG bytes
        filename="spoofed_document.pdf"  # Claims to be PDF
    )
    assert result.decision == DECISION_REJECTED
    assert any(f.rule_id == "POL-AGREE-001" and f.status == "FAIL" for f in result.findings)

def test_executable_payload_disguised_rejected(sample_exe_bytes):
    """Verify PE executable bytes disguised as .jpg are rejected."""
    result = evaluate_file_policy(
        file_bytes=sample_exe_bytes,
        filename="photo.jpg"
    )
    assert result.decision == DECISION_REJECTED
    assert any(f.rule_id == "POL-SIG-001" and f.status == "FAIL" for f in result.findings)

def test_executable_double_extension_rejected(sample_pdf_bytes):
    """Verify double extension like invoice.pdf.exe is rejected under POL-NAME-003."""
    result = evaluate_file_policy(
        file_bytes=sample_pdf_bytes,
        filename="invoice.pdf.exe"
    )
    assert result.decision == DECISION_REJECTED
    assert any(f.rule_id == "POL-NAME-003" and f.status == "FAIL" for f in result.findings)

def test_risk_score_capping_and_deduplication():
    """Verify risk scores never exceed 100 and do not duplicate rule_ids."""
    mock_findings = [
        {"rule_id": "POL-EXT-001", "status": "FAIL", "severity": "CRITICAL"},
        {"rule_id": "POL-EXT-001", "status": "FAIL", "severity": "CRITICAL"}, # Duplicate rule
        {"rule_id": "POL-SIG-001", "status": "FAIL", "severity": "CRITICAL"},
        {"rule_id": "POL-AGREE-001", "status": "FAIL", "severity": "CRITICAL"},
        {"rule_id": "POL-NAME-001", "status": "FAIL", "severity": "CRITICAL"},
    ]
    # Sum would be 45 * 5 = 225 without cap and deduplication
    risk = calculate_risk_score(mock_findings)
    assert risk.score <= 100
    assert risk.score == 100
    assert risk.level == "CRITICAL"
    # Deduplication ensures POL-EXT-001 only counted once: 4 distinct rules * 45 = 180 -> capped at 100
    assert len(risk.contributing_factors) == 4
