"""
SecureUpload Inspector - Security Reporting Service
===================================================
Produces human-readable compliance summaries and structured JSON audit
reports for file inspection events.

SECURITY CONTROLS:
- User-controlled inputs are sanitized.
- Internal filesystem paths and server configuration secrets are NEVER exposed.
- All report data originates from genuine inspection results.
- Includes mandatory academic cybersecurity disclaimers.
"""

import json
from typing import Any

def categorize_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Sort individual findings by PASS, FAIL, and WARN status."""
    passed = []
    failed = []
    warnings = []

    for f in findings:
        status = f.get("status", "").upper()
        if status == "PASS":
            passed.append(f)
        elif status == "FAIL":
            failed.append(f)
        elif status == "WARN":
            warnings.append(f)

    return {
        "total_performed": len(findings),
        "passed_checks": passed,
        "failed_checks": failed,
        "warnings": warnings,
        "passed_count": len(passed),
        "failed_count": len(failed),
        "warnings_count": len(warnings),
    }

def generate_inspection_report(record: dict[str, Any]) -> str:
    """
    Generate a comprehensive text-based cybersecurity inspection report.
    
    Args:
        record: Inspection record dictionary from database
        
    Returns:
        Formatted multi-section report string.
    """
    findings = record.get("findings", [])
    if isinstance(findings, str):
        try:
            findings = json.loads(findings)
        except Exception:
            findings = []

    cat = categorize_findings(findings)
    timestamp_val = record.get("created_at") or record.get("timestamp") or "N/A"
    declared_mime = record.get("declared_mime_type") or record.get("browser_mime") or "N/A"

    lines = [
        "=" * 72,
        " SECUREUPLOAD INSPECTOR - COMPREHENSIVE FILE AUDIT & VALIDATION REPORT",
        "=" * 72,
        f"Inspection ID:     {record.get('id', 'N/A')}",
        f"Timestamp (UTC):   {timestamp_val}",
        f"Original Filename: {record.get('original_filename', 'N/A')}",
        f"Sanitized Name:    {record.get('sanitized_filename', 'N/A')}",
        f"File Size:         {record.get('file_size', 0):,} bytes",
        f"Declared MIME:     {declared_mime}",
        f"Detected Format:   {record.get('detected_type', 'unknown').upper()}",
        f"Expected Format:   {record.get('expected_type', 'unknown').upper()}",
        f"SHA-256 Digest:    {record.get('sha256_hash', 'N/A')}",
        "-" * 72,
        "VERDICT & RISK POSTURE:",
        f"  Final Decision:  [{record.get('decision', 'UNKNOWN')}]",
        f"  Risk Score:      {record.get('risk_score', 0)} / 100 ({record.get('risk_level', 'LOW')})",
        f"  Summary:         {record.get('summary', 'No summary available.')}",
        "-" * 72,
        "CHECKS SUMMARY:",
        f"  Total Checks Performed: {cat['total_performed']}",
        f"  Passed Checks:          {cat['passed_count']}",
        f"  Failed Checks:          {cat['failed_count']}",
        f"  Warnings:               {cat['warnings_count']}",
        "-" * 72,
        "ITEMIZED POLICY FINDINGS:",
    ]

    if not findings:
        lines.append("  No individual findings recorded.")
    else:
        for idx, f in enumerate(findings, 1):
            lines.append(
                f"  [{idx}] {f.get('rule_id')} - {f.get('title')} [{f.get('status')}]"
            )
            lines.append(f"      Severity:       {f.get('severity')}")
            lines.append(f"      Evidence:       {f.get('evidence')}")
            lines.append(f"      Explanation:    {f.get('explanation')}")
            lines.append(f"      Recommendation: {f.get('recommendation')}")
            lines.append("")

    lines.extend([
        "-" * 72,
        "RECOMMENDED ACTIONS:",
    ])

    recommendations = [f.get("recommendation") for f in findings if f.get("recommendation") and f.get("status") in {"FAIL", "WARN"}]
    if recommendations:
        for r in recommendations:
            lines.append(f"  - {r}")
    else:
        lines.append("  - File conforms to active upload policies; proceed according to standard workflow.")

    lines.extend([
        "-" * 72,
        "CYBERSECURITY DISCLAIMER:",
        "  Passing file validation does not guarantee that a file is free of malware.",
        "  This tool validates file properties and configured upload policies; it is not",
        "  a complete antivirus engine.",
        "  Structural checks DO NOT establish that the file is free of zero-day malware or exploit payloads.",
        "=" * 72,
    ])

    return "\n".join(lines)

def export_json_report(record: dict[str, Any]) -> str:
    """
    Format an inspection record as a structured, safe JSON document.
    Does not expose sensitive internal filesystem paths.
    """
    findings = record.get("findings", [])
    if isinstance(findings, str):
        try:
            findings = json.loads(findings)
        except Exception:
            findings = []

    cat = categorize_findings(findings)
    timestamp_val = record.get("created_at") or record.get("timestamp") or ""
    declared_mime = record.get("declared_mime_type") or record.get("browser_mime") or ""

    recommendations = [
        f.get("recommendation") for f in findings
        if f.get("recommendation") and f.get("status") in {"FAIL", "WARN"}
    ]

    export_data = {
        "report_metadata": {
            "generator": "SecureUpload Inspector v3.0 (Academic Edition)",
            "standards": ["OWASP File Upload Cheat Sheet", "NIST SP 800-53", "CWE-434"],
            "security_notice": "Structural compliance verification; does not guarantee absence of malware."
        },
        "inspection_summary": {
            "id": record.get("id"),
            "timestamp": timestamp_val,
            "original_filename": record.get("original_filename"),
            "sanitized_filename": record.get("sanitized_filename"),
            "file_size": record.get("file_size"),
            "declared_mime_type": declared_mime,
            "detected_type": record.get("detected_type"),
            "expected_type": record.get("expected_type", "unknown"),
            "extension": record.get("extension"),
            "sha256_hash": record.get("sha256_hash"),
            "final_decision": record.get("decision"),
            "risk_score": record.get("risk_score"),
            "risk_level": record.get("risk_level"),
            "summary": record.get("summary")
        },
        "checks_summary": {
            "total_checks_performed": cat["total_performed"],
            "passed_checks_count": cat["passed_count"],
            "failed_checks_count": cat["failed_count"],
            "warnings_count": cat["warnings_count"]
        },
        "checks_performed": findings,
        "passed_checks": cat["passed_checks"],
        "failed_checks": cat["failed_checks"],
        "warnings": cat["warnings"],
        "explanations": record.get("summary", ""),
        "recommended_actions": recommendations,
        "academic_disclaimer": (
            "Passing file validation does not guarantee that a file is free of malware. "
            "This tool validates file properties and configured upload policies; it is not a complete antivirus engine."
        )
    }

    return json.dumps(export_data, indent=2)
