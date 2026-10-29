"""
SecureUpload Inspector - Upload Policy Engine
=============================================
Evaluates files against configurable security rules and renders deterministic verdicts:
ACCEPTED, REJECTED, or REVIEW_REQUIRED.

MANDATORY REJECTION RULES:
- Prohibited extensions (POL-EXT-001)
- Zero-byte files (POL-SIZE-001)
- Maximum file size violations (POL-SIZE-002)
- Path traversal attempts in filenames (POL-NAME-001)
- Suspicious executable double extensions (POL-NAME-003)
- Confirmed extension/signature mismatches (POL-AGREE-001)
- Detected executable/dangerous binary magic bytes (POL-SIG-001)

SECURITY NOTICE:
An ACCEPTED verdict indicates adherence to format rules and policy constraints.
It DOES NOT establish that the file is safe or free of embedded malware exploits.
"""

from dataclasses import dataclass, asdict, field
from typing import Optional, Sequence
from pathlib import Path

from .file_signatures import detect_file_signature, SignatureResult
from .filename_validation import validate_filename, FilenameValidationResult
from .mime_detection import inspect_mime_agreement, MimeComparisonResult
from .risk_assessment import calculate_risk_score, RiskAssessmentResult

# Default Policy Limits
DEFAULT_ALLOWED_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".txt"}
DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
DEFAULT_MAX_FILENAME_LENGTH = 255

DECISION_ACCEPTED = "ACCEPTED"
DECISION_REJECTED = "REJECTED"
DECISION_REVIEW_REQUIRED = "REVIEW_REQUIRED"

@dataclass
class Finding:
    """Structured security finding for an individual policy rule."""
    rule_id: str
    title: str
    severity: str        # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'
    status: str          # 'PASS', 'FAIL', 'WARN'
    evidence: str
    explanation: str
    recommendation: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PolicyEvaluationResult:
    """Consolidated policy evaluation output."""
    decision: str        # 'ACCEPTED', 'REJECTED', 'REVIEW_REQUIRED'
    decision_reason: str
    findings: list[Finding]
    risk_assessment: RiskAssessmentResult
    filename_result: FilenameValidationResult
    signature_result: SignatureResult
    mime_result: MimeComparisonResult
    file_size: int
    allowed_by_policy: bool
    summary: str

    def to_dict(self) -> dict:
        return {
            "decision": self.decision,
            "decision_reason": self.decision_reason,
            "findings": [f.to_dict() for f in self.findings],
            "risk_assessment": self.risk_assessment.to_dict(),
            "filename_result": self.filename_result.to_dict(),
            "signature_result": self.signature_result.to_dict(),
            "mime_result": self.mime_result.to_dict(),
            "file_size": self.file_size,
            "allowed_by_policy": self.allowed_by_policy,
            "summary": self.summary,
        }


def rule_check_file_size(
    file_size: int,
    max_size: int = DEFAULT_MAX_FILE_SIZE,
    reject_zero_byte: bool = True
) -> list[Finding]:
    """Inspect file size against lower and upper policy boundaries."""
    findings: list[Finding] = []

    # Check zero-byte policy
    if file_size == 0:
        if reject_zero_byte:
            findings.append(Finding(
                rule_id="POL-SIZE-001",
                title="Zero-Byte File Rejection",
                severity="CRITICAL",
                status="FAIL",
                evidence="File size is 0 bytes.",
                explanation="Zero-byte files contain no readable data, headers, or verifiable structure.",
                recommendation="Reject empty file upload. Legitimate documents must contain content."
            ))
        else:
            findings.append(Finding(
                rule_id="POL-SIZE-001",
                title="Zero-Byte File Warning",
                severity="HIGH",
                status="WARN",
                evidence="File size is 0 bytes.",
                explanation="File is empty. Uploaded without payload.",
                recommendation="Verify why an empty file was submitted."
            ))
    else:
        findings.append(Finding(
            rule_id="POL-SIZE-001",
            title="Non-Zero File Size Verification",
            severity="INFO",
            status="PASS",
            evidence=f"File size is {file_size} bytes (> 0 bytes).",
            explanation="File contains non-zero data payload.",
            recommendation="Proceed with content inspection."
        ))

    # Check maximum file size boundary
    if file_size > max_size:
        findings.append(Finding(
            rule_id="POL-SIZE-002",
            title="Maximum File Size Limit Exceeded",
            severity="CRITICAL",
            status="FAIL",
            evidence=f"File size {file_size} bytes exceeds configured limit of {max_size} bytes.",
            explanation="Unbounded file sizes risk Denial of Service (DoS) and resource exhaustion.",
            recommendation=f"Reject upload. Ensure files remain within the {max_size // (1024*1024)} MB threshold."
        ))
    else:
        findings.append(Finding(
            rule_id="POL-SIZE-002",
            title="File Size Boundary Verification",
            severity="INFO",
            status="PASS",
            evidence=f"File size {file_size} bytes is within allowed limit ({max_size} bytes).",
            explanation="File satisfies resource quota limits.",
            recommendation="No action required."
        ))

    return findings


def rule_check_filename(
    fn_result: FilenameValidationResult,
    max_len: int = DEFAULT_MAX_FILENAME_LENGTH
) -> list[Finding]:
    """Inspect filename integrity, path traversal, length, and double extensions."""
    findings: list[Finding] = []

    # Path traversal check
    if fn_result.is_path_traversal:
        findings.append(Finding(
            rule_id="POL-NAME-001",
            title="Path Traversal Sequence Detected",
            severity="CRITICAL",
            status="FAIL",
            evidence=f"Filename '{fn_result.original_filename}' contains path separators or traversal characters (..).",
            explanation="Path traversal attempts can overwrite arbitrary server files or bypass directory sandboxes.",
            recommendation="Reject request immediately. Never normalize path traversal filenames into accepted uploads."
        ))
    elif not fn_result.original_filename:
        findings.append(Finding(
            rule_id="POL-NAME-001",
            title="Empty Filename Provided",
            severity="CRITICAL",
            status="FAIL",
            evidence="Filename string is empty or absent.",
            explanation="Upload request lacked a valid filename identifier.",
            recommendation="Reject request. Filename parameter is required."
        ))
    else:
        findings.append(Finding(
            rule_id="POL-NAME-001",
            title="Filename Path Traversal Check",
            severity="INFO",
            status="PASS",
            evidence=f"Filename '{fn_result.original_filename}' contains no directory traversal sequences.",
            explanation="Filename adheres to leaf file identifier requirements.",
            recommendation="No action required."
        ))

    # Length check
    if len(fn_result.original_filename) > max_len:
        findings.append(Finding(
            rule_id="POL-NAME-002",
            title="Filename Length Exceeds Safety Threshold",
            severity="HIGH",
            status="FAIL",
            evidence=f"Filename length {len(fn_result.original_filename)} > maximum permitted {max_len}.",
            explanation="Excessively long filenames can cause buffer overflows or filesystem storage errors.",
            recommendation=f"Reject filename or truncate to <= {max_len} characters."
        ))
    else:
        findings.append(Finding(
            rule_id="POL-NAME-002",
            title="Filename Length Verification",
            severity="INFO",
            status="PASS",
            evidence=f"Filename length ({len(fn_result.original_filename)}) is within allowed limits.",
            explanation="Length is safe for all target operating systems.",
            recommendation="No action required."
        ))

    # Double extension check
    if fn_result.is_double_extension:
        if fn_result.double_extension_risk == "SUSPICIOUS_EXECUTABLE":
            findings.append(Finding(
                rule_id="POL-NAME-003",
                title="Suspicious Executable Double Extension",
                severity="CRITICAL",
                status="FAIL",
                evidence=f"Filename '{fn_result.original_filename}' contains disguised executable/script extension.",
                explanation="Attackers use double extensions (e.g., .pdf.exe) to trick users or web server handlers into executing malicious payloads.",
                recommendation="Reject file immediately. Strip or block dual-extension payloads."
            ))
        else:
            findings.append(Finding(
                rule_id="POL-NAME-003",
                title="Compound Extension Noted",
                severity="LOW",
                status="WARN",
                evidence=f"Filename '{fn_result.original_filename}' has multiple dots with non-executable segments.",
                explanation="Filename uses compound naming (e.g., report.2026.pdf). Permitted under heightened review.",
                recommendation="Verify filename context with submitting client."
            ))
    else:
        findings.append(Finding(
            rule_id="POL-NAME-003",
            title="Double Extension Check",
            severity="INFO",
            status="PASS",
            evidence="Single file extension detected without compound obfuscation.",
            explanation="No dual extension tricks detected.",
            recommendation="No action required."
        ))

    return findings


def rule_check_extension_allowlist(
    extension: str,
    allowed_extensions: set[str] = DEFAULT_ALLOWED_EXTENSIONS
) -> list[Finding]:
    """Inspect extension against permitted policy allowlist."""
    findings: list[Finding] = []
    norm_ext = extension.lower()

    if not norm_ext:
        findings.append(Finding(
            rule_id="POL-EXT-001",
            title="Missing File Extension",
            severity="CRITICAL",
            status="FAIL",
            evidence="File has no extension.",
            explanation="Policy mandates explicit, verified file extensions for all uploaded items.",
            recommendation="Reject file. Require client to specify a valid extension."
        ))
    elif norm_ext not in allowed_extensions:
        findings.append(Finding(
            rule_id="POL-EXT-001",
            title="Disallowed File Extension",
            severity="CRITICAL",
            status="FAIL",
            evidence=f"Extension '{norm_ext}' is not in allowed extensions list: {sorted(list(allowed_extensions))}.",
            explanation="Strict allowlist enforcement prevents uploading dangerous or unexpected file formats.",
            recommendation=f"Reject upload. Permitted extensions are: {', '.join(sorted(list(allowed_extensions)))}."
        ))
    else:
        findings.append(Finding(
            rule_id="POL-EXT-001",
            title="Extension Allowlist Compliance",
            severity="INFO",
            status="PASS",
            evidence=f"Extension '{norm_ext}' is permitted by security policy.",
            explanation="Extension matches approved organization allowlist.",
            recommendation="Proceed with signature concordance check."
        ))

    return findings


def rule_check_signature_and_agreement(
    sig_result: SignatureResult,
    mime_result: MimeComparisonResult,
    extension: str,
    strict_match: bool = True
) -> list[Finding]:
    """Evaluate file magic bytes, MIME headers, and cross-vector concordance."""
    findings: list[Finding] = []
    norm_ext = extension.lower()

    # 1. Signature validity check
    if not sig_result.signature_valid:
        severity = "CRITICAL" if sig_result.detected_type != "empty" else "CRITICAL"
        findings.append(Finding(
            rule_id="POL-SIG-001",
            title="File Signature Verification Failure",
            severity=severity,
            status="FAIL",
            evidence=f"Detected signature: '{sig_result.detected_type}', method: '{sig_result.detection_method}'.",
            explanation=sig_result.explanation,
            recommendation="Reject file. Header does not conform to genuine file format specifications."
        ))
    else:
        # Check if text was cautious
        status = "WARN" if sig_result.detected_type == "probable_text" and sig_result.certainty != "high" else "PASS"
        severity = "LOW" if status == "WARN" else "INFO"
        findings.append(Finding(
            rule_id="POL-SIG-001",
            title="File Signature Verified",
            severity=severity,
            status=status,
            evidence=f"Detected type '{sig_result.detected_type}' via '{sig_result.detection_method}' with {sig_result.certainty} certainty.",
            explanation=sig_result.explanation,
            recommendation="Proceed to verify extension concordance."
        ))

    # 2. Extension vs Signature Concordance Check
    if not mime_result.agreement:
        findings.append(Finding(
            rule_id="POL-AGREE-001",
            title="Extension and Signature Mismatch",
            severity="CRITICAL",
            status="FAIL",
            evidence=f"Extension '{norm_ext}' conflicts with detected signature '{sig_result.detected_type}'.",
            explanation=mime_result.explanation,
            recommendation="Reject file. Mismatched signatures indicate potential extension spoofing or disguised malware."
        ))
    else:
        findings.append(Finding(
            rule_id="POL-AGREE-001",
            title="Extension and Signature Concordance",
            severity="INFO",
            status="PASS",
            evidence=f"Extension '{norm_ext}' and detected signature '{sig_result.detected_type}' agree.",
            explanation="Header magic bytes match the file format indicated by the extension.",
            recommendation="No action required."
        ))

    # 3. Client MIME Divergence Check (Browser supplied Content-Type)
    if mime_result.discrepancies:
        # Check if browser mime caused a discrepancy
        browser_discrepancies = [d for d in mime_result.discrepancies if "Browser MIME" in d or "divergence" in d]
        if browser_discrepancies:
            findings.append(Finding(
                rule_id="POL-MIME-001",
                title="Client Browser MIME Header Inconsistency",
                severity="MEDIUM",
                status="WARN",
                evidence="; ".join(browser_discrepancies),
                explanation="Browser-supplied MIME header does not match standard canonical type. Browser MIME cannot be trusted alone.",
                recommendation="Flag for administrative review if other indicators warrant caution."
            ))

    return findings


def evaluate_file_policy(
    file_bytes: bytes,
    filename: str,
    browser_mime: Optional[str] = None,
    allowed_extensions: Optional[set[str]] = None,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_filename_length: int = DEFAULT_MAX_FILENAME_LENGTH,
    reject_zero_byte: bool = True,
    enforce_extension_signature_match: bool = True
) -> PolicyEvaluationResult:
    """
    Execute comprehensive multi-stage policy evaluation on an uploaded file.
    
    Stages:
    1. Size and boundary analysis.
    2. Filename validation (traversal, length, characters, double extensions).
    3. Extension allowlist auditing.
    4. Bounded magic byte signature inspection.
    5. MIME cross-validation and agreement testing.
    6. Heuristic risk calculation.
    7. Final deterministic decision synthesis (ACCEPTED, REJECTED, REVIEW_REQUIRED).
    
    Args:
        file_bytes: Raw file content
        filename: Untrusted client-supplied filename
        browser_mime: Client declared HTTP Content-Type
        allowed_extensions: Allowed extensions set (e.g. {'.pdf', '.png', ...})
        max_file_size: Maximum allowed size in bytes
        max_filename_length: Maximum allowed filename length
        reject_zero_byte: Whether to reject 0-byte files
        enforce_extension_signature_match: Whether to require strict signature match
        
    Returns:
        PolicyEvaluationResult containing full audit trail and final decision.
    """
    effective_allowed = allowed_extensions or DEFAULT_ALLOWED_EXTENSIONS
    file_size = len(file_bytes)

    # Execute underlying analyzers
    fn_result = validate_filename(
        filename=filename,
        max_length=max_filename_length,
        allowed_extensions=effective_allowed
    )
    sig_result = detect_file_signature(file_bytes)
    mime_result = inspect_mime_agreement(
        filename=fn_result.cleaned_basename,
        browser_mime=browser_mime,
        signature_result=sig_result
    )

    all_findings: list[Finding] = []

    # Run independent rules
    all_findings.extend(rule_check_file_size(file_size, max_file_size, reject_zero_byte))
    all_findings.extend(rule_check_filename(fn_result, max_filename_length))
    all_findings.extend(rule_check_extension_allowlist(fn_result.extension, effective_allowed))
    all_findings.extend(rule_check_signature_and_agreement(
        sig_result,
        mime_result,
        fn_result.extension,
        strict_match=enforce_extension_signature_match
    ))

    # Calculate heuristic risk score
    risk_assessment = calculate_risk_score([f.to_dict() for f in all_findings])

    # Determine Decision:
    # Mandatory Rejection Conditions:
    # 1. Any CRITICAL or HIGH finding with status == FAIL
    # 2. Path traversal
    # 3. Disallowed extension
    # 4. Zero byte (if reject_zero_byte)
    # 5. Over max size
    # 6. Signature mismatch
    # 7. Disguised executable signature or executable double extension
    has_mandatory_rejection = any(
        f.status == "FAIL" and f.severity in {"CRITICAL", "HIGH"}
        for f in all_findings
    )
    
    has_warnings = any(f.status == "WARN" for f in all_findings)

    if has_mandatory_rejection:
        decision = DECISION_REJECTED
        critical_reasons = [
            f.title for f in all_findings
            if f.status == "FAIL" and f.severity in {"CRITICAL", "HIGH"}
        ]
        decision_reason = f"File rejected due to mandatory security policy violations: {', '.join(critical_reasons[:3])}."
        allowed_by_policy = False
    elif has_warnings or sig_result.certainty in {"medium", "low"} or risk_assessment.score >= 20:
        # Ambiguous files or notable warnings require administrative review
        decision = DECISION_REVIEW_REQUIRED
        warn_reasons = [f.title for f in all_findings if f.status == "WARN"]
        reason_text = ", ".join(warn_reasons) if warn_reasons else "Elevated heuristic risk score"
        decision_reason = f"File requires manual review: {reason_text}."
        allowed_by_policy = False
    else:
        decision = DECISION_ACCEPTED
        decision_reason = (
            "File passed all mandatory security rules, extension allowlists, "
            "and signature concordance checks."
        )
        allowed_by_policy = True

    summary = (
        f"Validation verdict: {decision}. Risk score: {risk_assessment.score}/100 ({risk_assessment.level}). "
        f"{decision_reason} (Note: Verification does not guarantee absence of malware)."
    )

    return PolicyEvaluationResult(
        decision=decision,
        decision_reason=decision_reason,
        findings=all_findings,
        risk_assessment=risk_assessment,
        filename_result=fn_result,
        signature_result=sig_result,
        mime_result=mime_result,
        file_size=file_size,
        allowed_by_policy=allowed_by_policy,
        summary=summary
    )
