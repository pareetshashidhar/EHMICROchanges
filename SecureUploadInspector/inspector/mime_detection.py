"""
SecureUpload Inspector - MIME and Type Agreement Inspection Module
===================================================================
Cross-checks filename extensions, client-supplied MIME headers,
server-side mimetypes detection, and raw byte signature findings.

CRITICAL SECURITY RULE:
Client-declared MIME types (sent via HTTP Content-Type headers) can be trivially
forged or manipulated by an attacker. The browser-supplied MIME type must NEVER
be trusted alone. Cross-verification against detected magic bytes is mandatory.
"""

from dataclasses import dataclass, asdict
import mimetypes
from pathlib import Path
from typing import Optional

from .file_signatures import SignatureResult

# Initialize standard Python mimetypes mapping
mimetypes.init()

EXTENSION_EXPECTATIONS: dict[str, dict] = {
    ".pdf": {
        "expected_type": "pdf",
        "valid_signatures": {"pdf"},
        "canonical_mimes": {"application/pdf"},
        "acceptable_browser_mimes": {"application/pdf", "application/x-pdf"}
    },
    ".png": {
        "expected_type": "png",
        "valid_signatures": {"png"},
        "canonical_mimes": {"image/png"},
        "acceptable_browser_mimes": {"image/png", "application/png"}
    },
    ".jpg": {
        "expected_type": "jpeg",
        "valid_signatures": {"jpeg"},
        "canonical_mimes": {"image/jpeg"},
        "acceptable_browser_mimes": {"image/jpeg", "image/pjpeg"}
    },
    ".jpeg": {
        "expected_type": "jpeg",
        "valid_signatures": {"jpeg"},
        "canonical_mimes": {"image/jpeg"},
        "acceptable_browser_mimes": {"image/jpeg", "image/pjpeg"}
    },
    ".txt": {
        "expected_type": "text",
        "valid_signatures": {"probable_text"},
        "canonical_mimes": {"text/plain"},
        "acceptable_browser_mimes": {"text/plain", "text/x-plain", "application/octet-stream"}
    }
}

@dataclass
class MimeComparisonResult:
    """Structured assessment of MIME and file format agreement."""
    extension: str
    expected_type: str
    browser_mime: str
    server_guess_mime: str
    signature_type: str
    agreement: bool
    explanation: str
    discrepancies: list[str]
    risk_indication: str  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'

    def to_dict(self) -> dict:
        return asdict(self)


def inspect_mime_agreement(
    filename: str,
    browser_mime: Optional[str],
    signature_result: SignatureResult
) -> MimeComparisonResult:
    """
    Perform rigorous multi-vector comparison between extension, client MIME,
    server-guessed MIME, and actual detected file signature.
    
    Args:
        filename: Target filename including extension
        browser_mime: Content-Type declared by the HTTP client
        signature_result: Output from detect_file_signature()
        
    Returns:
        MimeComparisonResult detailing agreement status and any discrepancies.
    """
    ext = Path(filename).suffix.lower() if filename else ""
    client_mime_normalized = (browser_mime or "").strip().lower()
    
    # Server-side MIME guess from filename using Python standard library
    server_guess_mime, _ = mimetypes.guess_type(filename or "")
    server_guess_normalized = (server_guess_mime or "application/octet-stream").lower()

    expectation = EXTENSION_EXPECTATIONS.get(ext)
    discrepancies: list[str] = []
    
    if not expectation:
        discrepancies.append(f"Extension '{ext}' is unmapped or not in approved policy.")
        expected_type = "unsupported"
        risk = "HIGH"
        agreement = False
        explanation = (
            f"Extension '{ext or '(none)'}' is not supported. "
            f"Detected signature: '{signature_result.detected_type}'."
        )
        return MimeComparisonResult(
            extension=ext,
            expected_type=expected_type,
            browser_mime=client_mime_normalized,
            server_guess_mime=server_guess_normalized,
            signature_type=signature_result.detected_type,
            agreement=agreement,
            explanation=explanation,
            discrepancies=discrepancies,
            risk_indication=risk
        )

    expected_type = expectation["expected_type"]
    valid_signatures = expectation["valid_signatures"]
    acceptable_browser_mimes = expectation["acceptable_browser_mimes"]

    # 1. Check Signature vs Extension (Highest critical factor)
    signature_matches = signature_result.detected_type in valid_signatures
    if not signature_matches:
        discrepancies.append(
            f"Signature mismatch: Extension indicates '{expected_type}', "
            f"but byte header detected '{signature_result.detected_type}'."
        )

    # 2. Check Browser MIME vs Expected
    browser_matches = client_mime_normalized in acceptable_browser_mimes if client_mime_normalized else True
    if client_mime_normalized and not browser_matches:
        discrepancies.append(
            f"Browser MIME mismatch: Client declared '{client_mime_normalized}', "
            f"which does not match acceptable MIME types for '{ext}'."
        )

    # 3. Check Server Guess vs Browser MIME
    if client_mime_normalized and server_guess_normalized:
        if client_mime_normalized != server_guess_normalized and client_mime_normalized != "application/octet-stream":
            discrepancies.append(
                f"Client and server MIME divergence: Client declared '{client_mime_normalized}', "
                f"while server deduced '{server_guess_normalized}'."
            )

    # Determine agreement and risk indication
    if not signature_matches:
        agreement = False
        risk = "CRITICAL"
        explanation = (
            f"CRITICAL DISCREPANCY: Extension '{ext}' claimed type '{expected_type}', "
            f"but file header inspection found '{signature_result.detected_type}'. "
            f"This often indicates file extension spoofing or an executable disguised as a document."
        )
    elif discrepancies:
        agreement = False
        risk = "MEDIUM"
        explanation = (
            f"Signature matches '{expected_type}', but metadata inconsistencies were identified: "
            + "; ".join(discrepancies)
        )
    else:
        agreement = True
        risk = "LOW"
        explanation = (
            f"Complete agreement verified: Extension '{ext}', server MIME '{server_guess_normalized}', "
            f"and detected magic bytes '{signature_result.detected_type}' are concordant."
        )

    return MimeComparisonResult(
        extension=ext,
        expected_type=expected_type,
        browser_mime=client_mime_normalized,
        server_guess_mime=server_guess_normalized,
        signature_type=signature_result.detected_type,
        agreement=agreement,
        explanation=explanation,
        discrepancies=discrepancies,
        risk_indication=risk
    )
