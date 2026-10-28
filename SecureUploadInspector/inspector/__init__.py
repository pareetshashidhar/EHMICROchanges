"""
SecureUpload Inspector - Core Inspection Package
================================================
Contains modular file validation, signature analysis, MIME cross-checking,
filename hygiene, incremental hashing, risk assessment, and policy engine rules.
"""

from .file_signatures import detect_file_signature, SignatureResult
from .mime_detection import inspect_mime_agreement, MimeComparisonResult
from .filename_validation import validate_filename, FilenameValidationResult
from .hashing import compute_sha256_stream, compute_sha256_file, compare_hashes
from .risk_assessment import calculate_risk_score, RiskAssessmentResult
from .policy_engine import evaluate_file_policy, PolicyEvaluationResult, Finding

__all__ = [
    "detect_file_signature",
    "SignatureResult",
    "inspect_mime_agreement",
    "MimeComparisonResult",
    "validate_filename",
    "FilenameValidationResult",
    "compute_sha256_stream",
    "compute_sha256_file",
    "compare_hashes",
    "calculate_risk_score",
    "RiskAssessmentResult",
    "evaluate_file_policy",
    "PolicyEvaluationResult",
    "Finding",
]
