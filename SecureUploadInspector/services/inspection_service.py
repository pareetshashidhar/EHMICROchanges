"""
SecureUpload Inspector - Orchestration Inspection Service
=========================================================
Coordinates end-to-end file inspection workflow:
1. Input validation & boundary enforcement.
2. Filename validation & path traversal defense.
3. Bounded magic bytes signature detection.
4. MIME cross-checking and concordance verification.
5. Upload policy evaluation.
6. Memory-bounded incremental SHA-256 calculation.
7. Deterministic decision generation (ACCEPTED, REJECTED, REVIEW_REQUIRED).
8. Segregated secure storage handling (Accepted vault vs Quarantine vault vs Discard).
9. SQLite persistence with parameterized queries.
10. Report generation data preparation.

ACADEMIC SECURITY DISCLAIMER:
Validation confirms adherence to structural file specifications and policy constraints.
It DOES NOT establish that an accepted file is free of embedded zero-day malware.
"""

import uuid
from datetime import datetime, timezone
from typing import BinaryIO, Optional, Union, Any

from config import Config
from inspector.hashing import compute_sha256_bytes
from inspector.policy_engine import evaluate_file_policy, PolicyEvaluationResult
from storage.database import save_inspection, get_setting
from storage.audit_log import log_audit_event
from .quarantine_service import handle_secure_storage

def _cfg(cfg_obj: Any, key: str, default: Any = None) -> Any:
    """Helper to retrieve configuration value from either dict or object."""
    if hasattr(cfg_obj, "get"):
        val = cfg_obj.get(key)
        if val is not None:
            return val
    return getattr(cfg_obj, key, default)

def inspect_and_record_file(
    file_source: Union[bytes, BinaryIO],
    original_filename: str,
    browser_mime: Optional[str] = None,
    client_ip: str = "127.0.0.1",
    config: Optional[Union[Config, Any]] = None,
    discard_rejected_override: Optional[bool] = None,
    allowed_extensions_override: Optional[set[str]] = None
) -> dict[str, Any]:
    """
    Execute full multi-vector inspection lifecycle on a submitted file.
    """
    app_config = config if config is not None else Config()
    inspection_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()

    # 1. Input Validation: Extract raw bytes safely
    if isinstance(file_source, bytes):
        file_bytes = file_source
    elif hasattr(file_source, "read"):
        file_bytes = file_source.read()
    else:
        raise TypeError("file_source must be raw bytes or a readable binary stream")

    # 2. Check dynamic settings from database if available
    db_path = _cfg(app_config, "DATABASE_PATH", "instance/secureupload.db")
    discard_rejected = (
        discard_rejected_override if discard_rejected_override is not None
        else get_setting(db_path, "discard_rejected", _cfg(app_config, "DISCARD_REJECTED", False))
    )
    if isinstance(discard_rejected, str):
        discard_rejected = discard_rejected.lower() in ("true", "1")

    # Allowed extensions (from override, or db setting, or config)
    if allowed_extensions_override:
        effective_allowed = allowed_extensions_override
    else:
        db_exts = get_setting(db_path, "allowed_extensions", None)
        if db_exts and isinstance(db_exts, list):
            effective_allowed = set(db_exts)
        else:
            effective_allowed = _cfg(app_config, "ALLOWED_EXTENSIONS", Config.ALLOWED_EXTENSIONS)

    # Max file size setting
    db_max_size_mb = get_setting(db_path, "max_file_size_mb", None)
    effective_max_size = (
        int(db_max_size_mb) * 1024 * 1024 if db_max_size_mb
        else _cfg(app_config, "MAX_FILE_SIZE", Config.MAX_FILE_SIZE)
    )

    # 3. Compute incremental SHA-256 digest
    sha256_hash = compute_sha256_bytes(file_bytes)

    # 4. Evaluate Upload Policies (Filename, Signatures, MIME, Decision)
    policy_result: PolicyEvaluationResult = evaluate_file_policy(
        file_bytes=file_bytes,
        filename=original_filename,
        browser_mime=browser_mime,
        allowed_extensions=effective_allowed,
        max_file_size=effective_max_size,
        max_filename_length=_cfg(app_config, "MAX_FILENAME_LENGTH", Config.MAX_FILENAME_LENGTH),
        reject_zero_byte=_cfg(app_config, "REJECT_ZERO_BYTE_FILES", Config.REJECT_ZERO_BYTE_FILES),
        enforce_extension_signature_match=_cfg(app_config, "ENFORCE_EXTENSION_SIGNATURE_MATCH", Config.ENFORCE_EXTENSION_SIGNATURE_MATCH),
    )

    # 5. Safe Storage Handling
    # Segregate: Accepted goes to accepted vault; Rejected never enters accepted vault
    storage_meta = handle_secure_storage(
        file_bytes=file_bytes,
        decision=policy_result.decision,
        accepted_dir=_cfg(app_config, "ACCEPTED_STORAGE_DIR", "instance/accepted_uploads"),
        quarantine_dir=_cfg(app_config, "QUARANTINE_DIR", "instance/quarantine"),
        inspection_id=inspection_id,
        discard_rejected=discard_rejected,
        quota_bytes=_cfg(app_config, "MAX_STORAGE_QUOTA_BYTES", 100 * 1024 * 1024)
    )

    findings_list = [f.to_dict() for f in policy_result.findings]

    # 6. Construct structured record
    sanitized_name = policy_result.filename_result.cleaned_basename or "unknown_file"
    declared_mime = browser_mime or ""

    record = {
        "id": inspection_id,
        "created_at": now_iso,
        "timestamp": now_iso,
        "original_filename": original_filename,
        "sanitized_filename": sanitized_name,
        "file_size": policy_result.file_size,
        "sha256_hash": sha256_hash,
        "detected_type": policy_result.signature_result.detected_type,
        "expected_type": policy_result.mime_result.expected_type or "unknown",
        "declared_mime_type": declared_mime,
        "browser_mime": declared_mime,
        "extension": policy_result.filename_result.extension,
        "decision": policy_result.decision,
        "risk_score": policy_result.risk_assessment.score,
        "risk_level": policy_result.risk_assessment.level,
        "findings_json": findings_list,
        "summary": policy_result.summary,
        "storage_path": storage_meta.get("storage_path") or "",
        "storage_status": storage_meta.get("status"),
        "client_ip": client_ip,
    }

    # 7. Persist to SQLite database
    save_inspection(db_path, record)

    # 8. Record Security Audit Event
    audit_severity = (
        "CRITICAL" if policy_result.decision == "REJECTED" and policy_result.risk_assessment.score >= 50
        else "HIGH" if policy_result.decision == "REJECTED"
        else "MEDIUM" if policy_result.decision == "REVIEW_REQUIRED"
        else "INFO"
    )

    log_audit_event(
        db_path=db_path,
        event_type=f"INSPECTION_{policy_result.decision}",
        severity=audit_severity,
        details={
            "original_filename": original_filename,
            "decision": policy_result.decision,
            "risk_score": policy_result.risk_assessment.score,
            "sha256": sha256_hash,
            "file_size": len(file_bytes),
            "storage_status": storage_meta.get("status"),
            "client_ip": client_ip
        },
        inspection_id=inspection_id,
        log_file_path=_cfg(app_config, "AUDIT_LOG_PATH", "instance/audit.log")
    )

    # Attach in-memory evaluation objects for caller convenience
    record["findings"] = findings_list
    record["risk_assessment"] = policy_result.risk_assessment.to_dict()
    record["signature_result"] = policy_result.signature_result.to_dict()
    record["mime_result"] = policy_result.mime_result.to_dict()
    record["storage"] = storage_meta

    return record
