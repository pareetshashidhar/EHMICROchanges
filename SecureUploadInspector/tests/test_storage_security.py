"""
SecureUpload Inspector - Storage & Quarantine Security Tests
============================================================
Tests storage segregation, random server-side identifiers, path traversal defense,
atomic operations, and quarantine isolation.
"""

from pathlib import Path
from services.quarantine_service import (
    store_accepted_file,
    store_quarantine_file,
    handle_secure_storage,
    get_accepted_path,
    get_quarantine_path
)
from services.inspection_service import inspect_and_record_file

def test_accepted_file_stored_in_accepted_vault(tmp_path: Path):
    """Verify accepted files are placed in accepted vault outside web root."""
    accepted_dir = str(tmp_path / "accepted_vault")
    quarantine_dir = str(tmp_path / "quarantine_vault")
    payload = b"%PDF-1.4\nSample content"
    insp_id = "test-uuid-accepted-1"

    meta = handle_secure_storage(
        file_bytes=payload,
        decision="ACCEPTED",
        accepted_dir=accepted_dir,
        quarantine_dir=quarantine_dir,
        inspection_id=insp_id
    )

    assert meta["status"] == "ACCEPTED_STORED"
    assert meta["storage_vault"] == "ACCEPTED_VAULT"
    stored_path = Path(meta["storage_path"])
    assert stored_path.is_file()
    assert stored_path.parent == Path(accepted_dir)
    assert stored_path.name == f"{insp_id}.accepted"
    # Ensure nothing was written to quarantine
    assert not (Path(quarantine_dir) / f"{insp_id}.quarantine").exists()

def test_rejected_file_never_enters_accepted_storage(tmp_path: Path):
    """
    CRITICAL SECURITY INVARIANT:
    Rejected files must NEVER enter the accepted storage directory under any circumstances.
    """
    accepted_dir = str(tmp_path / "accepted_vault")
    quarantine_dir = str(tmp_path / "quarantine_vault")
    payload = b"MZ\x90\x00Disguised executable payload"
    insp_id = "test-uuid-rejected-1"

    meta = handle_secure_storage(
        file_bytes=payload,
        decision="REJECTED",
        accepted_dir=accepted_dir,
        quarantine_dir=quarantine_dir,
        inspection_id=insp_id,
        discard_rejected=False
    )

    assert meta["status"] == "REJECTED_QUARANTINED"
    assert meta["storage_vault"] == "QUARANTINE_VAULT"

    # Verify rejected file is NOT in accepted storage
    accepted_file = Path(accepted_dir) / f"{insp_id}.accepted"
    assert not accepted_file.exists()
    assert not any(Path(accepted_dir).glob("*")) if Path(accepted_dir).exists() else True

    # Verify quarantined file exists in quarantine
    quarantine_file = Path(quarantine_dir) / f"{insp_id}.quarantine"
    assert quarantine_file.is_file()

def test_discard_rejected_immediately_option(tmp_path: Path):
    """
    Verify configurable discard option: when discard_rejected is True,
    rejected files are purged and not retained on disk.
    """
    accepted_dir = str(tmp_path / "accepted_vault")
    quarantine_dir = str(tmp_path / "quarantine_vault")
    payload = b"MZ\x90\x00Malicious payload"
    insp_id = "test-uuid-discard-1"

    meta = handle_secure_storage(
        file_bytes=payload,
        decision="REJECTED",
        accepted_dir=accepted_dir,
        quarantine_dir=quarantine_dir,
        inspection_id=insp_id,
        discard_rejected=True
    )

    assert meta["status"] == "REJECTED_DISCARDED"
    assert meta["retained"] is False
    assert meta["storage_path"] is None

    # Verify neither accepted nor quarantine directories contain the file
    accepted_file = Path(accepted_dir) / f"{insp_id}.accepted"
    quarantine_file = Path(quarantine_dir) / f"{insp_id}.quarantine"
    assert not accepted_file.exists()
    assert not quarantine_file.exists()

def test_random_server_side_filename_not_user_supplied(test_app, sample_pdf_bytes):
    """Verify physical filename on disk is a UUID, never the client's supplied name."""
    user_filename = "Confidential Company Financials 2026.pdf"
    record = inspect_and_record_file(
        file_source=sample_pdf_bytes,
        original_filename=user_filename,
        config=test_app.config
    )

    assert record["decision"] == "ACCEPTED"
    storage_path = Path(record["storage_path"])
    assert storage_path.is_file()
    assert "Confidential" not in storage_path.name
    assert storage_path.name.endswith(".accepted")
    assert record["id"] in storage_path.name

def test_path_traversal_filename_cannot_escape_vault(test_app, sample_pdf_bytes):
    """Verify traversal sequences in filename do not alter the physical storage target."""
    traversal_filename = "../../../../etc/cron.d/backdoor.pdf"
    record = inspect_and_record_file(
        file_source=sample_pdf_bytes,
        original_filename=traversal_filename,
        config=test_app.config
    )

    # Path traversal violates policy -> REJECTED
    assert record["decision"] == "REJECTED"
    # Never stored in accepted storage
    accepted_dir = Path(test_app.config["ACCEPTED_STORAGE_DIR"])
    assert not any(accepted_dir.glob("*.accepted"))

def test_atomic_file_write_leaves_no_tmp_on_failure(tmp_path: Path):
    """Verify atomic write cleans up temporary files on simulated failure."""
    accepted_dir = str(tmp_path / "accepted_vault")
    # Setting an impossible quota of 5 bytes to force OSError
    payload = b"Longer than five bytes of content"
    insp_id = "test-uuid-quota-fail"

    try:
        store_accepted_file(payload, accepted_dir, insp_id, quota_bytes=5)
    except OSError:
        pass

    # Ensure no .tmp or .accepted file remains
    assert not (Path(accepted_dir) / f"{insp_id}.tmp").exists()
    assert not (Path(accepted_dir) / f"{insp_id}.accepted").exists()
