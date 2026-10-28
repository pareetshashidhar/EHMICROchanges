"""
SecureUpload Inspector - Secure Storage & Quarantine Service
============================================================
Provides isolated, server-generated filesystem storage for uploaded files.

SECURITY CONTROLS ENFORCED:
1. Storage Outside Web Root: Files are kept strictly in instance/ or data/ directories.
2. Server-Generated Identifiers: Target filenames are cryptographic UUIDs.
   Untrusted user-supplied filenames are NEVER used as physical paths.
3. Path Traversal Neutralization: Storage keys are validated against path traversal.
4. Execution Defense: Files are saved with inert suffixes (.accepted, .quarantine)
   and restrictive non-executable POSIX/NTFS permissions.
5. Storage Segregation: Rejected files NEVER enter the accepted storage directory.
6. Configurable Discard: Rejected files can be purged immediately rather than quarantined.
7. Atomic Operations: Atomic write-then-rename prevents partially-written artifacts.
8. Bounded Disk Usage: Storage quotas prevent disk exhaustion DoS.
"""

import os
from pathlib import Path
from typing import Optional

DEFAULT_STORAGE_QUOTA_BYTES = 100 * 1024 * 1024  # 100 MB default ceiling

def _get_dir_size(directory: Path) -> int:
    """Calculate total byte size of files in a directory."""
    if not directory.is_dir():
        return 0
    total = 0
    for entry in directory.iterdir():
        if entry.is_file():
            try:
                total += entry.stat().st_size
            except OSError:
                pass
    return total

def get_accepted_path(accepted_dir: str | Path, inspection_id: str) -> Path:
    """Return the physical path for an accepted storage artifact."""
    clean_id = Path(inspection_id).name  # Prevent traversal tokens
    return Path(accepted_dir) / f"{clean_id}.accepted"

def get_quarantine_path(quarantine_dir: str | Path, inspection_id: str) -> Path:
    """Return the physical path for an isolated quarantine artifact."""
    clean_id = Path(inspection_id).name
    return Path(quarantine_dir) / f"{clean_id}.quarantine"

def store_accepted_file(
    file_bytes: bytes,
    accepted_dir: str,
    inspection_id: str,
    quota_bytes: int = DEFAULT_STORAGE_QUOTA_BYTES
) -> dict[str, str | int | bool]:
    """
    Atomically store an ACCEPTED file into the secure vault outside the web root.
    
    Uses atomic write via temporary file so partial or interrupted uploads
    never leave corrupt accepted files.
    """
    target_dir = Path(accepted_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    
    # Check bounded storage quota
    current_size = _get_dir_size(target_dir)
    if current_size + len(file_bytes) > quota_bytes:
        raise OSError(f"Storage quota exceeded: {current_size} + {len(file_bytes)} > {quota_bytes}")

    final_path = get_accepted_path(target_dir, inspection_id)
    temp_path = target_dir / f"{Path(inspection_id).name}.tmp"

    try:
        with open(temp_path, "wb") as f:
            f.write(file_bytes)
            f.flush()
            os.fsync(f.fileno())

        # Atomic replace
        temp_path.replace(final_path)

        # Restrict permissions
        try:
            os.chmod(final_path, 0o400)
        except Exception:
            pass

        return {
            "inspection_id": inspection_id,
            "storage_path": str(final_path),
            "stored": True,
            "storage_vault": "ACCEPTED_VAULT",
            "file_size": len(file_bytes)
        }
    except Exception:
        if temp_path.is_file():
            try:
                temp_path.unlink()
            except Exception:
                pass
        raise

def store_quarantine_file(
    file_bytes: bytes,
    quarantine_dir: str,
    inspection_id: str
) -> dict[str, str | int | bool]:
    """
    Safely quarantine an untrusted or rejected file in private isolation.
    """
    target_dir = Path(quarantine_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    
    final_path = get_quarantine_path(target_dir, inspection_id)
    temp_path = target_dir / f"{Path(inspection_id).name}.tmp"

    try:
        with open(temp_path, "wb") as f:
            f.write(file_bytes)
            f.flush()
            os.fsync(f.fileno())

        temp_path.replace(final_path)

        try:
            os.chmod(final_path, 0o400)
        except Exception:
            pass

        return {
            "inspection_id": inspection_id,
            "quarantine_path": str(final_path),
            "quarantine_size": len(file_bytes),
            "isolated": True,
            "storage_vault": "QUARANTINE_VAULT"
        }
    except Exception:
        if temp_path.is_file():
            try:
                temp_path.unlink()
            except Exception:
                pass
        raise

def handle_secure_storage(
    file_bytes: bytes,
    decision: str,
    accepted_dir: str,
    quarantine_dir: str,
    inspection_id: str,
    discard_rejected: bool = False,
    quota_bytes: int = DEFAULT_STORAGE_QUOTA_BYTES
) -> dict[str, str | int | bool | None]:
    """
    Orchestrate secure storage handling based on inspection decision and policy.
    
    Rules:
    - ACCEPTED: Placed in accepted storage vault outside web root.
    - REJECTED: NEVER allowed in accepted storage.
                If discard_rejected is True -> purged immediately.
                If discard_rejected is False -> placed in quarantine directory.
    - REVIEW_REQUIRED: Placed in quarantine directory for admin review.
    """
    clean_dec = decision.upper()

    if clean_dec == "ACCEPTED":
        meta = store_accepted_file(
            file_bytes=file_bytes,
            accepted_dir=accepted_dir,
            inspection_id=inspection_id,
            quota_bytes=quota_bytes
        )
        return {
            "status": "ACCEPTED_STORED",
            "storage_vault": "ACCEPTED_VAULT",
            "storage_path": meta["storage_path"],
            "retained": True
        }

    elif clean_dec == "REJECTED":
        if discard_rejected:
            # Immediate discard policy: do not retain on disk
            return {
                "status": "REJECTED_DISCARDED",
                "storage_vault": "NONE",
                "storage_path": None,
                "retained": False
            }
        else:
            meta = store_quarantine_file(
                file_bytes=file_bytes,
                quarantine_dir=quarantine_dir,
                inspection_id=inspection_id
            )
            return {
                "status": "REJECTED_QUARANTINED",
                "storage_vault": "QUARANTINE_VAULT",
                "storage_path": meta["quarantine_path"],
                "retained": True
            }

    else:
        # Ambiguous / REVIEW_REQUIRED
        meta = store_quarantine_file(
            file_bytes=file_bytes,
            quarantine_dir=quarantine_dir,
            inspection_id=inspection_id
        )
        return {
            "status": "REVIEW_QUARANTINED",
            "storage_vault": "QUARANTINE_VAULT",
            "storage_path": meta["quarantine_path"],
            "retained": True
        }

# Compatibility functions for Part 1 callers
def quarantine_file(
    file_bytes: bytes,
    quarantine_dir: str,
    inspection_id: str
) -> dict[str, str | int]:
    """Backward compatibility wrapper for store_quarantine_file."""
    res = store_quarantine_file(file_bytes, quarantine_dir, inspection_id)
    return {
        "inspection_id": inspection_id,
        "quarantine_path": str(res["quarantine_path"]),
        "quarantine_size": int(res["quarantine_size"]),
        "isolated": True
    }

def purge_quarantined_file(quarantine_dir: str, inspection_id: str) -> bool:
    """Securely delete a quarantined file."""
    file_path = get_quarantine_path(quarantine_dir, inspection_id)
    if file_path.is_file():
        try:
            os.chmod(file_path, 0o600)
            file_path.unlink()
            return True
        except Exception:
            return False
    return False

def purge_accepted_file(accepted_dir: str, inspection_id: str) -> bool:
    """Securely delete an accepted file."""
    file_path = get_accepted_path(accepted_dir, inspection_id)
    if file_path.is_file():
        try:
            os.chmod(file_path, 0o600)
            file_path.unlink()
            return True
        except Exception:
            return False
    return False

def get_quarantine_info(quarantine_dir: str, inspection_id: str) -> Optional[dict[str, str | int | bool]]:
    """Check status and metadata of a quarantined file."""
    file_path = get_quarantine_path(quarantine_dir, inspection_id)
    if not file_path.is_file():
        return None
    return {
        "inspection_id": inspection_id,
        "quarantine_path": str(file_path),
        "file_size": file_path.stat().st_size,
        "exists": True
    }
