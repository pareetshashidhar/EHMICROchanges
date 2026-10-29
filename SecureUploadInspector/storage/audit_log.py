"""
SecureUpload Inspector - Security Audit Logging Module
======================================================
Maintains structured event records in both SQLite and flat log files
for forensic traceability and compliance auditing.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .database import get_db_connection

def log_audit_event(
    db_path: str,
    event_type: str,
    severity: str,
    details: dict[str, Any],
    inspection_id: Optional[str] = None,
    log_file_path: Optional[str] = None
) -> None:
    """
    Record a security audit event in SQLite and optional flat log file.
    
    Args:
        db_path: SQLite database path
        event_type: e.g. 'UPLOAD_ATTEMPT', 'POLICY_REJECTION', 'TRAVERSAL_DETECTED'
        severity: 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
        details: Arbitrary contextual event attributes
        inspection_id: Associated inspection UUID if applicable
        log_file_path: Optional path to append-only text log file
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    details_str = json.dumps(details)

    # 1. Insert into SQLite audit table
    try:
        with get_db_connection(db_path) as conn:
            conn.execute(
                """
                INSERT INTO audit_events (timestamp, event_type, inspection_id, severity, details_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (now_iso, event_type, inspection_id, severity.upper(), details_str)
            )
            conn.commit()
    except Exception as e:
        # Fallback print if db is temporarily locked
        print(f"[AUDIT LOG ERROR] Database log write failed: {e}")

    # 2. Append to flat log file if specified
    if log_file_path:
        try:
            log_path = Path(log_file_path)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_line = f"[{now_iso}] [{severity.upper()}] [{event_type}] [id={inspection_id or 'none'}] {details_str}\n"
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(log_line)
        except Exception as e:
            print(f"[AUDIT LOG ERROR] Flat file append failed: {e}")

def get_recent_audit_events(db_path: str, limit: int = 50) -> list[dict[str, Any]]:
    """Retrieve the most recent audit events."""
    sql = "SELECT * FROM audit_events ORDER BY id DESC LIMIT ?"
    with get_db_connection(db_path) as conn:
        rows = conn.execute(sql, (limit,)).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            try:
                d["details"] = json.loads(d.get("details_json", "{}"))
            except (json.JSONDecodeError, TypeError):
                d["details"] = {}
            result.append(d)
        return result
