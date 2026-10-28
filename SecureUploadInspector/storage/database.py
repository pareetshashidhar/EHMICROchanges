"""
SecureUpload Inspector - SQLite Database Management
===================================================
Provides robust, parameterized persistence for inspection records,
audit findings, settings, and real-time operational metrics.
"""

import json
import sqlite3
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS inspections (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    sanitized_filename TEXT NOT NULL,
    detected_type TEXT NOT NULL,
    declared_mime_type TEXT,
    browser_mime TEXT,
    file_size INTEGER NOT NULL,
    sha256_hash TEXT NOT NULL,
    extension TEXT NOT NULL,
    decision TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    findings_json TEXT NOT NULL,
    summary TEXT NOT NULL,
    storage_path TEXT,
    client_ip TEXT
);

CREATE INDEX IF NOT EXISTS idx_inspections_created_at ON inspections(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_inspections_timestamp ON inspections(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_inspections_decision ON inspections(decision);
CREATE INDEX IF NOT EXISTS idx_inspections_detected_type ON inspections(detected_type);
CREATE INDEX IF NOT EXISTS idx_inspections_sha256 ON inspections(sha256_hash);

CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    inspection_id TEXT,
    severity TEXT NOT NULL,
    details_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp DESC);
"""

def get_db_connection(db_path: str) -> sqlite3.Connection:
    """Create a configured SQLite connection with row factories."""
    if db_path != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    if db_path != ":memory:":
        conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db(db_path: str) -> None:
    """Initialize database tables, indexes, and default settings."""
    with get_db_connection(db_path) as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS inspections (
            id TEXT PRIMARY KEY,
            created_at TEXT DEFAULT '',
            timestamp TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            sanitized_filename TEXT NOT NULL,
            detected_type TEXT NOT NULL,
            declared_mime_type TEXT DEFAULT '',
            browser_mime TEXT,
            file_size INTEGER NOT NULL,
            sha256_hash TEXT NOT NULL,
            extension TEXT NOT NULL,
            decision TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            findings_json TEXT NOT NULL,
            summary TEXT NOT NULL,
            storage_path TEXT DEFAULT '',
            client_ip TEXT
        );
        """)

        # Migration: Ensure created_at, declared_mime_type, and storage_path exist if table was created earlier
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(inspections);").fetchall()]
        if "created_at" not in cols:
            conn.execute("ALTER TABLE inspections ADD COLUMN created_at TEXT DEFAULT '';")
            conn.execute("UPDATE inspections SET created_at = timestamp WHERE created_at = '';")
        if "declared_mime_type" not in cols:
            conn.execute("ALTER TABLE inspections ADD COLUMN declared_mime_type TEXT DEFAULT '';")
            conn.execute("UPDATE inspections SET declared_mime_type = browser_mime WHERE declared_mime_type = '';")
        if "storage_path" not in cols:
            conn.execute("ALTER TABLE inspections ADD COLUMN storage_path TEXT DEFAULT '';")

        conn.execute("""
        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """)

        conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            inspection_id TEXT,
            severity TEXT NOT NULL,
            details_json TEXT NOT NULL
        );
        """)

        # Create indexes after columns are guaranteed to exist
        conn.execute("CREATE INDEX IF NOT EXISTS idx_inspections_created_at ON inspections(created_at DESC);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_inspections_timestamp ON inspections(timestamp DESC);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_inspections_decision ON inspections(decision);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_inspections_detected_type ON inspections(detected_type);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_inspections_sha256 ON inspections(sha256_hash);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp DESC);")

        conn.commit()
    init_default_settings(db_path)

def init_default_settings(db_path: str) -> None:
    """Initialize system configuration defaults if not present."""
    defaults = {
        "max_file_size_mb": "10",
        "max_files_per_request": "5",
        "allowed_extensions": json.dumps([".pdf", ".png", ".jpg", ".jpeg", ".txt"]),
        "require_review_ambiguous": "true",
        "discard_rejected": "false"
    }
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db_connection(db_path) as conn:
        for k, v in defaults.items():
            conn.execute(
                "INSERT OR IGNORE INTO app_settings (key, value, updated_at) VALUES (?, ?, ?);",
                (k, v, now_iso)
            )
        conn.commit()

def get_all_settings(db_path: str) -> dict[str, Any]:
    """Retrieve all configuration keys and values from SQLite."""
    with get_db_connection(db_path) as conn:
        rows = conn.execute("SELECT key, value FROM app_settings;").fetchall()
        settings = {}
        for r in rows:
            val = r["value"]
            if val.startswith("[") or val.startswith("{"):
                try:
                    val = json.loads(val)
                except Exception:
                    pass
            elif val.lower() in ("true", "false"):
                val = val.lower() == "true"
            elif val.isdigit():
                val = int(val)
            settings[r["key"]] = val
        return settings

def get_setting(db_path: str, key: str, default: Any = None) -> Any:
    """Retrieve a single setting value from SQLite."""
    with get_db_connection(db_path) as conn:
        row = conn.execute("SELECT value FROM app_settings WHERE key = ?;", (key,)).fetchone()
        if not row:
            return default
        val = row["value"]
        if val.startswith("[") or val.startswith("{"):
            try:
                return json.loads(val)
            except Exception:
                return val
        if val.lower() in ("true", "false"):
            return val.lower() == "true"
        if val.isdigit():
            return int(val)
        return val

def save_setting(db_path: str, key: str, value: Any) -> None:
    """Upsert a configuration setting into SQLite."""
    str_val = json.dumps(value) if isinstance(value, (list, dict)) else str(value).lower() if isinstance(value, bool) else str(value)
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO app_settings (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at;
            """,
            (key, str_val, now_iso)
        )
        conn.commit()

def save_inspection(db_path: str, record: dict[str, Any]) -> str:
    """
    Persist an inspection audit record using parameterized queries.
    """
    sql = """
    INSERT INTO inspections (
        id, created_at, timestamp, original_filename, sanitized_filename,
        detected_type, declared_mime_type, browser_mime, file_size,
        sha256_hash, extension, decision, risk_score, risk_level,
        findings_json, summary, storage_path, client_ip
    ) VALUES (
        :id, :created_at, :timestamp, :original_filename, :sanitized_filename,
        :detected_type, :declared_mime_type, :browser_mime, :file_size,
        :sha256_hash, :extension, :decision, :risk_score, :risk_level,
        :findings_json, :summary, :storage_path, :client_ip
    )
    """
    findings_data = record.get("findings_json")
    if not isinstance(findings_data, str):
        findings_data = json.dumps(findings_data or [])

    now_iso = record.get("created_at") or record.get("timestamp") or datetime.now(timezone.utc).isoformat()
    mime = record.get("declared_mime_type") or record.get("browser_mime") or ""

    params = {
        "id": record["id"],
        "created_at": now_iso,
        "timestamp": now_iso,
        "original_filename": record["original_filename"],
        "sanitized_filename": record.get("sanitized_filename", record["original_filename"]),
        "detected_type": record["detected_type"],
        "declared_mime_type": mime,
        "browser_mime": mime,
        "file_size": record["file_size"],
        "sha256_hash": record["sha256_hash"],
        "extension": record.get("extension", ""),
        "decision": record["decision"],
        "risk_score": record.get("risk_score", 0),
        "risk_level": record.get("risk_level", "LOW"),
        "findings_json": findings_data,
        "summary": record.get("summary", ""),
        "storage_path": record.get("storage_path", ""),
        "client_ip": record.get("client_ip", "127.0.0.1"),
    }

    with get_db_connection(db_path) as conn:
        conn.execute(sql, params)
        conn.commit()

    return record["id"]

def get_inspection_by_id(db_path: str, inspection_id: str) -> Optional[dict[str, Any]]:
    """Retrieve full inspection record by UUID."""
    sql = "SELECT * FROM inspections WHERE id = ?;"
    with get_db_connection(db_path) as conn:
        row = conn.execute(sql, (inspection_id,)).fetchone()
        if not row:
            return None
        data = dict(row)
        try:
            data["findings"] = json.loads(data["findings_json"])
        except (json.JSONDecodeError, TypeError):
            data["findings"] = []
            
        if not data.get("expected_type"):
            ext = (data.get("extension") or "").lower()
            from inspector.mime_detection import EXTENSION_EXPECTATIONS
            data["expected_type"] = EXTENSION_EXPECTATIONS.get(ext, {}).get("expected_type", "unknown")
            
        return data

def list_inspections(
    db_path: str,
    limit: int = 50,
    offset: int = 0,
    decision_filter: Optional[str] = None,
    search_query: Optional[str] = None
) -> list[dict[str, Any]]:
    """Query inspection records with optional filtering (Part 1 compatibility)."""
    clauses = []
    params: list[Any] = []

    if decision_filter and decision_filter.upper() != "ALL":
        clauses.append("decision = ?")
        params.append(decision_filter.upper())

    if search_query:
        clauses.append("(original_filename LIKE ? OR sha256_hash LIKE ? OR detected_type LIKE ?)")
        wildcard = f"%{search_query}%"
        params.extend([wildcard, wildcard, wildcard])

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = f"""
    SELECT id, created_at, timestamp, original_filename, sanitized_filename, file_size,
           sha256_hash, detected_type, declared_mime_type, browser_mime, extension,
           decision, risk_score, risk_level, summary
    FROM inspections
    {where_sql}
    ORDER BY created_at DESC
    LIMIT ? OFFSET ?
    """
    params.extend([limit, offset])

    with get_db_connection(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

def list_inspections_paginated(
    db_path: str,
    page: int = 1,
    per_page: int = 10,
    decision_filter: Optional[str] = None,
    type_filter: Optional[str] = None,
    search_query: Optional[str] = None
) -> dict[str, Any]:
    """
    Retrieve paginated inspection records with filtering by decision, file type, and query.
    Validates and bounds pagination arguments to prevent resource exhaustion.
    """
    # Sanitize pagination bounds
    page = max(1, page)
    per_page = max(1, min(per_page, 100))
    offset = (page - 1) * per_page

    clauses = []
    params: list[Any] = []

    if decision_filter and decision_filter.upper() != "ALL":
        clauses.append("decision = ?")
        params.append(decision_filter.upper())

    if type_filter and type_filter.upper() != "ALL":
        clauses.append("LOWER(detected_type) = LOWER(?)")
        params.append(type_filter.strip())

    if search_query:
        clean_q = search_query.strip()
        if clean_q:
            clauses.append("(original_filename LIKE ? OR sha256_hash LIKE ? OR detected_type LIKE ?)")
            wildcard = f"%{clean_q}%"
            params.extend([wildcard, wildcard, wildcard])

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    with get_db_connection(db_path) as conn:
        # Get total matching count
        count_sql = f"SELECT COUNT(*) as total FROM inspections {where_sql};"
        total_row = conn.execute(count_sql, params).fetchone()
        total_count = total_row["total"] if total_row else 0

        # Retrieve items
        data_sql = f"""
        SELECT id, created_at, timestamp, original_filename, sanitized_filename, file_size,
               sha256_hash, detected_type, declared_mime_type, browser_mime, extension,
               decision, risk_score, risk_level, summary
        FROM inspections
        {where_sql}
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?;
        """
        data_params = list(params) + [per_page, offset]
        rows = conn.execute(data_sql, data_params).fetchall()
        items = [dict(r) for r in rows]

    total_pages = max(1, math.ceil(total_count / per_page))

    return {
        "items": items,
        "total": total_count,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
        "has_prev": page > 1,
        "has_next": page < total_pages,
        "prev_page": page - 1 if page > 1 else None,
        "next_page": page + 1 if page < total_pages else None,
    }

def get_dashboard_statistics(db_path: str) -> dict[str, Any]:
    """
    Compute operational metrics and distribution statistics directly from SQLite records.
    Never uses hardcoded fake numbers.
    """
    with get_db_connection(db_path) as conn:
        counts_sql = """
        SELECT
            COUNT(*) as total_inspected,
            SUM(CASE WHEN decision = 'ACCEPTED' THEN 1 ELSE 0 END) as accepted_count,
            SUM(CASE WHEN decision = 'REJECTED' THEN 1 ELSE 0 END) as rejected_count,
            SUM(CASE WHEN decision = 'REVIEW_REQUIRED' THEN 1 ELSE 0 END) as review_count
        FROM inspections;
        """
        row = conn.execute(counts_sql).fetchone()
        total_inspected = row["total_inspected"] if row and row["total_inspected"] else 0
        accepted_count = row["accepted_count"] if row and row["accepted_count"] else 0
        rejected_count = row["rejected_count"] if row and row["rejected_count"] else 0
        review_count = row["review_count"] if row and row["review_count"] else 0

        type_sql = """
        SELECT detected_type, COUNT(*) as count
        FROM inspections
        GROUP BY detected_type
        ORDER BY count DESC;
        """
        type_rows = conn.execute(type_sql).fetchall()
        type_distribution = {r["detected_type"]: r["count"] for r in type_rows}

        recent_sql = """
        SELECT id, created_at, timestamp, original_filename, file_size, sha256_hash,
               detected_type, decision, risk_score, risk_level
        FROM inspections
        ORDER BY created_at DESC
        LIMIT 8;
        """
        recent_rows = conn.execute(recent_sql).fetchall()
        recent_inspections = [dict(r) for r in recent_rows]

        findings_sql = """
        SELECT id, original_filename, created_at, timestamp, decision, risk_score, findings_json
        FROM inspections
        WHERE decision != 'ACCEPTED'
        ORDER BY created_at DESC
        LIMIT 6;
        """
        findings_rows = conn.execute(findings_sql).fetchall()
        recent_findings = []
        for f_row in findings_rows:
            f_dict = dict(f_row)
            try:
                parsed_findings = json.loads(f_dict.get("findings_json", "[]"))
                critical_ones = [f for f in parsed_findings if f.get("status") in {"FAIL", "WARN"}]
                for cf in critical_ones[:2]:
                    recent_findings.append({
                        "inspection_id": f_dict["id"],
                        "filename": f_dict["original_filename"],
                        "timestamp": f_dict.get("created_at") or f_dict["timestamp"],
                        "decision": f_dict["decision"],
                        "rule_id": cf.get("rule_id", "N/A"),
                        "title": cf.get("title", "Finding"),
                        "severity": cf.get("severity", "MEDIUM"),
                        "evidence": cf.get("evidence", ""),
                    })
            except (json.JSONDecodeError, TypeError):
                pass

        return {
            "total_inspected": total_inspected,
            "accepted_count": accepted_count,
            "rejected_count": rejected_count,
            "review_count": review_count,
            "type_distribution": type_distribution,
            "recent_inspections": recent_inspections,
            "recent_findings": recent_findings[:6],
        }
