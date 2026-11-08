"""
database.py - SQLite Central Database & Audit Logging Layer
Uses Python sqlite3 with WAL journaling, parameterized queries, and transactions.
Stores metadata, file paths, and hashes for all evidence and cases.
"""

import sqlite3
import os
import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from contextlib import contextmanager

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_DIR = os.path.join(BASE_DIR, "database")
DB_PATH = os.path.join(DB_DIR, "forensic.db")


def get_current_timestamp() -> str:
    """Returns ISO 8601 UTC timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


@contextmanager
def get_db_connection():
    """Context manager for SQLite connection with automatic commit/rollback."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Initializes SQLite schema matching strict specification."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # 1. Cases Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                case_name TEXT NOT NULL,
                description TEXT,
                created_at TEXT NOT NULL,
                case_status TEXT NOT NULL DEFAULT 'ACTIVE'
            );
        """)

        # 2. Devices Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                device_identifier TEXT NOT NULL,
                model TEXT,
                manufacturer TEXT,
                android_version TEXT,
                connection_status TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
            );
        """)

        # 3. Evidence Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                evidence_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                device_id TEXT,
                filename TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                original_filename TEXT NOT NULL,
                original_source_path TEXT,
                stored_evidence_path TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                sha256_hash TEXT NOT NULL,
                acquisition_method TEXT NOT NULL,
                acquisition_timestamp TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE,
                FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE SET NULL
            );
        """)

        # 4. Analysis Results Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_results (
                analysis_id TEXT PRIMARY KEY,
                evidence_id TEXT NOT NULL,
                case_id TEXT NOT NULL,
                analysis_type TEXT NOT NULL,
                finding_description TEXT NOT NULL,
                severity TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                verification_status TEXT NOT NULL,
                FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id) ON DELETE CASCADE,
                FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
            );
        """)

        # 5. AI Reports Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ai_reports (
                report_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                ollama_model_name TEXT NOT NULL,
                ai_summary TEXT NOT NULL,
                report_path TEXT,
                generation_timestamp TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
            );
        """)

        # 6. Audit Logs Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                log_id TEXT PRIMARY KEY,
                case_id TEXT,
                evidence_id TEXT,
                action_performed TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                status TEXT NOT NULL,
                details TEXT
            );
        """)


def _row_to_dict(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
    return dict(row) if row else None


def _rows_to_list(rows: List[sqlite3.Row]) -> List[Dict[str, Any]]:
    return [dict(r) for r in rows]


# ─── CASE MANAGEMENT ─────────────────────────────────────────────────────────

def create_case(case_name: str, description: str = "") -> Dict[str, Any]:
    case_id = f"CASE-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    now = get_current_timestamp()
    with get_db_connection() as conn:
        conn.execute(
            """INSERT INTO cases (case_id, case_name, description, created_at, case_status)
               VALUES (?, ?, ?, ?, ?)""",
            (case_id, case_name, description, now, "ACTIVE"),
        )
    log_audit(case_id=case_id, action="CREATE_CASE", status="SUCCESS", details=f"Created case {case_name}")
    return {"case_id": case_id, "case_name": case_name, "description": description, "created_at": now, "case_status": "ACTIVE"}


def get_case(case_id: str) -> Optional[Dict[str, Any]]:
    with get_db_connection() as conn:
        row = conn.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
    return _row_to_dict(row)


def list_cases() -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        rows = conn.execute("SELECT * FROM cases ORDER BY created_at DESC").fetchall()
    return _rows_to_list(rows)


def update_case_status(case_id: str, new_status: str) -> bool:
    with get_db_connection() as conn:
        res = conn.execute("UPDATE cases SET case_status = ? WHERE case_id = ?", (new_status, case_id))
        success = res.rowcount > 0
    if success:
        log_audit(case_id=case_id, action="UPDATE_CASE_STATUS", status="SUCCESS", details=f"Status set to {new_status}")
    return success


# ─── DEVICE MANAGEMENT ───────────────────────────────────────────────────────

def register_device(
    case_id: str,
    device_identifier: str,
    model: str = "Unknown",
    manufacturer: str = "Unknown",
    android_version: str = "Unknown",
    connection_status: str = "CONNECTED",
) -> Dict[str, Any]:
    device_id = f"DEV-{uuid.uuid4().hex[:8].upper()}"
    with get_db_connection() as conn:
        # Check if already registered in case
        existing = conn.execute(
            "SELECT * FROM devices WHERE case_id = ? AND device_identifier = ?",
            (case_id, device_identifier)
        ).fetchone()
        if existing:
            conn.execute(
                """UPDATE devices SET model = ?, manufacturer = ?, android_version = ?, connection_status = ?
                   WHERE device_id = ?""",
                (model, manufacturer, android_version, connection_status, existing["device_id"])
            )
            device_id = existing["device_id"]
        else:
            conn.execute(
                """INSERT INTO devices (device_id, case_id, device_identifier, model, manufacturer, android_version, connection_status)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (device_id, case_id, device_identifier, model, manufacturer, android_version, connection_status),
            )
    log_audit(case_id=case_id, action="REGISTER_DEVICE", status="SUCCESS", details=f"Device {model} ({device_identifier})")
    return {
        "device_id": device_id,
        "case_id": case_id,
        "device_identifier": device_identifier,
        "model": model,
        "manufacturer": manufacturer,
        "android_version": android_version,
        "connection_status": connection_status,
    }


def get_devices_by_case(case_id: str) -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        rows = conn.execute("SELECT * FROM devices WHERE case_id = ? ORDER BY device_id", (case_id,)).fetchall()
    return _rows_to_list(rows)


def list_all_devices() -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        rows = conn.execute("SELECT * FROM devices ORDER BY device_id").fetchall()
    return _rows_to_list(rows)


# ─── EVIDENCE MANAGEMENT ─────────────────────────────────────────────────────

def add_evidence(
    case_id: str,
    filename: str,
    evidence_type: str,
    original_filename: str,
    stored_evidence_path: str,
    file_size: int,
    sha256_hash: str,
    acquisition_method: str,
    original_source_path: Optional[str] = None,
    device_id: Optional[str] = None,
) -> Dict[str, Any]:
    evidence_id = f"EVD-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    now = get_current_timestamp()
    with get_db_connection() as conn:
        conn.execute(
            """INSERT INTO evidence (
                evidence_id, case_id, device_id, filename, evidence_type, original_filename,
                original_source_path, stored_evidence_path, file_size, sha256_hash,
                acquisition_method, acquisition_timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                evidence_id, case_id, device_id, filename, evidence_type, original_filename,
                original_source_path, stored_evidence_path, file_size, sha256_hash,
                acquisition_method, now
            ),
        )
    log_audit(
        case_id=case_id,
        evidence_id=evidence_id,
        action="ACQUIRE_EVIDENCE",
        status="SUCCESS",
        details=f"Stored {filename} ({file_size} bytes, SHA-256: {sha256_hash[:16]}... via {acquisition_method})",
    )
    return {
        "evidence_id": evidence_id,
        "case_id": case_id,
        "device_id": device_id,
        "filename": filename,
        "evidence_type": evidence_type,
        "original_filename": original_filename,
        "original_source_path": original_source_path,
        "stored_evidence_path": stored_evidence_path,
        "file_size": file_size,
        "sha256_hash": sha256_hash,
        "acquisition_method": acquisition_method,
        "acquisition_timestamp": now,
    }


def get_evidence_by_case(case_id: str) -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM evidence WHERE case_id = ? ORDER BY acquisition_timestamp DESC",
            (case_id,)
        ).fetchall()
    return _rows_to_list(rows)


def get_evidence_by_id(evidence_id: str) -> Optional[Dict[str, Any]]:
    with get_db_connection() as conn:
        row = conn.execute("SELECT * FROM evidence WHERE evidence_id = ?", (evidence_id,)).fetchone()
    return _row_to_dict(row)


def list_all_evidence() -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        rows = conn.execute("SELECT * FROM evidence ORDER BY acquisition_timestamp DESC").fetchall()
    return _rows_to_list(rows)


# ─── ANALYSIS RESULTS ────────────────────────────────────────────────────────

def add_analysis_result(
    evidence_id: str,
    case_id: str,
    analysis_type: str,
    finding_description: str,
    severity: str,
    verification_status: str,
) -> Dict[str, Any]:
    analysis_id = f"ANL-{uuid.uuid4().hex[:8].upper()}"
    now = get_current_timestamp()
    with get_db_connection() as conn:
        conn.execute(
            """INSERT INTO analysis_results (
                analysis_id, evidence_id, case_id, analysis_type,
                finding_description, severity, timestamp, verification_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                analysis_id, evidence_id, case_id, analysis_type,
                finding_description, severity.upper(), now, verification_status.upper()
            ),
        )
    return {
        "analysis_id": analysis_id,
        "evidence_id": evidence_id,
        "case_id": case_id,
        "analysis_type": analysis_type,
        "finding_description": finding_description,
        "severity": severity.upper(),
        "timestamp": now,
        "verification_status": verification_status.upper(),
    }


def get_analysis_results_by_case(case_id: str) -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        rows = conn.execute(
            """SELECT a.*, e.filename, e.evidence_type 
               FROM analysis_results a
               LEFT JOIN evidence e ON a.evidence_id = e.evidence_id
               WHERE a.case_id = ? 
               ORDER BY a.timestamp DESC""",
            (case_id,)
        ).fetchall()
    return _rows_to_list(rows)


def get_analysis_results_by_evidence(evidence_id: str) -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM analysis_results WHERE evidence_id = ? ORDER BY timestamp DESC",
            (evidence_id,)
        ).fetchall()
    return _rows_to_list(rows)


def list_all_analysis_results() -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        rows = conn.execute(
            """SELECT a.*, e.filename, e.evidence_type, c.case_name 
               FROM analysis_results a
               LEFT JOIN evidence e ON a.evidence_id = e.evidence_id
               LEFT JOIN cases c ON a.case_id = c.case_id
               ORDER BY a.timestamp DESC"""
        ).fetchall()
    return _rows_to_list(rows)


# ─── AI REPORTS ──────────────────────────────────────────────────────────────

def add_ai_report(
    case_id: str,
    ollama_model_name: str,
    ai_summary: str,
    report_path: Optional[str] = None,
) -> Dict[str, Any]:
    report_id = f"RPT-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    now = get_current_timestamp()
    with get_db_connection() as conn:
        conn.execute(
            """INSERT INTO ai_reports (report_id, case_id, ollama_model_name, ai_summary, report_path, generation_timestamp)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (report_id, case_id, ollama_model_name, ai_summary, report_path, now),
        )
    log_audit(case_id=case_id, action="GENERATE_AI_REPORT", status="SUCCESS", details=f"Model: {ollama_model_name}")
    return {
        "report_id": report_id,
        "case_id": case_id,
        "ollama_model_name": ollama_model_name,
        "ai_summary": ai_summary,
        "report_path": report_path,
        "generation_timestamp": now,
    }


def get_ai_reports_by_case(case_id: str) -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM ai_reports WHERE case_id = ? ORDER BY generation_timestamp DESC",
            (case_id,)
        ).fetchall()
    return _rows_to_list(rows)


def list_all_ai_reports() -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        rows = conn.execute(
            """SELECT r.*, c.case_name 
               FROM ai_reports r
               LEFT JOIN cases c ON r.case_id = c.case_id
               ORDER BY r.generation_timestamp DESC"""
        ).fetchall()
    return _rows_to_list(rows)


# ─── AUDIT LOGGING ───────────────────────────────────────────────────────────

def log_audit(
    action: str,
    status: str = "SUCCESS",
    case_id: Optional[str] = None,
    evidence_id: Optional[str] = None,
    details: Optional[str] = None,
) -> str:
    log_id = f"LOG-{uuid.uuid4().hex[:10].upper()}"
    now = get_current_timestamp()
    with get_db_connection() as conn:
        conn.execute(
            """INSERT INTO audit_logs (log_id, case_id, evidence_id, action_performed, timestamp, status, details)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (log_id, case_id, evidence_id, action, now, status, details),
        )
    return log_id


def get_audit_logs(case_id: Optional[str] = None, limit: int = 200) -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        if case_id:
            rows = conn.execute(
                "SELECT * FROM audit_logs WHERE case_id = ? ORDER BY timestamp DESC LIMIT ?",
                (case_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
    return _rows_to_list(rows)


# ─── DASHBOARD STATISTICS ────────────────────────────────────────────────────

def get_dashboard_metrics(case_id: Optional[str] = None) -> Dict[str, Any]:
    """Calculates all metrics specified in Section 2."""
    with get_db_connection() as conn:
        def scalar(query, params=()):
            row = conn.execute(query, params).fetchone()
            return row[0] if row else 0

        where_case = " WHERE case_id = ?" if case_id else ""
        params = (case_id,) if case_id else ()

        total_cases = scalar("SELECT COUNT(*) FROM cases")
        total_devices = scalar(f"SELECT COUNT(*) FROM devices{where_case}", params)
        total_evidence = scalar(f"SELECT COUNT(*) FROM evidence{where_case}", params)
        total_analyzed = scalar(f"SELECT COUNT(DISTINCT evidence_id) FROM analysis_results{where_case}", params)

        confirmed_findings = scalar(
            f"SELECT COUNT(*) FROM analysis_results WHERE verification_status = 'CONFIRMED EVIDENCE'" +
            (" AND case_id = ?" if case_id else ""),
            params
        )
        ai_observations = scalar(
            f"SELECT COUNT(*) FROM analysis_results WHERE verification_status = 'AI OBSERVATION'" +
            (" AND case_id = ?" if case_id else ""),
            params
        )
        possible_leads = scalar(
            f"SELECT COUNT(*) FROM analysis_results WHERE verification_status = 'POSSIBLE LEAD'" +
            (" AND case_id = ?" if case_id else ""),
            params
        )

        total_reports = scalar(f"SELECT COUNT(*) FROM ai_reports{where_case}", params)

        # Integrity verified count and mismatch count from audit logs
        verified_count = scalar(
            "SELECT COUNT(DISTINCT evidence_id) FROM audit_logs WHERE action_performed = 'INTEGRITY_VERIFICATION' AND status = 'INTEGRITY VERIFIED'" +
            (" AND case_id = ?" if case_id else ""),
            params
        )
        mismatch_count = scalar(
            "SELECT COUNT(DISTINCT evidence_id) FROM audit_logs WHERE action_performed = 'INTEGRITY_VERIFICATION' AND status = 'INTEGRITY MISMATCH'" +
            (" AND case_id = ?" if case_id else ""),
            params
        )

        # Recent activities
        recent_activity = _rows_to_list(
            conn.execute(
                f"SELECT * FROM audit_logs{where_case} ORDER BY timestamp DESC LIMIT 10",
                params
            ).fetchall()
        )

        return {
            "total_cases": total_cases,
            "total_devices": total_devices,
            "total_evidence": total_evidence,
            "total_analyzed": total_analyzed,
            "verified_count": verified_count,
            "mismatch_count": mismatch_count,
            "confirmed_findings": confirmed_findings,
            "ai_observations": ai_observations,
            "possible_leads": possible_leads,
            "total_reports": total_reports,
            "recent_activity": recent_activity,
        }

