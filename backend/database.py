"""
database.py - SQLite database layer for the Forensic Intelligence System.

Manages all evidence tables, investigation records, and provides
utility functions for inserting, querying, and hashing forensic data.
"""

import sqlite3
import hashlib
import json
import uuid
import os
from datetime import datetime, timezone
from contextlib import contextmanager
from typing import Optional, Any

# Database path relative to this file
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "forensic_evidence.db")


def compute_sha256(data: Any) -> str:
    """Compute SHA-256 hash of a string or dict for evidence integrity verification."""
    if isinstance(data, dict):
        raw = json.dumps(data, sort_keys=True, default=str)
    elif isinstance(data, (list, tuple)):
        raw = json.dumps(data, sort_keys=True, default=str)
    else:
        raw = str(data)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@contextmanager
def get_db():
    """Context manager that yields a SQLite connection with row_factory."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Create all tables if they don't exist."""
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS investigations (
                id TEXT PRIMARY KEY,
                case_number TEXT NOT NULL,
                title TEXT NOT NULL,
                investigator TEXT,
                agency TEXT,
                description TEXT,
                status TEXT DEFAULT 'active',
                suspect TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                investigation_id TEXT,
                model TEXT,
                manufacturer TEXT,
                os_version TEXT,
                api_level INTEGER,
                serial TEXT,
                imei TEXT,
                phone_number TEXT,
                acquisition_method TEXT,
                status TEXT DEFAULT 'pending',
                storage_info TEXT,
                battery_level INTEGER,
                usb_debugging INTEGER DEFAULT 0,
                data_source TEXT DEFAULT 'sample-data',
                connected_at TEXT,
                FOREIGN KEY (investigation_id) REFERENCES investigations(id)
            );

            CREATE TABLE IF NOT EXISTS sms_evidence (
                id TEXT PRIMARY KEY,
                device_id TEXT,
                direction TEXT,
                contact TEXT,
                number TEXT,
                timestamp TEXT,
                body TEXT,
                thread_id TEXT,
                read_status INTEGER DEFAULT 1,
                sha256_hash TEXT,
                data_source TEXT DEFAULT 'sample-data',
                collected_at TEXT
            );

            CREATE TABLE IF NOT EXISTS call_evidence (
                id TEXT PRIMARY KEY,
                device_id TEXT,
                type TEXT,
                contact TEXT,
                number TEXT,
                timestamp TEXT,
                duration_sec INTEGER DEFAULT 0,
                sha256_hash TEXT,
                data_source TEXT DEFAULT 'sample-data',
                collected_at TEXT
            );

            CREATE TABLE IF NOT EXISTS contact_evidence (
                id TEXT PRIMARY KEY,
                device_id TEXT,
                name TEXT,
                number TEXT,
                email TEXT,
                organization TEXT,
                notes TEXT,
                sha256_hash TEXT,
                data_source TEXT DEFAULT 'sample-data',
                collected_at TEXT
            );

            CREATE TABLE IF NOT EXISTS gps_evidence (
                id TEXT PRIMARY KEY,
                device_id TEXT,
                latitude REAL,
                longitude REAL,
                place TEXT,
                timestamp TEXT,
                accuracy_m REAL,
                altitude REAL,
                provider TEXT,
                sha256_hash TEXT,
                data_source TEXT DEFAULT 'sample-data',
                collected_at TEXT
            );

            CREATE TABLE IF NOT EXISTS browser_evidence (
                id TEXT PRIMARY KEY,
                device_id TEXT,
                title TEXT,
                url TEXT,
                timestamp TEXT,
                visits INTEGER DEFAULT 1,
                browser TEXT,
                sha256_hash TEXT,
                data_source TEXT DEFAULT 'sample-data',
                collected_at TEXT
            );

            CREATE TABLE IF NOT EXISTS app_evidence (
                id TEXT PRIMARY KEY,
                device_id TEXT,
                name TEXT,
                package TEXT,
                installed_at TEXT,
                version TEXT,
                permissions TEXT,
                suspicious INTEGER DEFAULT 0,
                category TEXT,
                sha256_hash TEXT,
                data_source TEXT DEFAULT 'sample-data',
                collected_at TEXT
            );

            CREATE TABLE IF NOT EXISTS media_evidence (
                id TEXT PRIMARY KEY,
                device_id TEXT,
                type TEXT,
                filename TEXT,
                size_kb INTEGER,
                created_at TEXT,
                path TEXT,
                sha256_hash TEXT,
                data_source TEXT DEFAULT 'sample-data',
                collected_at TEXT
            );

            CREATE TABLE IF NOT EXISTS analysis_results (
                id TEXT PRIMARY KEY,
                investigation_id TEXT,
                device_id TEXT,
                analysis_type TEXT,
                findings TEXT,
                summary TEXT,
                risk_level TEXT,
                ai_model TEXT,
                duration_ms INTEGER,
                created_at TEXT,
                FOREIGN KEY (investigation_id) REFERENCES investigations(id)
            );

            CREATE TABLE IF NOT EXISTS generated_reports (
                id TEXT PRIMARY KEY,
                investigation_id TEXT,
                report_path TEXT,
                generated_at TEXT,
                sections_included TEXT,
                FOREIGN KEY (investigation_id) REFERENCES investigations(id)
            );
        """)


def row_to_dict(row) -> dict:
    """Convert sqlite3.Row to plain dict."""
    return dict(row) if row else {}


def rows_to_list(rows) -> list:
    """Convert list of sqlite3.Row to list of dicts."""
    return [dict(r) for r in rows]


# ─── INVESTIGATION FUNCTIONS ──────────────────────────────────────────────────

def create_investigation(data: dict) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    inv_id = data.get("id", str(uuid.uuid4()))
    with get_db() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO investigations
               (id, case_number, title, investigator, agency, description, status, suspect, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                inv_id,
                data.get("case_number", "MFIS-2026-0042"),
                data.get("title", "Android Forensic Investigation"),
                data.get("investigator", "Forensic Analyst"),
                data.get("agency", "Digital Forensics Unit"),
                data.get("description", ""),
                data.get("status", "active"),
                data.get("suspect", "Unknown"),
                data.get("created_at", now),
                now,
            ),
        )
    return {"id": inv_id, **data, "created_at": now, "updated_at": now}


def get_investigation(inv_id: str) -> Optional[dict]:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM investigations WHERE id = ?", (inv_id,)).fetchone()
    return row_to_dict(row)


def list_investigations() -> list:
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM investigations ORDER BY created_at DESC").fetchall()
    return rows_to_list(rows)


# ─── DEVICE FUNCTIONS ─────────────────────────────────────────────────────────

def upsert_device(data: dict) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO devices
               (id, investigation_id, model, manufacturer, os_version, api_level, serial, imei,
                phone_number, acquisition_method, status, storage_info, battery_level,
                usb_debugging, data_source, connected_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                data.get("id", str(uuid.uuid4())),
                data.get("investigation_id"),
                data.get("model", "Unknown"),
                data.get("manufacturer", "Unknown"),
                data.get("os_version", "Android"),
                data.get("api_level", 0),
                data.get("serial", ""),
                data.get("imei", ""),
                data.get("phone_number"),
                data.get("acquisition_method", "ADB"),
                data.get("status", "connected"),
                data.get("storage_info"),
                data.get("battery_level"),
                1 if data.get("usb_debugging") else 0,
                data.get("data_source", "sample-data"),
                now,
            ),
        )
    return data


def get_devices(investigation_id: Optional[str] = None) -> list:
    with get_db() as conn:
        if investigation_id:
            rows = conn.execute(
                "SELECT * FROM devices WHERE investigation_id = ?", (investigation_id,)
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM devices").fetchall()
    return rows_to_list(rows)


# ─── EVIDENCE FUNCTIONS ───────────────────────────────────────────────────────

def insert_evidence(table: str, data: dict) -> dict:
    """Insert evidence record with auto-computed SHA-256 hash."""
    now = datetime.now(timezone.utc).isoformat()
    data_copy = dict(data)
    data_copy["sha256_hash"] = compute_sha256(data)
    data_copy["collected_at"] = now
    if "id" not in data_copy:
        data_copy["id"] = str(uuid.uuid4())

    allowed_tables = {
        "sms_evidence", "call_evidence", "contact_evidence",
        "gps_evidence", "browser_evidence", "app_evidence", "media_evidence",
    }
    if table not in allowed_tables:
        raise ValueError(f"Invalid table: {table}")

    with get_db() as conn:
        cols = list(data_copy.keys())
        placeholders = ", ".join(["?" for _ in cols])
        col_str = ", ".join(cols)
        conn.execute(
            f"INSERT OR REPLACE INTO {table} ({col_str}) VALUES ({placeholders})",
            [data_copy[c] for c in cols],
        )
    return data_copy


def get_evidence(table: str, device_id: Optional[str] = None) -> list:
    allowed_tables = {
        "sms_evidence", "call_evidence", "contact_evidence",
        "gps_evidence", "browser_evidence", "app_evidence", "media_evidence",
    }
    if table not in allowed_tables:
        return []
    with get_db() as conn:
        if device_id:
            rows = conn.execute(
                f"SELECT * FROM {table} WHERE device_id = ? ORDER BY rowid DESC", (device_id,)
            ).fetchall()
        else:
            rows = conn.execute(f"SELECT * FROM {table} ORDER BY rowid DESC").fetchall()
    return rows_to_list(rows)


def clear_evidence_for_device(device_id: str):
    """Remove all evidence for a device (before re-collection)."""
    tables = [
        "sms_evidence", "call_evidence", "contact_evidence",
        "gps_evidence", "browser_evidence", "app_evidence", "media_evidence",
    ]
    with get_db() as conn:
        for table in tables:
            conn.execute(f"DELETE FROM {table} WHERE device_id = ?", (device_id,))


def get_all_hashes(device_id: Optional[str] = None) -> list:
    """Return SHA-256 hashes for all evidence records."""
    tables = [
        ("sms_evidence", "SMS"), ("call_evidence", "Call"),
        ("contact_evidence", "Contact"), ("gps_evidence", "GPS"),
        ("browser_evidence", "Browser"), ("app_evidence", "App"),
        ("media_evidence", "Media"),
    ]
    results = []
    with get_db() as conn:
        for table, kind in tables:
            if device_id:
                rows = conn.execute(
                    f"SELECT id, sha256_hash, collected_at FROM {table} WHERE device_id = ?",
                    (device_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    f"SELECT id, sha256_hash, collected_at FROM {table}"
                ).fetchall()
            for row in rows:
                results.append({
                    "id": row["id"],
                    "kind": kind,
                    "hash": row["sha256_hash"] or "",
                    "collected_at": row["collected_at"],
                })
    return results


# ─── ANALYSIS FUNCTIONS ───────────────────────────────────────────────────────

def save_analysis_result(data: dict) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    result_id = str(uuid.uuid4())
    with get_db() as conn:
        conn.execute(
            """INSERT INTO analysis_results
               (id, investigation_id, device_id, analysis_type, findings, summary,
                risk_level, ai_model, duration_ms, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                result_id,
                data.get("investigation_id"),
                data.get("device_id"),
                data.get("analysis_type", "forensic"),
                json.dumps(data.get("findings", []), default=str),
                data.get("summary", ""),
                data.get("risk_level", "Unknown"),
                data.get("ai_model", "heuristic"),
                data.get("duration_ms", 0),
                now,
            ),
        )
    return {"id": result_id, **data, "created_at": now}


def get_analysis_results(investigation_id: str) -> list:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM analysis_results WHERE investigation_id = ? ORDER BY created_at DESC",
            (investigation_id,),
        ).fetchall()
    results = rows_to_list(rows)
    for r in results:
        try:
            r["findings"] = json.loads(r["findings"]) if r.get("findings") else []
        except Exception:
            r["findings"] = []
    return results


# ─── DASHBOARD STATISTICS ─────────────────────────────────────────────────────

def get_statistics() -> dict:
    with get_db() as conn:
        def count(table, where=""):
            q = f"SELECT COUNT(*) FROM {table}"
            if where:
                q += f" WHERE {where}"
            return conn.execute(q).fetchone()[0]

        return {
            "total_devices": count("devices"),
            "total_sms": count("sms_evidence"),
            "total_calls": count("call_evidence"),
            "total_contacts": count("contact_evidence"),
            "total_gps": count("gps_evidence"),
            "total_browser": count("browser_evidence"),
            "total_apps": count("app_evidence"),
            "total_media": count("media_evidence"),
            "suspicious_apps": count("app_evidence", "suspicious = 1"),
            "total_investigations": count("investigations"),
            "active_investigations": count("investigations", "status = 'active'"),
            "total_evidence": (
                count("sms_evidence") + count("call_evidence") + count("contact_evidence") +
                count("gps_evidence") + count("browser_evidence") +
                count("app_evidence") + count("media_evidence")
            ),
        }
