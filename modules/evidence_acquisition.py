"""
evidence_acquisition.py - Evidence Ingestion and Acquisition Controller
Supports:
  - Option A: ADB Mobile Acquisition (Authorized logical extraction)
  - Option B: Laptop File Upload (TXT, CSV, JSON, XML, SQLITE, DB, LOG, ZIP, Images)
  - Option C: Mobile-Transferred Evidence Upload
Computes SHA-256 immediately, stores original in evidence_storage/, and creates a working copy.
"""

import os
import shutil
import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from modules.hash_manager import calculate_file_sha256, create_working_copy
from modules.database import add_evidence, log_audit, register_device
from modules.adb_manager import run_adb_command
from modules.device_info import get_android_device_profile

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVIDENCE_STORAGE_DIR = os.path.join(BASE_DIR, "evidence_storage")
WORKING_COPIES_DIR = os.path.join(BASE_DIR, "working_copies")
LOGS_DIR = os.path.join(BASE_DIR, "logs")


def ensure_directories():
    os.makedirs(EVIDENCE_STORAGE_DIR, exist_ok=True)
    os.makedirs(WORKING_COPIES_DIR, exist_ok=True)
    os.makedirs(LOGS_DIR, exist_ok=True)


def detect_evidence_type(filename: str) -> str:
    """Classifies file based on extension and naming conventions."""
    ext = os.path.splitext(filename)[1].lower()
    name_lower = filename.lower()

    if ext in [".sqlite", ".sqlite3", ".db", ".db3"]:
        if "browser" in name_lower or "history" in name_lower or "chrome" in name_lower:
            return "SQLITE_BROWSER_HISTORY"
        elif "sms" in name_lower or "mms" in name_lower or "telephony" in name_lower:
            return "SQLITE_TELEPHONY"
        elif "contact" in name_lower:
            return "SQLITE_CONTACTS"
        return "SQLITE_DATABASE"
    elif ext == ".csv":
        return "CSV_SPREADSHEET"
    elif ext == ".json":
        return "JSON_DATA"
    elif ext in [".txt", ".text"]:
        return "TEXT_DOCUMENT"
    elif ext == ".log":
        return "SYSTEM_LOG"
    elif ext == ".xml":
        return "XML_CONFIGURATION"
    elif ext in [".zip", ".tar", ".gz", ".7z"]:
        return "COMPRESSED_ARCHIVE"
    elif ext in [".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"]:
        return "MEDIA_IMAGE"
    elif ext in [".mp4", ".mkv", ".3gp", ".avi"]:
        return "MEDIA_VIDEO"
    elif ext in [".mp3", ".m4a", ".wav", ".aac"]:
        return "MEDIA_AUDIO"
    elif ext in [".raw", ".dd", ".img", ".e01"]:
        return "FORENSIC_DISK_IMAGE"
    return "UNKNOWN_BINARY"


def register_uploaded_file(
    file_bytes: bytes,
    original_filename: str,
    case_id: str,
    acquisition_method: str = "LAPTOP_UPLOAD",
    device_id: Optional[str] = None,
    original_source_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Saves uploaded file bytes to evidence_storage/, computes SHA-256,
    creates working copy, and registers in SQLite.
    """
    ensure_directories()
    case_storage_dir = os.path.join(EVIDENCE_STORAGE_DIR, case_id)
    case_working_dir = os.path.join(WORKING_COPIES_DIR, case_id)
    os.makedirs(case_storage_dir, exist_ok=True)
    os.makedirs(case_working_dir, exist_ok=True)

    timestamp_prefix = datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_name = os.path.basename(original_filename).replace(" ", "_")
    stored_filename = f"{timestamp_prefix}_{clean_name}"
    stored_path = os.path.join(case_storage_dir, stored_filename)

    # Write original evidence without alteration
    with open(stored_path, "wb") as f:
        f.write(file_bytes)

    file_size = len(file_bytes)
    sha256_hash = calculate_file_sha256(stored_path)
    evidence_type = detect_evidence_type(original_filename)

    # Register in database
    record = add_evidence(
        case_id=case_id,
        filename=stored_filename,
        evidence_type=evidence_type,
        original_filename=original_filename,
        stored_evidence_path=stored_path,
        file_size=file_size,
        sha256_hash=sha256_hash,
        acquisition_method=acquisition_method,
        original_source_path=original_source_path or original_filename,
        device_id=device_id,
    )

    # Create safe working copy for analysis
    working_copy_path = create_working_copy(
        original_path=stored_path,
        working_dir=case_working_dir,
        evidence_id=record["evidence_id"]
    )
    record["working_copy_path"] = working_copy_path
    return record


def acquire_android_adb_evidence(
    serial: str,
    case_id: str,
    acquire_packages: bool = True,
    acquire_device_profile: bool = True,
    acquire_accessible_logs: bool = True,
    acquire_shared_storage: bool = False,
    progress_callback=None
) -> Dict[str, Any]:
    """
    Option A: Authorized ADB Evidence Acquisition.
    Pulls accessible artifacts without bypassing device security or claiming fake capabilities.
    """
    ensure_directories()
    case_storage_dir = os.path.join(EVIDENCE_STORAGE_DIR, case_id)
    os.makedirs(case_storage_dir, exist_ok=True)

    results = {
        "device_id": None,
        "acquired_items": [],
        "failed_items": [],
        "log_messages": [],
    }

    def log_step(msg: str):
        results["log_messages"].append(msg)
        if progress_callback:
            progress_callback(msg)

    # 1. Device Profile Acquisition
    log_step(f"Connecting to Android Device {serial}...")
    profile = get_android_device_profile(serial)
    dev_record = register_device(
        case_id=case_id,
        device_identifier=serial,
        model=profile.get("model", "Unknown"),
        manufacturer=profile.get("manufacturer", "Unknown"),
        android_version=profile.get("android_version", "Unknown"),
        connection_status="ACQUIRED",
    )
    results["device_id"] = dev_record["device_id"]
    log_step(f"Device profile retrieved: {profile['model']} ({profile['manufacturer']}, Android {profile['android_version']})")

    # Save Device Profile JSON
    if acquire_device_profile:
        profile_json = json.dumps(profile, indent=2).encode("utf-8")
        rec = register_uploaded_file(
            file_bytes=profile_json,
            original_filename=f"adb_device_profile_{serial}.json",
            case_id=case_id,
            acquisition_method="ADB_LOGICAL_PROFILE",
            device_id=dev_record["device_id"],
            original_source_path=f"adb://{serial}/system_properties",
        )
        results["acquired_items"].append(rec)
        log_step(f"Saved device profile evidence: {rec['evidence_id']} (SHA-256: {rec['sha256_hash'][:16]}...)")

    # 2. Installed Packages Acquisition
    if acquire_packages:
        log_step("Acquiring third-party and system package registry...")
        ok, stdout, err = run_adb_command(["shell", "pm", "list", "packages", "-3", "-f"], serial=serial, timeout=15)
        if ok and stdout:
            rec = register_uploaded_file(
                file_bytes=stdout.encode("utf-8"),
                original_filename=f"adb_installed_packages_{serial}.txt",
                case_id=case_id,
                acquisition_method="ADB_LOGICAL_PM",
                device_id=dev_record["device_id"],
                original_source_path=f"adb://{serial}/pm_list_packages",
            )
            results["acquired_items"].append(rec)
            log_step(f"Saved package registry evidence: {rec['evidence_id']}")
        else:
            results["failed_items"].append({"item": "Installed Packages", "reason": err or "No packages returned"})
            log_step(f"Warning: Package listing failed: {err}")

    # 3. System Logcat Excerpt (last 5000 lines accessible)
    if acquire_accessible_logs:
        log_step("Acquiring system diagnostic ring buffer logcat...")
        ok, stdout, err = run_adb_command(["logcat", "-d", "-t", "5000"], serial=serial, timeout=20)
        if ok and stdout:
            rec = register_uploaded_file(
                file_bytes=stdout.encode("utf-8"),
                original_filename=f"adb_system_logcat_{serial}.log",
                case_id=case_id,
                acquisition_method="ADB_LOGCAT_DUMP",
                device_id=dev_record["device_id"],
                original_source_path=f"adb://{serial}/logcat",
            )
            results["acquired_items"].append(rec)
            log_step(f"Saved logcat diagnostic evidence: {rec['evidence_id']}")
        else:
            results["failed_items"].append({"item": "System Logcat", "reason": err or "Permission denied or log buffer empty"})

    # 4. Inaccessible Evidence Documentation
    results["failed_items"].append({
        "item": "Protected Private Databases (WhatsApp, Signal, App Sandboxes)",
        "reason": "Restricted by Android SELinux / Non-root permission model on production device.",
    })
    results["failed_items"].append({
        "item": "Physical NAND Bitstream Dump",
        "reason": "Requires unlocked bootloader / physical EDL or forensic chip-off hardware.",
    })

    log_step(f"ADB acquisition completed. {len(results['acquired_items'])} items acquired, {len(results['failed_items'])} restricted items documented.")
    return results

