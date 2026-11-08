"""routes/evidence.py - Evidence collection and storage endpoints."""

import uuid
from fastapi import APIRouter
from database import (
    insert_evidence, get_evidence, get_all_hashes,
    clear_evidence_for_device, upsert_device, create_investigation, compute_sha256,
)
from adb_manager import ADBManager, load_sample_data

router = APIRouter()
adb = ADBManager()


@router.post("/collect/{serial}")
def collect_evidence(serial: str):
    """Collect all evidence from an Android device via ADB."""
    device_info_result = adb.get_device_info(serial)
    device = device_info_result.get("device", {})
    device_id = f"dev-{serial}"
    device["id"] = device_id
    upsert_device(device)

    results = {}

    # SMS
    sms_result = adb.extract_sms(serial)
    results["sms"] = {"count": sms_result["count"], "success": sms_result["success"], "error": sms_result.get("error")}
    for r in sms_result.get("records", []):
        r["device_id"] = device_id
        insert_evidence("sms_evidence", r)

    # Calls
    call_result = adb.extract_call_logs(serial)
    results["calls"] = {"count": call_result["count"], "success": call_result["success"], "error": call_result.get("error")}
    for r in call_result.get("records", []):
        r["device_id"] = device_id
        insert_evidence("call_evidence", r)

    # Contacts
    contact_result = adb.extract_contacts(serial)
    results["contacts"] = {"count": contact_result["count"], "success": contact_result["success"]}
    for r in contact_result.get("records", []):
        r["device_id"] = device_id
        insert_evidence("contact_evidence", r)

    # Apps
    app_result = adb.extract_installed_apps(serial)
    results["apps"] = {"count": app_result["count"], "success": app_result["success"]}
    for r in app_result.get("records", []):
        r["device_id"] = device_id
        r["permissions"] = ",".join(r.get("permissions", []))
        insert_evidence("app_evidence", r)

    # GPS
    gps_result = adb.extract_gps_data(serial)
    results["gps"] = {"count": gps_result["count"], "success": gps_result["success"], "note": gps_result.get("note")}
    for r in gps_result.get("records", []):
        r["device_id"] = device_id
        insert_evidence("gps_evidence", r)

    # Media
    media_result = adb.extract_media_files(serial)
    results["media"] = {"count": media_result["count"], "success": media_result["success"]}
    for r in media_result.get("records", []):
        r["device_id"] = device_id
        insert_evidence("media_evidence", r)

    total = sum(v["count"] for v in results.values())
    return {
        "success": True,
        "device_id": device_id,
        "serial": serial,
        "total_collected": total,
        "breakdown": results,
        "message": f"Collected {total} evidence records from device {serial}",
    }


@router.post("/load-sample")
def load_sample_dataset():
    """Load the sample forensic dataset into SQLite for testing."""
    data = load_sample_data()
    inv = data["investigation"]
    create_investigation(inv)

    device = data["device"]
    device_id = device["id"]
    upsert_device(device)

    # Clear existing sample data for this device
    clear_evidence_for_device(device_id)

    counts = {}

    for sms in data.get("sms", []):
        sms["device_id"] = device_id
        insert_evidence("sms_evidence", sms)
    counts["sms"] = len(data.get("sms", []))

    for call in data.get("calls", []):
        call["device_id"] = device_id
        insert_evidence("call_evidence", call)
    counts["calls"] = len(data.get("calls", []))

    for contact in data.get("contacts", []):
        contact["device_id"] = device_id
        insert_evidence("contact_evidence", contact)
    counts["contacts"] = len(data.get("contacts", []))

    for gps in data.get("gps", []):
        gps["device_id"] = device_id
        insert_evidence("gps_evidence", gps)
    counts["gps"] = len(data.get("gps", []))

    for browser in data.get("browser", []):
        browser["device_id"] = device_id
        insert_evidence("browser_evidence", browser)
    counts["browser"] = len(data.get("browser", []))

    for app in data.get("apps", []):
        app["device_id"] = device_id
        app["suspicious"] = 1 if app.get("suspicious") else 0
        app["permissions"] = ",".join(app.get("permissions", []))
        insert_evidence("app_evidence", app)
    counts["apps"] = len(data.get("apps", []))

    for media in data.get("media", []):
        media["device_id"] = device_id
        insert_evidence("media_evidence", media)
    counts["media"] = len(data.get("media", []))

    total = sum(counts.values())
    return {
        "success": True,
        "message": f"Loaded {total} sample evidence records",
        "investigation_id": inv["id"],
        "device_id": device_id,
        "counts": counts,
    }


@router.get("/hashes/{device_id}")
def get_evidence_hashes(device_id: str):
    hashes = get_all_hashes(device_id)
    return {"success": True, "hashes": hashes, "count": len(hashes)}


@router.get("/{device_id}")
def get_all_evidence(device_id: str):
    return {
        "success": True,
        "device_id": device_id,
        "sms": get_evidence("sms_evidence", device_id),
        "calls": get_evidence("call_evidence", device_id),
        "contacts": get_evidence("contact_evidence", device_id),
        "gps": get_evidence("gps_evidence", device_id),
        "browser": get_evidence("browser_evidence", device_id),
        "apps": get_evidence("app_evidence", device_id),
        "media": get_evidence("media_evidence", device_id),
    }


@router.get("/{device_id}/{category}")
def get_evidence_by_category(device_id: str, category: str):
    table_map = {
        "sms": "sms_evidence",
        "calls": "call_evidence",
        "contacts": "contact_evidence",
        "gps": "gps_evidence",
        "browser": "browser_evidence",
        "apps": "app_evidence",
        "media": "media_evidence",
    }
    table = table_map.get(category)
    if not table:
        return {"success": False, "error": f"Unknown category: {category}"}
    records = get_evidence(table, device_id)
    return {"success": True, "category": category, "records": records, "count": len(records)}


@router.post("/import")
def import_evidence(data: dict):
    """Import evidence from a JSON payload."""
    device_id = data.get("device_id", f"imported-{uuid.uuid4().hex[:8]}")
    imported = {}

    for category, records in data.get("evidence", {}).items():
        table_map = {
            "sms": "sms_evidence", "calls": "call_evidence",
            "contacts": "contact_evidence", "gps": "gps_evidence",
            "browser": "browser_evidence", "apps": "app_evidence", "media": "media_evidence",
        }
        table = table_map.get(category)
        if table and isinstance(records, list):
            for r in records:
                r["device_id"] = device_id
                r["data_source"] = "imported"
                insert_evidence(table, r)
            imported[category] = len(records)

    return {"success": True, "device_id": device_id, "imported": imported}

