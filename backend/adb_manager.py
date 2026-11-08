"""
adb_manager.py - ADB Device Connection Manager for Android forensic acquisition.

Connects to Android devices via ADB (Android Debug Bridge), extracts forensic
evidence respecting Android permissions and access restrictions.
NOTE: Does NOT assume root access. Handles permission denied gracefully.
"""

import subprocess
import json
import re
import os
from datetime import datetime, timezone
from typing import Optional


def _run_adb(args: list[str], serial: Optional[str] = None, timeout: int = 15) -> tuple[str, str, int]:
    """Run an ADB command and return (stdout, stderr, returncode)."""
    cmd = ["adb"]
    if serial:
        cmd += ["-s", serial]
    cmd += args
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", "ADB command timed out", 1
    except FileNotFoundError:
        return "", "ADB not found in PATH. Please install Android SDK platform-tools.", 1
    except Exception as e:
        return "", str(e), 1


def _run_adb_shell(serial: str, shell_cmd: str, timeout: int = 20) -> tuple[str, str, int]:
    """Run an ADB shell command on a connected device."""
    return _run_adb(["shell", shell_cmd], serial=serial, timeout=timeout)


class ADBManager:
    """Manages ADB connections and forensic data extraction from Android devices."""

    def list_devices(self) -> dict:
        """List all connected ADB devices. Returns list of device dicts."""
        stdout, stderr, rc = _run_adb(["devices", "-l"])
        if rc != 0:
            return {"success": False, "devices": [], "error": stderr or "ADB not available"}

        devices = []
        lines = stdout.strip().split("\n")
        for line in lines[1:]:  # Skip "List of devices attached" header
            line = line.strip()
            if not line or "offline" in line or "unauthorized" in line:
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "device":
                serial = parts[0]
                # Parse device info from -l output
                info = {}
                for part in parts[2:]:
                    if ":" in part:
                        k, v = part.split(":", 1)
                        info[k] = v
                devices.append({
                    "serial": serial,
                    "status": "connected",
                    "model": info.get("model", "Unknown").replace("_", " "),
                    "product": info.get("product", ""),
                    "device": info.get("device", ""),
                    "transport_id": info.get("transport_id", ""),
                })
        return {"success": True, "devices": devices}

    def get_device_info(self, serial: str) -> dict:
        """Get detailed device information using ADB shell commands."""
        info = {"serial": serial, "status": "connected", "os": "Android"}

        def prop(key: str) -> str:
            out, _, _ = _run_adb_shell(serial, f"getprop {key}")
            return out.strip()

        info["model"] = prop("ro.product.model") or "Unknown"
        info["manufacturer"] = prop("ro.product.manufacturer") or "Unknown"
        info["brand"] = prop("ro.product.brand") or ""
        info["os_version"] = prop("ro.build.version.release") or "Unknown"
        info["api_level"] = prop("ro.build.version.sdk") or "0"
        info["build_id"] = prop("ro.build.id") or ""
        info["android_id"] = ""

        # Try to get IMEI (requires privileged access on most devices)
        imei_out, _, _ = _run_adb_shell(serial, "service call iphonesubinfo 1")
        imei = ""
        if imei_out and "Result" not in imei_out:
            # Parse IMEI from service call output (hex chars)
            chars = re.findall(r"'(.)'\.", imei_out)
            imei = "".join(chars).strip()
        info["imei"] = imei or "Not accessible (requires privileged access)"

        # Battery level
        batt_out, _, _ = _run_adb_shell(serial, "dumpsys battery | grep level")
        batt_match = re.search(r"level:\s*(\d+)", batt_out)
        info["battery_level"] = int(batt_match.group(1)) if batt_match else None

        # Storage info
        storage_out, _, _ = _run_adb_shell(serial, "df /sdcard")
        info["storage_info"] = storage_out.split("\n")[-1].strip() if storage_out else "Unknown"

        # USB debugging (if we're connected, it's enabled)
        info["usb_debugging"] = True
        info["acquisition_method"] = "ADB"
        info["data_source"] = "adb-live"
        info["connected_at"] = datetime.now(timezone.utc).isoformat()

        return {"success": True, "device": info}

    def extract_sms(self, serial: str) -> dict:
        """Extract SMS messages via ADB content provider."""
        out, err, rc = _run_adb_shell(
            serial,
            "content query --uri content://sms --projection _id,address,date,body,type,read",
            timeout=30,
        )
        if "Permission Denial" in err or "Exception" in err:
            return {
                "success": False,
                "records": [],
                "error": "Permission denied: SMS requires READ_SMS permission (not available without root on Android 10+)",
                "count": 0,
            }
        records = _parse_content_query(out, "sms")
        return {"success": True, "records": records, "count": len(records)}

    def extract_call_logs(self, serial: str) -> dict:
        """Extract call logs via ADB content provider."""
        out, err, rc = _run_adb_shell(
            serial,
            "content query --uri content://call_log/calls --projection _id,number,name,date,duration,type",
            timeout=30,
        )
        if "Permission Denial" in err or "Exception" in err:
            return {
                "success": False,
                "records": [],
                "error": "Permission denied: Call logs require READ_CALL_LOG permission (restricted on Android 10+)",
                "count": 0,
            }
        records = _parse_content_query(out, "calls")
        return {"success": True, "records": records, "count": len(records)}

    def extract_contacts(self, serial: str) -> dict:
        """Extract contacts via ADB content provider."""
        out, err, rc = _run_adb_shell(
            serial,
            "content query --uri content://contacts/phones --projection _id,display_name,number",
            timeout=30,
        )
        if "Permission Denial" in err or "Exception" in err:
            # Try alternate URI
            out, err, rc = _run_adb_shell(
                serial,
                "content query --uri content://com.android.contacts/data/phones --projection display_name,data1",
                timeout=30,
            )
        records = _parse_content_query(out, "contacts")
        return {"success": True, "records": records, "count": len(records)}

    def extract_installed_apps(self, serial: str) -> dict:
        """Extract list of installed third-party apps."""
        out, err, rc = _run_adb_shell(serial, "pm list packages -3 -f", timeout=30)
        records = []
        for line in out.strip().split("\n"):
            line = line.strip()
            if line.startswith("package:"):
                # Format: package:/path/to/app.apk=com.package.name
                match = re.match(r"package:(.+)=(.+)", line)
                if match:
                    apk_path, pkg = match.group(1), match.group(2)
                    records.append({
                        "id": pkg,
                        "package": pkg,
                        "name": pkg.split(".")[-1].title(),
                        "apk_path": apk_path,
                        "installed_at": "",
                        "version": "",
                        "permissions": [],
                        "suspicious": _is_suspicious_package(pkg),
                        "category": _categorize_package(pkg),
                    })
        return {"success": True, "records": records, "count": len(records)}

    def extract_gps_data(self, serial: str) -> dict:
        """Try to get last known GPS location from Android settings."""
        # Try reading from settings or location providers
        out, err, rc = _run_adb_shell(
            serial, "dumpsys location | grep -A5 'Last Known Locations'", timeout=15
        )
        records = []
        if out and "last known" in out.lower():
            lat_match = re.search(r"lat=([0-9.\-]+)", out)
            lng_match = re.search(r"lng=([0-9.\-]+)", out)
            if lat_match and lng_match:
                records.append({
                    "id": "gps-live-1",
                    "latitude": float(lat_match.group(1)),
                    "longitude": float(lng_match.group(1)),
                    "place": "Last Known Location (ADB)",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "accuracy_m": 0,
                    "provider": "GPS",
                })
        return {
            "success": True,
            "records": records,
            "count": len(records),
            "note": "GPS data limited without root access. Only last known location may be available.",
        }

    def extract_media_files(self, serial: str) -> dict:
        """List media files from DCIM, Pictures, Downloads directories."""
        dirs = ["/sdcard/DCIM/Camera", "/sdcard/Pictures", "/sdcard/Downloads", "/sdcard/Documents"]
        records = []
        for d in dirs:
            out, err, rc = _run_adb_shell(serial, f"ls -la {d}", timeout=15)
            if rc == 0 and out:
                for line in out.split("\n"):
                    parts = line.split()
                    if len(parts) >= 8:
                        filename = parts[-1]
                        if any(filename.lower().endswith(ext) for ext in
                               [".jpg", ".jpeg", ".png", ".mp4", ".avi", ".pdf", ".txt", ".m4a", ".mp3"]):
                            size_str = parts[4] if len(parts) > 4 else "0"
                            try:
                                size_kb = int(size_str) // 1024
                            except Exception:
                                size_kb = 0
                            records.append({
                                "id": f"media-{len(records)+1}",
                                "filename": filename,
                                "path": f"{d}/{filename}",
                                "size_kb": size_kb,
                                "type": _guess_media_type(filename),
                                "created_at": datetime.now(timezone.utc).isoformat(),
                            })
        return {"success": True, "records": records, "count": len(records)}

    def extract_browser_history(self, serial: str) -> dict:
        """Attempt to extract Chrome browser history via ADB."""
        # Chrome history DB (requires root or backup extraction)
        out, err, rc = _run_adb_shell(
            serial,
            "content query --uri content://com.android.browser.home/res",
            timeout=15,
        )
        return {
            "success": False,
            "records": [],
            "count": 0,
            "note": "Browser history requires root access or ADB backup extraction on Android 10+. "
                    "Use ADB backup method or Autopsy for full browser history extraction.",
        }


def _parse_content_query(output: str, record_type: str) -> list:
    """Parse ADB content query output into list of dicts."""
    records = []
    if not output or "No result found" in output:
        return records

    current = {}
    for line in output.strip().split("\n"):
        line = line.strip()
        if line.startswith("Row:"):
            if current:
                records.append(current)
            current = {"id": str(len(records) + 1)}
        elif "=" in line and current is not None:
            # Format: key=value, or key=NULL
            eq_idx = line.find("=")
            if eq_idx > 0:
                k = line[:eq_idx].strip().strip(",")
                v = line[eq_idx + 1:].strip()
                current[k] = None if v == "NULL" else v
    if current and "id" in current:
        records.append(current)
    return records


def _is_suspicious_package(pkg: str) -> bool:
    """Flag known anti-forensic or high-risk packages."""
    suspicious_patterns = [
        "torproject", "wickr", "ishredder", "protectstar", "exodus",
        "mywickr", "securesms", "encryptedphone", "privacyguard",
        "nethunter", "termux", "superuser", "magisk",
    ]
    return any(p in pkg.lower() for p in suspicious_patterns)


def _categorize_package(pkg: str) -> str:
    """Categorize an app by its package name."""
    if any(p in pkg for p in ["chrome", "firefox", "opera", "browser"]):
        return "Browser"
    if any(p in pkg for p in ["telegram", "whatsapp", "signal", "wickr", "messenger"]):
        return "Communication"
    if any(p in pkg for p in ["torproject", "orbot", "vpn", "proxy"]):
        return "Privacy / Anti-Forensic"
    if any(p in pkg for p in ["shredder", "cleaner", "eraser", "protectstar"]):
        return "Privacy / Anti-Forensic"
    if any(p in pkg for p in ["bitcoin", "crypto", "wallet", "exodus", "coinbase"]):
        return "Finance / Crypto"
    return "Other"


def _guess_media_type(filename: str) -> str:
    ext = filename.lower().split(".")[-1]
    if ext in ["jpg", "jpeg", "png", "gif", "bmp", "webp", "heic"]:
        return "photo"
    if ext in ["mp4", "avi", "mov", "mkv", "3gp"]:
        return "video"
    if ext in ["mp3", "m4a", "wav", "aac", "ogg"]:
        return "audio"
    return "document"


def load_sample_data() -> dict:
    """Return the standard sample Android forensic dataset for testing."""
    return {
        "investigation": {
            "id": "inv-sample-001",
            "case_number": "MFIS-2026-0042",
            "title": "Operation Nighthawk – Android Device Forensic Investigation",
            "investigator": "Forensic Analyst",
            "agency": "Digital Forensics Unit",
            "description": "Investigation of suspected data exfiltration and evidence tampering on Android device.",
            "status": "active",
            "suspect": "Subject Alpha (device owner)",
        },
        "device": {
            "id": "dev-android-01",
            "model": "Samsung Galaxy S23",
            "manufacturer": "Samsung",
            "os_version": "14 (One UI 6.1)",
            "api_level": 34,
            "serial": "R58N90ABCD1",
            "imei": "356938035643809",
            "phone_number": "+1-415-555-0100",
            "acquisition_method": "ADB",
            "status": "acquired",
            "storage_info": "184.2 GB / 256 GB",
            "battery_level": 67,
            "usb_debugging": True,
            "data_source": "sample-data",
        },
        "sms": [
            {"id": "s1", "direction": "in", "contact": "Kai M.", "number": "+1-415-555-0132",
             "timestamp": "2026-10-30T22:14:00Z", "body": "did you get the drop? use the encrypted channel next time", "read_status": 1},
            {"id": "s2", "direction": "out", "contact": "Kai M.", "number": "+1-415-555-0132",
             "timestamp": "2026-10-30T22:17:00Z", "body": "yeah wallet address confirmed. burn the phone after", "read_status": 1},
            {"id": "s3", "direction": "in", "contact": "Mom", "number": "+1-408-555-0199",
             "timestamp": "2026-10-31T08:02:00Z", "body": "don't forget lunch on sunday <3", "read_status": 1},
            {"id": "s4", "direction": "out", "contact": "Unknown (+44)", "number": "+44-20-7946-0812",
             "timestamp": "2026-10-31T02:41:00Z", "body": "transfer 0.6 BTC to the cold wallet tonight", "read_status": 1},
            {"id": "s5", "direction": "in", "contact": "Bank Alert", "number": "26426",
             "timestamp": "2026-11-01T09:15:00Z", "body": "Your OTP is 481932. Do not share.", "read_status": 1},
            {"id": "s6", "direction": "in", "contact": "Kai M.", "number": "+1-415-555-0132",
             "timestamp": "2026-11-01T01:04:00Z", "body": "delete the logs and wipe the sd card", "read_status": 0},
            {"id": "s7", "direction": "out", "contact": "Alex", "number": "+1-650-555-0177",
             "timestamp": "2026-10-29T18:30:00Z", "body": "grabbing coffee at 5, cool?", "read_status": 1},
            {"id": "s8", "direction": "in", "contact": "Unknown (+7)", "number": "+7-495-555-0143",
             "timestamp": "2026-10-30T23:55:00Z", "body": "btc mixer confirmed, use channel 4", "read_status": 0},
        ],
        "calls": [
            {"id": "c1", "type": "outgoing", "contact": "Kai M.", "number": "+1-415-555-0132",
             "timestamp": "2026-10-30T22:20:00Z", "duration_sec": 412},
            {"id": "c2", "type": "incoming", "contact": "Unknown (+44)", "number": "+44-20-7946-0812",
             "timestamp": "2026-10-31T02:38:00Z", "duration_sec": 187},
            {"id": "c3", "type": "missed", "contact": "Unknown (+7)", "number": "+7-495-555-0143",
             "timestamp": "2026-10-31T03:11:00Z", "duration_sec": 0},
            {"id": "c4", "type": "outgoing", "contact": "Mom", "number": "+1-408-555-0199",
             "timestamp": "2026-11-01T19:04:00Z", "duration_sec": 621},
            {"id": "c5", "type": "incoming", "contact": "Kai M.", "number": "+1-415-555-0132",
             "timestamp": "2026-10-31T01:12:00Z", "duration_sec": 89},
            {"id": "c6", "type": "rejected", "contact": "Unknown (+86)", "number": "+86-10-5551-0288",
             "timestamp": "2026-10-31T04:02:00Z", "duration_sec": 0},
        ],
        "contacts": [
            {"id": "con1", "name": "Kai M.", "number": "+1-415-555-0132", "email": "kai@protonmail.com"},
            {"id": "con2", "name": "Mom", "number": "+1-408-555-0199", "email": "mom@gmail.com"},
            {"id": "con3", "name": "Alex", "number": "+1-650-555-0177", "organization": "Tech Corp"},
            {"id": "con4", "name": "Work IT", "number": "+1-800-555-0100", "organization": "IT Department"},
            {"id": "con5", "name": "Dr. Patel", "number": "+1-408-555-0250", "organization": "Valley Medical"},
        ],
        "gps": [
            {"id": "g1", "latitude": 37.7749, "longitude": -122.4194, "place": "San Francisco – Financial District",
             "timestamp": "2026-10-30T21:44:00Z", "accuracy_m": 8, "provider": "GPS"},
            {"id": "g2", "latitude": 37.7599, "longitude": -122.4148, "place": "Mission District – 16th & Valencia",
             "timestamp": "2026-10-30T22:12:00Z", "accuracy_m": 12, "provider": "GPS"},
            {"id": "g3", "latitude": 37.7286, "longitude": -122.4756, "place": "Ocean Beach – Parking Lot 4",
             "timestamp": "2026-10-31T02:35:00Z", "accuracy_m": 6, "provider": "GPS"},
            {"id": "g4", "latitude": 37.6213, "longitude": -122.379, "place": "SFO Airport – Terminal 2",
             "timestamp": "2026-10-31T04:18:00Z", "accuracy_m": 5, "provider": "GPS"},
            {"id": "g5", "latitude": 37.4419, "longitude": -122.143, "place": "Palo Alto – Home Address",
             "timestamp": "2026-11-01T18:02:00Z", "accuracy_m": 10, "provider": "network"},
        ],
        "browser": [
            {"id": "b1", "title": "How to wipe Android securely", "url": "https://forums.xda-developers.com/wipe-guide",
             "timestamp": "2026-11-01T23:11:00Z", "visits": 4, "browser": "Chrome"},
            {"id": "b2", "title": "Bitcoin mixing services 2026", "url": "https://darkforum.onion/mixers",
             "timestamp": "2026-10-30T20:44:00Z", "visits": 7, "browser": "Tor Browser"},
            {"id": "b3", "title": "Weather – SFGate", "url": "https://sfgate.com/weather",
             "timestamp": "2026-10-29T09:12:00Z", "visits": 2, "browser": "Chrome"},
            {"id": "b4", "title": "ProtonMail login", "url": "https://mail.proton.me/login",
             "timestamp": "2026-10-31T02:02:00Z", "visits": 12, "browser": "Chrome"},
            {"id": "b5", "title": "Signal – Secure Messenger Download", "url": "https://signal.org/download",
             "timestamp": "2026-10-28T15:22:00Z", "visits": 1, "browser": "Chrome"},
            {"id": "b6", "title": "Cold wallet setup guide", "url": "https://coldcard.com/docs/quick-start",
             "timestamp": "2026-10-30T19:30:00Z", "visits": 3, "browser": "Chrome"},
        ],
        "apps": [
            {"id": "a1", "name": "Signal", "package": "org.thoughtcrime.securesms",
             "installed_at": "2026-10-28T15:24:00Z", "version": "6.45.3",
             "permissions": ["contacts", "sms", "camera", "mic", "storage"], "suspicious": False, "category": "Communication"},
            {"id": "a2", "name": "Telegram", "package": "org.telegram.messenger",
             "installed_at": "2026-06-10T11:00:00Z", "version": "10.12.1",
             "permissions": ["contacts", "storage", "mic", "camera"], "suspicious": False, "category": "Communication"},
            {"id": "a3", "name": "Orbot: Tor for Android", "package": "org.torproject.android",
             "installed_at": "2026-10-29T02:14:00Z", "version": "16.6.3",
             "permissions": ["network", "boot"], "suspicious": True, "category": "Privacy / Anti-Forensic"},
            {"id": "a4", "name": "Wickr Me", "package": "com.mywickr.wickr2",
             "installed_at": "2026-10-29T02:20:00Z", "version": "5.111.0",
             "permissions": ["contacts", "mic", "camera", "storage"], "suspicious": True, "category": "Privacy / Anti-Forensic"},
            {"id": "a5", "name": "iShredder Professional", "package": "com.protectstar.ishredder",
             "installed_at": "2026-11-01T22:50:00Z", "version": "7.2.0",
             "permissions": ["storage", "admin"], "suspicious": True, "category": "Privacy / Anti-Forensic"},
            {"id": "a6", "name": "Google Chrome", "package": "com.android.chrome",
             "installed_at": "2024-01-14T08:00:00Z", "version": "120.0.6099.230",
             "permissions": ["network", "location", "storage"], "suspicious": False, "category": "Browser"},
            {"id": "a7", "name": "Exodus Crypto Wallet", "package": "exodusmovement.exodus",
             "installed_at": "2026-10-28T20:10:00Z", "version": "24.8.9",
             "permissions": ["network", "biometrics", "camera"], "suspicious": True, "category": "Finance / Crypto"},
        ],
        "media": [
            {"id": "m1", "type": "photo", "filename": "IMG_20261030_2201.jpg", "size_kb": 3421,
             "created_at": "2026-10-30T22:01:00Z", "path": "/sdcard/DCIM/Camera/IMG_20261030_2201.jpg"},
            {"id": "m2", "type": "photo", "filename": "IMG_20261031_0233.jpg", "size_kb": 2988,
             "created_at": "2026-10-31T02:33:00Z", "path": "/sdcard/DCIM/Camera/IMG_20261031_0233.jpg"},
            {"id": "m3", "type": "video", "filename": "VID_20261031_0240.mp4", "size_kb": 41220,
             "created_at": "2026-10-31T02:40:00Z", "path": "/sdcard/DCIM/Camera/VID_20261031_0240.mp4"},
            {"id": "m4", "type": "document", "filename": "wallet_backup.txt", "size_kb": 4,
             "created_at": "2026-10-30T21:12:00Z", "path": "/sdcard/Documents/wallet_backup.txt"},
            {"id": "m5", "type": "document", "filename": "meeting_notes.pdf", "size_kb": 218,
             "created_at": "2026-10-29T14:00:00Z", "path": "/sdcard/Documents/meeting_notes.pdf"},
            {"id": "m6", "type": "audio", "filename": "voice_memo_1031.m4a", "size_kb": 890,
             "created_at": "2026-10-31T03:05:00Z", "path": "/sdcard/Recordings/voice_memo_1031.m4a"},
        ],
    }
