"""
adb_manager.py - Android Debug Bridge (ADB) Forensic Acquisition Module
Controls actual USB-connected and Wi-Fi Android devices respecting platform boundaries.
Does not claim or attempt unauthorized security bypass.
"""

import subprocess
import shutil
import re
import os
import json
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(BASE_DIR, "adb_config.json")

# In-memory cache for resolved adb path
_RESOLVED_ADB_PATH: Optional[str] = None


def get_adb_path() -> Optional[str]:
    """
    Resolves the actual ADB executable on the system in priority order:
    1. Saved path in adb_config.json
    2. Environment variable ADB_PATH
    3. User Downloads platform-tools
    4. System PATH (shutil.which)
    5. Common Windows & Android Studio SDK install paths
    """
    global _RESOLVED_ADB_PATH
    if _RESOLVED_ADB_PATH and os.path.isfile(_RESOLVED_ADB_PATH):
        return _RESOLVED_ADB_PATH

    # 1. Check adb_config.json
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                custom_path = cfg.get("adb_path", "").strip()
                if custom_path and os.path.isfile(custom_path):
                    _RESOLVED_ADB_PATH = custom_path
                    return _RESOLVED_ADB_PATH
        except Exception:
            pass

    # 2. Check environment variable
    env_path = os.environ.get("ADB_PATH", "").strip()
    if env_path and os.path.isfile(env_path):
        _RESOLVED_ADB_PATH = env_path
        return _RESOLVED_ADB_PATH

    # 3. Known download locations on user's machine
    candidate_paths = [
        r"C:\Users\hp\Downloads\platform-tools-latest-windows\platform-tools\adb.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe"),
        os.path.expandvars(r"%USERPROFILE%\Downloads\platform-tools-latest-windows\platform-tools\adb.exe"),
        os.path.expandvars(r"%USERPROFILE%\Downloads\platform-tools\adb.exe"),
        r"C:\platform-tools\adb.exe",
        r"C:\Android\platform-tools\adb.exe",
        r"C:\adb\adb.exe",
        os.path.expandvars(r"%PROGRAMFILES%\Android\platform-tools\adb.exe"),
    ]
    for p in candidate_paths:
        if os.path.isfile(p):
            _RESOLVED_ADB_PATH = p
            save_adb_path(p)
            return _RESOLVED_ADB_PATH

    # 4. Check global PATH
    which_adb = shutil.which("adb")
    if which_adb and os.path.isfile(which_adb):
        _RESOLVED_ADB_PATH = which_adb
        save_adb_path(which_adb)
        return _RESOLVED_ADB_PATH

    return None


def save_adb_path(adb_path: str) -> bool:
    """Saves the verified ADB path to adb_config.json."""
    try:
        cfg = {}
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        cfg["adb_path"] = adb_path
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        return True
    except Exception:
        return False


def set_adb_path(new_path: str) -> Tuple[bool, str]:
    """Manually configure and validate a new ADB binary path."""
    global _RESOLVED_ADB_PATH
    clean_path = new_path.strip().strip('"').strip("'")
    if not os.path.isfile(clean_path):
        return False, f"File does not exist at: {clean_path}"

    try:
        proc = subprocess.run([clean_path, "version"], capture_output=True, text=True, timeout=5)
        if proc.returncode == 0:
            _RESOLVED_ADB_PATH = clean_path
            save_adb_path(clean_path)
            ver = proc.stdout.splitlines()[0] if proc.stdout else "ADB validated"
            return True, f"Success: {ver}"
        return False, f"Executable failed with code {proc.returncode}: {proc.stderr}"
    except Exception as e:
        return False, f"Error validating executable: {str(e)}"


def check_adb_installed() -> Tuple[bool, str]:
    """Checks if adb binary is available and returns (is_installed, version_str)."""
    adb_path = get_adb_path()
    if not adb_path:
        return False, "ADB not found. Please specify the path to adb.exe or install Android Platform Tools."

    try:
        proc = subprocess.run([adb_path, "version"], capture_output=True, text=True, timeout=5)
        if proc.returncode == 0:
            version_line = proc.stdout.splitlines()[0] if proc.stdout else "ADB installed"
            return True, f"{version_line} ({adb_path})"
        return False, f"ADB exited with code {proc.returncode}"
    except Exception as e:
        return False, str(e)


def run_adb_command(args: List[str], serial: Optional[str] = None, timeout: int = 30) -> Tuple[bool, str, str]:
    """
    Executes an authorized ADB command using the resolved executable.
    Returns: (success, stdout, stderr)
    """
    adb_path = get_adb_path()
    if not adb_path:
        return False, "", "ADB executable not found. Please configure adb.exe path."

    cmd = [adb_path]
    if serial:
        cmd += ["-s", serial]
    cmd += args

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace"
        )
        return (proc.returncode == 0, proc.stdout.strip(), proc.stderr.strip())
    except subprocess.TimeoutExpired:
        return False, "", f"Command timed out after {timeout}s: {' '.join(args)}"
    except FileNotFoundError:
        return False, "", f"Executable not found at: {adb_path}"
    except Exception as e:
        return False, "", str(e)


def restart_adb_server() -> Tuple[bool, str]:
    """Kills and restarts the local ADB server daemon."""
    adb_path = get_adb_path()
    if not adb_path:
        return False, "ADB path not configured"
    try:
        subprocess.run([adb_path, "kill-server"], capture_output=True, timeout=10)
        proc = subprocess.run([adb_path, "start-server"], capture_output=True, text=True, timeout=10)
        return (proc.returncode == 0, proc.stdout.strip() or "ADB server restarted")
    except Exception as e:
        return False, str(e)


def connect_device_ip(ip_address: str, port: int = 5555) -> Tuple[bool, str]:
    """Connects to an Android device over Wi-Fi (Wireless Debugging)."""
    target = f"{ip_address}:{port}"
    success, stdout, stderr = run_adb_command(["connect", target])
    output = stdout or stderr
    if "connected to" in output.lower():
        return True, output
    return False, output or "Failed to connect to device IP"


def disconnect_device(serial: str) -> Tuple[bool, str]:
    """Disconnects a device."""
    success, stdout, stderr = run_adb_command(["disconnect", serial])
    return success, stdout or stderr


def detect_connected_devices() -> List[Dict[str, Any]]:
    """
    Detects devices attached via USB or Wi-Fi.
    Parses 'adb devices -l' and queries live system properties for authorized devices.
    Returns structured list with verified hardware details.
    """
    is_installed, _ = check_adb_installed()
    if not is_installed:
        return []

    success, stdout, stderr = run_adb_command(["devices", "-l"])
    if not success or not stdout:
        return []

    devices = []
    lines = stdout.splitlines()
    for line in lines[1:]:  # Skip header 'List of devices attached'
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            serial = parts[0]
            raw_status = parts[1]

            # Parse metadata tokens (e.g., model:SM_G960F device:starqlte)
            meta = {}
            for part in parts[2:]:
                if ":" in part:
                    k, v = part.split(":", 1)
                    meta[k] = v

            status_desc = {
                "device": "AUTHORIZED (Online)",
                "unauthorized": "UNAUTHORIZED (Screen Locked / Allow USB Prompt Required)",
                "offline": "OFFLINE",
                "recovery": "RECOVERY MODE",
                "sideload": "SIDELOAD MODE",
            }.get(raw_status, raw_status.upper())

            is_auth = (raw_status == "device")
            model = meta.get("model", "Unknown").replace("_", " ")
            manufacturer = "Unknown"
            android_ver = "Unknown"
            api_level = "Unknown"
            security_patch = "Unknown"

            # If authorized, retrieve accurate live properties from the phone
            if is_auth:
                s_mod, out_mod, _ = run_adb_command(["shell", "getprop", "ro.product.model"], serial=serial, timeout=5)
                if s_mod and out_mod:
                    model = out_mod

                s_mfg, out_mfg, _ = run_adb_command(["shell", "getprop", "ro.product.manufacturer"], serial=serial, timeout=5)
                if s_mfg and out_mfg:
                    manufacturer = out_mfg.title()

                s_ver, out_ver, _ = run_adb_command(["shell", "getprop", "ro.build.version.release"], serial=serial, timeout=5)
                if s_ver and out_ver:
                    android_ver = out_ver

                s_sdk, out_sdk, _ = run_adb_command(["shell", "getprop", "ro.build.version.sdk"], serial=serial, timeout=5)
                if s_sdk and out_sdk:
                    api_level = out_sdk

                s_pat, out_pat, _ = run_adb_command(["shell", "getprop", "ro.build.version.security_patch"], serial=serial, timeout=5)
                if s_pat and out_pat:
                    security_patch = out_pat

            devices.append({
                "serial": serial,
                "raw_status": raw_status,
                "status": status_desc,
                "is_authorized": is_auth,
                "model": model,
                "manufacturer": manufacturer,
                "android_version": android_ver,
                "api_level": api_level,
                "security_patch": security_patch,
                "product": meta.get("product", "Unknown"),
                "device_code": meta.get("device", "Unknown"),
                "transport_id": meta.get("transport_id", ""),
            })

    return devices


def get_device_detailed_profile(serial: str) -> Dict[str, Any]:
    """Retrieves comprehensive hardware, battery, and storage profile for an authorized device."""
    profile: Dict[str, Any] = {
        "serial": serial,
        "model": "Unknown",
        "manufacturer": "Unknown",
        "android_version": "Unknown",
        "sdk_api": "Unknown",
        "build_fingerprint": "Unknown",
        "security_patch": "Unknown",
        "battery_level": "Unknown",
        "battery_status": "Unknown",
        "battery_health": "Unknown",
        "storage_sdcard": "Unknown",
        "is_rooted": False,
        "selinux_enforcing": "Unknown",
    }

    # 1. Properties
    _, stdout, _ = run_adb_command(["shell", "getprop"], serial=serial, timeout=10)
    for line in stdout.splitlines():
        if "[ro.product.model]:" in line:
            profile["model"] = line.split(":", 1)[1].strip(" []")
        elif "[ro.product.manufacturer]:" in line:
            profile["manufacturer"] = line.split(":", 1)[1].strip(" []").title()
        elif "[ro.build.version.release]:" in line:
            profile["android_version"] = line.split(":", 1)[1].strip(" []")
        elif "[ro.build.version.sdk]:" in line:
            profile["sdk_api"] = line.split(":", 1)[1].strip(" []")
        elif "[ro.build.fingerprint]:" in line:
            profile["build_fingerprint"] = line.split(":", 1)[1].strip(" []")
        elif "[ro.build.version.security_patch]:" in line:
            profile["security_patch"] = line.split(":", 1)[1].strip(" []")

    # 2. Battery
    _, b_out, _ = run_adb_command(["shell", "dumpsys", "battery"], serial=serial, timeout=5)
    for line in b_out.splitlines():
        line = line.strip()
        if line.startswith("level:"):
            profile["battery_level"] = line.split(":", 1)[1].strip() + "%"
        elif line.startswith("status:"):
            st_map = {"1": "Unknown", "2": "Charging", "3": "Discharging", "4": "Not Charging", "5": "Full"}
            val = line.split(":", 1)[1].strip()
            profile["battery_status"] = st_map.get(val, val)
        elif line.startswith("health:"):
            h_map = {"1": "Unknown", "2": "Good", "3": "Overheat", "4": "Dead", "5": "Over Voltage", "6": "Unspecified Failure", "7": "Cold"}
            val = line.split(":", 1)[1].strip()
            profile["battery_health"] = h_map.get(val, val)

    # 3. Storage
    _, df_out, _ = run_adb_command(["shell", "df", "-h", "/sdcard"], serial=serial, timeout=5)
    lines = df_out.splitlines()
    if len(lines) >= 2:
        profile["storage_sdcard"] = " ".join(lines[1].split())

    # 4. Root & SELinux status
    s_su, su_out, _ = run_adb_command(["shell", "which", "su"], serial=serial, timeout=5)
    profile["is_rooted"] = s_su and bool(su_out) and ("su" in su_out)

    s_se, se_out, _ = run_adb_command(["shell", "getenforce"], serial=serial, timeout=5)
    if s_se and se_out:
        profile["selinux_enforcing"] = se_out

    return profile
