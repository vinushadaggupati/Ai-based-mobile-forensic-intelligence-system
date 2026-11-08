"""
device_info.py - Detailed Android Device Profile Extraction
Gathers authorized forensic hardware and OS telemetry.
"""

from typing import Dict, Any
from modules.adb_manager import run_adb_command
import re


def get_android_device_profile(serial: str) -> Dict[str, Any]:
    """
    Retrieves system properties and hardware telemetry via ADB getprop and dumpsys.
    Does not violate device boundaries or require root access.
    """
    props: Dict[str, Any] = {
        "serial": serial,
        "manufacturer": "Unknown",
        "model": "Unknown",
        "brand": "Unknown",
        "android_version": "Unknown",
        "sdk_api_level": "Unknown",
        "security_patch": "Unknown",
        "build_fingerprint": "Unknown",
        "battery_level": "Unknown",
        "battery_health": "Unknown",
        "storage_internal": "Unknown",
        "usb_debugging": True,
        "is_rooted": False,
        "imei_accessible": False,
        "imei": "Restricted (Requires Privileged Carrier/Root Access on Android 10+)",
    }

    # Query getprop in batch
    success, stdout, _ = run_adb_command(["shell", "getprop"], serial=serial, timeout=10)
    if success and stdout:
        pattern = re.compile(r"\[(.*?)\]:\s*\[(.*?)\]")
        raw_props = dict(pattern.findall(stdout))

        props["manufacturer"] = raw_props.get("ro.product.manufacturer", raw_props.get("ro.product.brand", "Unknown")).title()
        props["model"] = raw_props.get("ro.product.model", "Unknown").replace("_", " ")
        props["brand"] = raw_props.get("ro.product.brand", "Unknown").title()
        props["android_version"] = raw_props.get("ro.build.version.release", "Unknown")
        props["sdk_api_level"] = raw_props.get("ro.build.version.sdk", "Unknown")
        props["security_patch"] = raw_props.get("ro.build.version.security_patch", "Unknown")
        props["build_fingerprint"] = raw_props.get("ro.build.fingerprint", "Unknown")

    # Battery info
    b_success, b_stdout, _ = run_adb_command(["shell", "dumpsys", "battery"], serial=serial, timeout=5)
    if b_success and b_stdout:
        lvl_m = re.search(r"level:\s*(\d+)", b_stdout)
        hlth_m = re.search(r"health:\s*(\d+)", b_stdout)
        if lvl_m:
            props["battery_level"] = f"{lvl_m.group(1)}%"
        health_codes = {"2": "Good", "3": "Overheat", "4": "Dead", "5": "Over Voltage", "7": "Cold"}
        if hlth_m:
            props["battery_health"] = health_codes.get(hlth_m.group(1), "Normal")

    # Storage partition df
    df_success, df_stdout, _ = run_adb_command(["shell", "df", "-h", "/sdcard"], serial=serial, timeout=5)
    if df_success and df_stdout:
        lines = df_stdout.strip().splitlines()
        if len(lines) > 1:
            props["storage_internal"] = lines[1].strip()

    # Check root presence
    su_success, su_stdout, _ = run_adb_command(["shell", "which", "su"], serial=serial, timeout=5)
    props["is_rooted"] = su_success and ("su" in su_stdout)

    return props

