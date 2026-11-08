"""routes/devices.py - ADB device management endpoints."""

from fastapi import APIRouter
from adb_manager import ADBManager

router = APIRouter()
adb = ADBManager()


@router.get("")
def list_devices():
    result = adb.list_devices()
    return result


@router.post("/connect")
def connect_device(body: dict):
    serial = body.get("serial", "")
    if not serial:
        return {"success": False, "error": "Serial number required"}
    info = adb.get_device_info(serial)
    return info


@router.post("/disconnect")
def disconnect_device(body: dict):
    serial = body.get("serial", "")
    return {"success": True, "message": f"Device {serial} disconnected"}


@router.post("/refresh")
def refresh_devices():
    result = adb.list_devices()
    return result


@router.get("/{serial}/info")
def get_device_info(serial: str):
    return adb.get_device_info(serial)

