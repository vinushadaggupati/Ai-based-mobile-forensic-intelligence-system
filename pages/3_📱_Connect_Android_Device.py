"""
3_📱_Connect_Android_Device.py - ADB Mobile Connection & Evidence Acquisition Workstation
Detects, connects, and acquires forensically sound evidence from physical Android devices via ADB.
"""

import streamlit as st
import pandas as pd
import os
import json
from datetime import datetime

from modules.adb_manager import (
    check_adb_installed,
    detect_connected_devices,
    get_adb_path,
    set_adb_path,
    restart_adb_server,
    connect_device_ip,
    get_device_detailed_profile,
    run_adb_command
)
from modules.evidence_acquisition import acquire_android_adb_evidence
from modules.database import (
    register_device,
    log_audit,
    get_case,
    get_devices_by_case,
    get_evidence_by_case
)
from modules.forensic_analyzer import run_full_case_analysis
from modules.report_generator import generate_pdf_report

st.set_page_config(page_title="Connect Android Device", page_icon="📱", layout="wide")

st.title("📱 Android Device Connection & Acquisition (ADB)")
st.caption("Inspect, authorize, establish forensic sessions, and acquire evidence from Android mobile devices.")

# Validate active case
case_id = st.session_state.get("active_case_id")
if not case_id:
    st.warning("⚠️ Please select or create an active investigation case before connecting devices.")
    st.stop()

case_info = get_case(case_id) or {}
st.info(f"📁 Active Investigation: **{case_info.get('case_name', 'Investigation Case')}** (`{case_id}`)")

# ─── SECTION 1: ADB CONFIGURATION & STATUS ────────────────────────────────────
st.subheader("1. Android Debug Bridge (ADB) Engine Status")

adb_installed, adb_msg = check_adb_installed()
current_adb_path = get_adb_path() or "Not Found"

col_adb1, col_adb2, col_adb3 = st.columns([3, 1, 1])

with col_adb1:
    if adb_installed:
        st.success(f"**ADB Engine Active:** {adb_msg}", icon="✅")
        st.caption(f"Configured Binary: `{current_adb_path}`")
    else:
        st.error(f"**ADB Not Found:** {adb_msg}", icon="❌")

with col_adb2:
    if st.button("🔄 Refresh ADB", use_container_width=True, key="btn_refresh_adb"):
        st.rerun()

with col_adb3:
    if st.button("⚡ Restart ADB Server", use_container_width=True, key="btn_restart_adb"):
        with st.spinner("Restarting ADB server daemon..."):
            ok, msg = restart_adb_server()
            if ok:
                st.success(msg)
            else:
                st.error(msg)
        st.rerun()

# ADB Path Customization Expander
with st.expander("⚙️ Configure ADB Binary Path"):
    st.write("If ADB is installed in a custom location, enter the path to `adb.exe` below:")
    new_adb_input = st.text_input("Full path to adb.exe:", value=current_adb_path if current_adb_path != "Not Found" else "")
    if st.button("Save & Validate ADB Path", key="btn_save_adb_path"):
        ok, v_msg = set_adb_path(new_adb_input)
        if ok:
            st.success(v_msg)
            st.rerun()
        else:
            st.error(v_msg)

st.divider()

# ─── SECTION 2: CONNECTED ANDROID DEVICES ─────────────────────────────────────
st.subheader("2. Attached Android Devices")

col_scan1, col_scan2 = st.columns([2, 5])
with col_scan1:
    refresh_clicked = st.button("🔄 Refresh Devices", use_container_width=True, type="primary", key="btn_refresh_devices")

# Run actual detection via Python subprocess
with st.spinner("Scanning for connected Android devices via ADB..."):
    devices = detect_connected_devices()

if devices:
    st.success(f"Found **{len(devices)}** device(s) attached via USB/ADB:")
    
    # Render table of detected hardware
    table_data = []
    for d in devices:
        table_data.append({
            "Device ID (Serial)": d["serial"],
            "Model": d["model"],
            "Manufacturer": d["manufacturer"],
            "Android OS": d["android_version"],
            "API Level": d["api_level"],
            "Security Patch": d["security_patch"],
            "Status": d["status"],
            "Authorized": "✅ YES" if d["is_authorized"] else "⚠️ PENDING AUTHORIZATION"
        })
    st.dataframe(pd.DataFrame(table_data), use_container_width=True, hide_index=True)

    # Device Selector
    selected_serial = st.selectbox(
        "Select Device for Forensic Operations",
        options=[d["serial"] for d in devices],
        format_func=lambda s: f"{s} - {[d['model'] for d in devices if d['serial'] == s][0]} ({[d['status'] for d in devices if d['serial'] == s][0]})",
        key="sel_device_serial"
    )

    selected_dev = [d for d in devices if d["serial"] == selected_serial][0]

    # Show Warning if unauthorized
    if not selected_dev["is_authorized"]:
        st.warning(
            "⚠️ **Device Authorization Required:**\n\n"
            "1. Unlock your phone screen.\n"
            "2. When prompted: **'Allow USB debugging?'**, check **'Always allow from this computer'** and tap **Allow**.\n"
            "3. If prompted for USB configuration, select **File Transfer / MTP** (not Charge Only).\n"
            "4. Then click **'🔄 Refresh Devices'** above."
        )
    else:
        # Authorized Device Operations
        st.subheader("3. Device Details & Forensic Acquisition")

        # Pull live detailed profile
        with st.spinner(f"Extracting live hardware telemetry from {selected_serial}..."):
            detailed_profile = get_device_detailed_profile(selected_serial)

        # Metric Tiles
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Device ID", selected_serial)
        m2.metric("Model / Brand", f"{detailed_profile.get('manufacturer')} {detailed_profile.get('model')}")
        m3.metric("Android Version", f"Android {detailed_profile.get('android_version')} (API {detailed_profile.get('sdk_api')})")
        m4.metric("Battery Level", detailed_profile.get('battery_level', 'Unknown'))

        with st.expander("📋 View Complete Device Hardware Profile", expanded=False):
            st.json(detailed_profile)

        # Action Buttons
        col_act1, col_act2 = st.columns(2)

        with col_act1:
            connect_btn = st.button("⚡ Connect Device (Register to Case)", use_container_width=True, key="btn_connect_dev")
            if connect_btn:
                with st.spinner("Registering device in SQLite forensic database..."):
                    reg = register_device(
                        case_id=case_id,
                        device_identifier=selected_serial,
                        model=detailed_profile.get("model", selected_dev["model"]),
                        manufacturer=detailed_profile.get("manufacturer", selected_dev["manufacturer"]),
                        android_version=detailed_profile.get("android_version", selected_dev["android_version"]),
                        connection_status="CONNECTED"
                    )
                    st.success(f"✅ Device registered in case `{case_id}` as `{reg['device_id']}`!")
                    st.session_state["connected_device_id"] = reg["device_id"]

        with col_act2:
            acquire_btn = st.button("📥 Acquire Accessible Evidence", use_container_width=True, type="primary", key="btn_acquire_ev")

        # Acquisition Execution
        if acquire_btn:
            st.markdown("### 📥 Live Evidence Acquisition Progress")
            progress_bar = st.progress(0)
            status_text = st.empty()
            log_container = st.empty()
            log_lines = []

            def progress_cb(msg: str):
                log_lines.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
                log_container.code("\n".join(log_lines), language="text")
                status_text.info(msg)

            with st.spinner("Extracting accessible forensic evidence over ADB..."):
                acq_results = acquire_android_adb_evidence(
                    serial=selected_serial,
                    case_id=case_id,
                    acquire_packages=True,
                    acquire_device_profile=True,
                    acquire_accessible_logs=True,
                    progress_callback=progress_cb
                )
                progress_bar.progress(100)

            st.success(f"🎉 Acquisition Completed! Acquired {len(acq_results['acquired_items'])} forensically preserved items.")

            # Display acquired items with SHA-256
            if acq_results["acquired_items"]:
                st.write("**Acquired Evidence Items & Cryptographic Hashes:**")
                ev_table = []
                for item in acq_results["acquired_items"]:
                    ev_table.append({
                        "Evidence ID": item["evidence_id"],
                        "Filename": item["filename"],
                        "Type": item["evidence_type"],
                        "Size (Bytes)": item["file_size"],
                        "SHA-256 Hash": item["sha256_hash"],
                        "Preserved Master Path": item["stored_evidence_path"],
                        "Working Copy Path": item.get("working_copy_path", "Created"),
                        "Method": item["acquisition_method"]
                    })
                st.dataframe(pd.DataFrame(ev_table), use_container_width=True, hide_index=True)

            # Display documented restrictions
            if acq_results.get("failed_items"):
                with st.expander("ℹ️ Documented Android Permission Boundaries & Restrictions"):
                    st.dataframe(pd.DataFrame(acq_results["failed_items"]), use_container_width=True, hide_index=True)

            # Quick follow-up actions
            st.divider()
            st.subheader("Next Investigation Steps:")
            nc1, nc2, nc3 = st.columns(3)
            with nc1:
                if st.button("🔬 Run Forensic Analysis Now", use_container_width=True):
                    with st.spinner("Running forensic rule engine on acquired evidence..."):
                        findings = run_full_case_analysis(case_id)
                        st.success(f"Identified {len(findings)} forensic findings!")
                        st.switch_page("pages/7_🔬_Forensic_Analysis.py")
            with nc2:
                if st.button("🤖 Run AI Analysis with Ollama", use_container_width=True):
                    st.switch_page("pages/9_🤖_AI_Analysis.py")
            with nc3:
                if st.button("📄 Generate 20-Section PDF Report", use_container_width=True):
                    st.switch_page("pages/11_📄_Report_Generation.py")

else:
    st.info("ℹ️ No Android devices currently detected via ADB.")
    
    # Live Subprocess Probe Output
    with st.expander("🔍 Live ADB Diagnostic Probe (Raw Subprocess Output)"):
        st.write("Raw output from `adb devices -l`:")
        ok, stdout, stderr = run_adb_command(["devices", "-l"])
        st.code(f"STDOUT:\n{stdout}\n\nSTDERR:\n{stderr}", language="text")

    # Wireless ADB Option
    with st.expander("📶 Connect via Wireless Debugging (IP:Port)"):
        col_ip, col_port, col_wbtn = st.columns([3, 1, 2])
        with col_ip:
            device_ip = st.text_input("Device IP Address:", placeholder="192.168.1.100")
        with col_port:
            device_port = st.number_input("Port:", min_value=1000, max_value=65535, value=5555)
        with col_wbtn:
            st.write("")
            st.write("")
            if st.button("Connect via Wi-Fi", use_container_width=True):
                if device_ip:
                    with st.spinner(f"Connecting to {device_ip}:{device_port}..."):
                        s_con, m_con = connect_device_ip(device_ip, int(device_port))
                        if s_con:
                            st.success(m_con)
                            st.rerun()
                        else:
                            st.error(m_con)
                else:
                    st.warning("Please enter device IP address.")

st.divider()

# Instructions Guide
with st.expander("ℹ️ Complete Guide: Enabling USB Debugging on Android Phones"):
    st.markdown("""
    ### Step-by-Step Instructions:
    1. **Unlock your phone** and open **Settings**.
    2. Scroll down and tap **About Phone** (or **About Device**).
    3. Tap **Build Number** continuously **7 times** until you see: *"You are now a developer!"*
    4. Go back to **Settings** → **System** (or **Additional Settings**) → **Developer Options**.
    5. Turn the **Developer Options** switch ON.
    6. Scroll down and enable **USB Debugging**.
    7. Connect the phone to this computer using a quality USB data cable.
    8. When the prompt appears on the phone screen:
       - Check the box: **"Always allow from this computer"**
       - Tap **Allow**
    9. On phone notification shade, set USB mode to **File Transfer / MTP** (not Charge Only).
    10. Click **"🔄 Refresh Devices"** above to detect the phone.
    """)
