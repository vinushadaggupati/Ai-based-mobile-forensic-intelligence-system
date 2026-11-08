"""
4_📥_Evidence_Acquisition.py - Three-Option Evidence Ingestion Engine
Option A: Android ADB Logical Acquisition
Option B: Laptop Multiple-File Upload
Option C: Mobile Transferred File Import
"""

import streamlit as st
import pandas as pd
from datetime import datetime

from modules.adb_manager import (
    detect_connected_devices,
    check_adb_installed,
    get_adb_path,
    get_device_detailed_profile
)
from modules.evidence_acquisition import acquire_android_adb_evidence
from modules.file_upload import process_uploaded_files
from modules.database import get_case, get_evidence_by_case, register_device
from modules.forensic_analyzer import run_full_case_analysis

st.set_page_config(page_title="Evidence Acquisition", page_icon="📥", layout="wide")

case_id = st.session_state.get("active_case_id")
if not case_id:
    st.warning("⚠️ Please select or create an active investigation case before acquiring evidence.")
    st.stop()

case_info = get_case(case_id) or {}
st.title("📥 Forensic Evidence Acquisition")
st.caption(f"Active Case: **{case_info.get('case_name')}** (`{case_id}`)")

opt_tab1, opt_tab2, opt_tab3 = st.tabs([
    "Option A: Android Connection (ADB)",
    "Option B: Upload Evidence from Laptop",
    "Option C: Import Evidence Transferred from Mobile"
])

# ─── OPTION A: ADB ACQUISITION ────────────────────────────────────────────────
with opt_tab1:
    st.subheader("Option A: Live Android Extraction via ADB")
    st.caption("Acquires authorized device profiles, installed package lists, diagnostic logcat, and accessible storage artifacts directly from physical Android devices.")

    adb_ok, adb_msg = check_adb_installed()
    if not adb_ok:
        st.error(f"❌ ADB Error: {adb_msg}")
        st.info("Please configure ADB path in the 'Connect Android Device' page.")
    else:
        col_hdr1, col_hdr2 = st.columns([4, 1])
        with col_hdr1:
            st.caption(f"Using ADB Binary: `{get_adb_path()}`")
        with col_hdr2:
            if st.button("🔄 Refresh Devices", use_container_width=True, key="opt_a_refresh"):
                st.rerun()

        devices = detect_connected_devices()
        if not devices:
            st.info("ℹ️ No Android devices currently attached via USB. Connect device with USB Debugging enabled, then click **'🔄 Refresh Devices'**.")
            st.markdown("""
            **Troubleshooting Connection:**
            - Verify phone screen is unlocked.
            - Ensure **USB Debugging** is toggled ON under Developer Options.
            - Set USB mode to **File Transfer / MTP** (not Charge Only).
            - Accept the **'Allow USB debugging'** prompt on the phone screen.
            """)
        else:
            # Display summary table of detected devices
            d_table = []
            for d in devices:
                d_table.append({
                    "Device ID (Serial)": d["serial"],
                    "Model": d["model"],
                    "Manufacturer": d["manufacturer"],
                    "Android Version": d["android_version"],
                    "API Level": d["api_level"],
                    "Status": d["status"],
                    "Authorized": "✅ YES" if d["is_authorized"] else "⚠️ PENDING"
                })
            st.dataframe(pd.DataFrame(d_table), use_container_width=True, hide_index=True)

            auth_devices = [d for d in devices if d["is_authorized"]]
            if not auth_devices:
                st.warning("⚠️ Connected device is **UNAUTHORIZED**. Please accept the USB debugging authorization prompt on your phone screen and click '🔄 Refresh Devices'.")
            else:
                target_serial = st.selectbox(
                    "Select Target Android Device for Forensic Acquisition",
                    options=[d["serial"] for d in auth_devices],
                    format_func=lambda s: f"{s} - {[d['manufacturer'] for d in auth_devices if d['serial'] == s][0]} {[d['model'] for d in auth_devices if d['serial'] == s][0]} (Android {[d['android_version'] for d in auth_devices if d['serial'] == s][0]})",
                    key="sel_target_adb"
                )

                chosen_dev = [d for d in auth_devices if d["serial"] == target_serial][0]

                # Connection card
                with st.container():
                    st.markdown(
                        f"""
                        <div style="background-color: #0f172a; border-left: 4px solid #10b981; padding: 12px; border-radius: 6px; margin-bottom: 12px;">
                            <strong>Ready for Acquisition:</strong> {chosen_dev['manufacturer']} {chosen_dev['model']} | 
                            <strong>Serial:</strong> <code>{chosen_dev['serial']}</code> | 
                            <strong>OS:</strong> Android {chosen_dev['android_version']} (API {chosen_dev['api_level']}) | 
                            <strong>Status:</strong> <span style="color: #10b981;">{chosen_dev['status']}</span>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )

                c_conn_btn, c_acq_btn = st.columns([1, 2])
                with c_conn_btn:
                    if st.button("⚡ Connect Device to Case", use_container_width=True, key="opt_a_connect_btn"):
                        reg = register_device(
                            case_id=case_id,
                            device_identifier=target_serial,
                            model=chosen_dev["model"],
                            manufacturer=chosen_dev["manufacturer"],
                            android_version=chosen_dev["android_version"],
                            connection_status="CONNECTED"
                        )
                        st.success(f"Device registered to case as `{reg['device_id']}`!")

                st.write("**Select Forensic Acquisition Targets (Authorized Logical Extraction):**")
                col_c1, col_c2, col_c3 = st.columns(3)
                with col_c1:
                    c_prof = st.checkbox("Device Profile (`getprop`, `dumpsys`)", value=True, key="chk_prof")
                with col_c2:
                    c_pkgs = st.checkbox("Installed Applications (`pm list packages`)", value=True, key="chk_pkgs")
                with col_c3:
                    c_logs = st.checkbox("System Logcat Diagnostic Dump (5000 lines)", value=True, key="chk_logs")

                st.markdown("""
                <div style="background-color: #1e1b4b; border-left: 4px solid #818cf8; padding: 10px; margin: 10px 0; font-size: 12px; color: #e0e7ff;">
                    <strong>Forensic Standard Notice:</strong><br/>
                    Original evidence files will be written unmodified to <code>evidence_storage/{case_id}/</code>. 
                    Cryptographic SHA-256 hashes will be calculated on the binary stream immediately upon acquisition. 
                    An isolated duplicate working copy will be created in <code>working_copies/{case_id}/</code> for forensic examination.
                </div>
                """, unsafe_allow_html=True)

                if st.button("📥 Acquire Accessible Evidence", use_container_width=True, type="primary", key="btn_acquire_opt_a"):
                    prog_bar = st.progress(0)
                    status_placeholder = st.empty()
                    log_box = st.empty()
                    captured_logs = []

                    def on_progress(msg):
                        captured_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
                        log_box.code("\n".join(captured_logs), language="text")
                        status_placeholder.info(msg)

                    with st.spinner("Executing authorized logical acquisition over USB..."):
                        res = acquire_android_adb_evidence(
                            serial=target_serial,
                            case_id=case_id,
                            acquire_packages=c_pkgs,
                            acquire_device_profile=c_prof,
                            acquire_accessible_logs=c_logs,
                            progress_callback=on_progress
                        )
                    prog_bar.progress(100)
                    st.success(f"🎉 Acquisition Complete! {len(res['acquired_items'])} forensic items acquired and cryptographically verified.")

                    st.write("**Acquired Evidence Metadata & SHA-256 Hashes:**")
                    if res["acquired_items"]:
                        df_acq = pd.DataFrame(res["acquired_items"])[["evidence_id", "filename", "file_size", "sha256_hash", "acquisition_method", "stored_evidence_path"]]
                        df_acq.columns = ["Evidence ID", "Filename", "Size (Bytes)", "SHA-256 Hash", "Method", "Preserved Path"]
                        st.dataframe(df_acq, use_container_width=True, hide_index=True)

                    if res["failed_items"]:
                        with st.expander("ℹ️ Inaccessible Protected Artifacts (Documented Forensic Boundaries)"):
                            st.dataframe(pd.DataFrame(res["failed_items"]), use_container_width=True, hide_index=True)

                    # Seamless Next Actions
                    st.divider()
                    st.subheader("Proceed with Investigation:")
                    a1, a2, a3 = st.columns(3)
                    with a1:
                        if st.button("🔬 Run Forensic Analysis", use_container_width=True, key="opt_a_run_analysis"):
                            with st.spinner("Analyzing newly acquired evidence..."):
                                findings = run_full_case_analysis(case_id)
                                st.success(f"Discovered {len(findings)} findings!")
                                st.switch_page("pages/7_🔬_Forensic_Analysis.py")
                    with a2:
                        if st.button("🤖 Run AI Analysis (Ollama)", use_container_width=True, key="opt_a_run_ai"):
                            st.switch_page("pages/9_🤖_AI_Analysis.py")
                    with a3:
                        if st.button("📄 Generate 20-Section PDF Report", use_container_width=True, key="opt_a_run_rpt"):
                            st.switch_page("pages/11_📄_Report_Generation.py")

# ─── OPTION B: LAPTOP UPLOAD ──────────────────────────────────────────────────
with opt_tab2:
    st.subheader("Option B: Upload Evidence from Laptop")
    st.caption("Upload multiple evidence files directly from local workstation storage (TXT, CSV, JSON, XML, SQLITE, DB, LOG, ZIP, Images).")

    uploaded_files = st.file_uploader(
        "Choose Evidence Files to Ingest",
        accept_multiple_files=True,
        type=["txt", "csv", "json", "xml", "sqlite", "sqlite3", "db", "db3", "log", "zip", "jpg", "jpeg", "png", "mp4", "m4a", "pdf", "raw", "dd", "img", "e01"]
    )

    if uploaded_files:
        st.write(f"Selected **{len(uploaded_files)}** file(s) for forensic ingestion:")
        preview_data = [
            {"Filename": f.name, "Size (bytes)": len(f.getvalue()), "Size (KB)": round(len(f.getvalue()) / 1024, 2)}
            for f in uploaded_files
        ]
        st.dataframe(pd.DataFrame(preview_data), use_container_width=True, hide_index=True)

        if st.button("📥 Register & Hash Uploaded Files", use_container_width=True):
            with st.spinner("Writing to evidence_storage/ and calculating SHA-256 digests..."):
                saved = process_uploaded_files(
                    uploaded_files=uploaded_files,
                    case_id=case_id,
                    acquisition_method="LAPTOP_UPLOAD"
                )
            st.success(f"Successfully processed {len(saved)} evidence file(s) with SHA-256 hashes.")
            st.rerun()

# ─── OPTION C: MOBILE TRANSFERRED EXPORT ──────────────────────────────────────
with opt_tab3:
    st.subheader("Option C: Import Evidence Transferred from Mobile")
    st.caption("Ingest evidence files exported from Android devices via MTP / File Transfer mode.")

    st.markdown("""
    **Instructions for Manual Mobile File Transfer:**
    1. Connect your Android phone to the laptop using a USB cable.
    2. Swipe down from the top of the phone screen and tap the USB notification: **'Charging this device via USB'**.
    3. Under *'Use USB for'*, select **'File Transfer'** (MTP mode).
    4. On your PC, open Windows File Explorer to browse the phone's internal storage (e.g. `Download`, `Documents`, `DCIM`, `WhatsApp/Databases`).
    5. Copy the target evidence files onto your laptop.
    6. Select those transferred files below to upload and register them into this forensic case.
    """)

    mobile_files = st.file_uploader(
        "Select Mobile-Transferred Evidence Files",
        accept_multiple_files=True,
        key="mobile_upload_field"
    )

    if mobile_files:
        if st.button("📲 Ingest Mobile Exported Files", use_container_width=True):
            with st.spinner("Computing SHA-256 checksums and securing evidence copy..."):
                saved_m = process_uploaded_files(
                    uploaded_files=mobile_files,
                    case_id=case_id,
                    acquisition_method="MOBILE_MTP_EXPORT"
                )
            st.success(f"Ingested {len(saved_m)} mobile evidence artifact(s) into case.")
            st.rerun()
