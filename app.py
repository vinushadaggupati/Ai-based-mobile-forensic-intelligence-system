"""
app.py - AI-Based Mobile Forensic Intelligence System (MFIS)
Central Streamlit Application Entrypoint & Executive Dashboard
"""

import streamlit as st
import os
import sys

# Ensure modules package can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.database import init_db, list_cases, create_case, get_case, get_dashboard_metrics, add_evidence, register_device
from modules.adb_manager import check_adb_installed, detect_connected_devices
from modules.ollama_manager import check_ollama_status
from modules.hash_manager import calculate_file_sha256

st.set_page_config(
    page_title="AI-Based Mobile Forensic Intelligence System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize SQLite database
init_db()

# ─── SEED SAMPLE DATA IF DATABASE IS EMPTY ─────────────────────────────────────
def seed_sample_case_if_empty():
    cases = list_cases()
    if not cases:
        sample_case = create_case(
            case_name="Operation Nighthawk – Suspected Data Exfiltration",
            description="Android device investigation regarding unauthorized data transfer, cryptocurrency transactions, and anti-forensic wiping commands."
        )
        case_id = sample_case["case_id"]

        # Register target Android device
        dev = register_device(
            case_id=case_id,
            device_identifier="R58N90ABCD1",
            model="Galaxy S23",
            manufacturer="Samsung",
            android_version="14 (One UI 6.1)",
            connection_status="ACQUIRED"
        )

        # Seed sample evidence file
        sample_ev_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence_storage", case_id)
        os.makedirs(sample_ev_dir, exist_ok=True)
        sample_file_path = os.path.join(sample_ev_dir, "sample_telephony_dump.json")

        sample_content = {
            "case_id": case_id,
            "device": "Samsung Galaxy S23",
            "sms": [
                {"sender": "Kai M.", "body": "yeah wallet address confirmed. burn the phone after", "timestamp": "2026-10-30 22:17:00 UTC"},
                {"sender": "Kai M.", "body": "delete the logs and wipe the sd card before crossing border", "timestamp": "2026-11-01 01:04:00 UTC"},
                {"sender": "+44-20-7946-0812", "body": "transfer 0.6 BTC to the cold wallet tonight", "timestamp": "2026-10-31 02:41:00 UTC"},
                {"sender": "+7-495-555-0143", "body": "btc mixer confirmed, use channel 4", "timestamp": "2026-10-30 23:55:00 UTC"}
            ],
            "installed_packages": [
                "org.torproject.android", "com.protectstar.ishredder", "com.mywickr.wickr2", "exodusmovement.exodus"
            ],
            "gps_coordinates": [
                {"lat": 37.7749, "lng": -122.4194, "location": "Financial District"},
                {"lat": 37.7286, "lng": -122.4756, "location": "Ocean Beach Lot 4 (Rendezvous)"},
                {"lat": 37.6213, "lng": -122.3790, "location": "SFO Airport Terminal 2 (Departure)"}
            ]
        }
        import json
        with open(sample_file_path, "w", encoding="utf-8") as f:
            json.dump(sample_content, f, indent=2)

        file_size = os.path.getsize(sample_file_path)
        sha256_hash = calculate_file_sha256(sample_file_path)

        add_evidence(
            case_id=case_id,
            filename="sample_telephony_dump.json",
            evidence_type="JSON_DATA",
            original_filename="sample_telephony_dump.json",
            stored_evidence_path=sample_file_path,
            file_size=file_size,
            sha256_hash=sha256_hash,
            acquisition_method="ADB_LOGICAL_BACKUP",
            original_source_path="adb://R58N90ABCD1/sdcard/Download",
            device_id=dev["device_id"]
        )

seed_sample_case_if_empty()

# ─── SIDEBAR STATE MANAGEMENT ──────────────────────────────────────────────────
st.sidebar.title("🛡️ Forensic Intelligence")
st.sidebar.caption("Android Mobile Forensic System (MFIS)")

cases = list_cases()
case_options = {c["case_id"]: f"{c['case_id']} - {c['case_name'][:24]}..." for c in cases}

if "active_case_id" not in st.session_state:
    st.session_state["active_case_id"] = cases[0]["case_id"] if cases else None

selected_case = st.sidebar.selectbox(
    "Active Investigation Case",
    options=list(case_options.keys()),
    format_func=lambda x: case_options.get(x, x),
    index=0 if st.session_state["active_case_id"] in case_options else 0
)
st.session_state["active_case_id"] = selected_case

# Hardware and AI System Status indicators
st.sidebar.divider()
st.sidebar.subheader("System Status")

# ADB status
adb_installed, adb_msg = check_adb_installed()
if adb_installed:
    st.sidebar.success("ADB: Available", icon="🟢")
else:
    st.sidebar.warning("ADB: Not in PATH", icon="🟡")

# Ollama status
ollama_stat = check_ollama_status()
if ollama_stat["connected"]:
    st.sidebar.success(f"Ollama: Online ({ollama_stat['active_model']})", icon="🟢")
else:
    st.sidebar.warning("Ollama: Offline (Heuristic Mode)", icon="🟡")

st.sidebar.divider()
st.sidebar.info(
    "**Standards Compliance:**\n"
    "• NIST SP 800-101 Rev. 1\n"
    "• ISO/IEC 27037 Integrity\n"
    "• SHA-256 Non-Repudiation"
)

# ─── MAIN LANDING PAGE / DASHBOARD ─────────────────────────────────────────────
st.title("🛡️ AI-Based Mobile Forensic Intelligence System")
st.caption("Comprehensive digital forensics platform focusing exclusively on Android mobile devices.")

active_case = get_case(st.session_state["active_case_id"])
if active_case:
    st.markdown(f"""
    <div style="background-color: #0f172a; padding: 16px; border-radius: 8px; border: 1px solid #1e293b; margin-bottom: 20px;">
        <span style="color: #0284c7; font-weight: bold; font-size: 11px; text-transform: uppercase;">Active Case File</span>
        <h3 style="margin-top: 4px; margin-bottom: 4px; color: #f8fafc;">{active_case['case_name']}</h3>
        <span style="color: #94a3b8; font-size: 13px;">ID: <code style="color: #38bdf8;">{active_case['case_id']}</code> | Status: <strong style="color: #22c55e;">{active_case['case_status']}</strong> | Opened: {active_case['created_at']}</span>
        <p style="color: #cbd5e1; font-size: 12px; margin-top: 8px; margin-bottom: 0;">{active_case.get('description', '')}</p>
    </div>
    """, unsafe_allow_html=True)

# Dashboard Metrics Row
metrics = get_dashboard_metrics(st.session_state["active_case_id"])

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Total Cases", metrics["total_cases"])
col2.metric("Connected Devices", metrics["total_devices"])
col3.metric("Evidence Files", metrics["total_evidence"])
col4.metric("Analyzed Artifacts", metrics["total_analyzed"])
col5.metric("Reports Generated", metrics["total_reports"])

col6, col7, col8, col9, col10 = st.columns(5)
col6.metric("Integrity Verified", metrics["verified_count"], delta="SHA-256 Match")
col7.metric("Integrity Mismatches", metrics["mismatch_count"], delta="-Mismatch" if metrics["mismatch_count"] > 0 else "0", delta_color="inverse")
col8.metric("Confirmed Findings", metrics["confirmed_findings"], delta="Facts")
col9.metric("AI Observations", metrics["ai_observations"], delta="Inferences")
col10.metric("Possible Leads", metrics["possible_leads"], delta="Hypotheses")

st.divider()

# Quick Navigation Grid
st.subheader("Investigation Workflow Modules")
st.caption("Select any module from the sidebar or click below to proceed with the investigation.")

m1, m2, m3, m4 = st.columns(4)
with m1:
    st.markdown("#### 1. Case Management")
    st.write("Create, open, and review forensic investigation case files.")
    if st.button("Open Cases →", key="btn_m1"):
        st.switch_page("pages/2_📁_Case_Management.py")

with m2:
    st.markdown("#### 2. Device Connection")
    st.write("Scan USB devices and establish authorized ADB connection.")
    if st.button("Connect Device →", key="btn_m2"):
        st.switch_page("pages/3_📱_Connect_Android_Device.py")

with m3:
    st.markdown("#### 3. Evidence Acquisition")
    st.write("Acquire from ADB, upload laptop files, or import mobile data.")
    if st.button("Acquire Evidence →", key="btn_m3"):
        st.switch_page("pages/4_📥_Evidence_Acquisition.py")

with m4:
    st.markdown("#### 4. Integrity Verification")
    st.write("Recalculate and compare SHA-256 hashes against original content.")
    if st.button("Verify Integrity →", key="btn_m4"):
        st.switch_page("pages/6_🔒_Integrity_Verification.py")

m5, m6, m7, m8 = st.columns(4)
with m5:
    st.markdown("#### 5. Forensic Analysis")
    st.write("Execute rule-based heuristics across databases, logs, and keywords.")
    if st.button("Run Forensic Analysis →", key="btn_m5"):
        st.switch_page("pages/7_🔬_Forensic_Analysis.py")

with m6:
    st.markdown("#### 6. Database Inspection")
    st.write("Inspect SQLite tables, schemas, and freelist unallocated pages.")
    if st.button("Inspect SQLite →", key="btn_m6"):
        st.switch_page("pages/8_🗃️_SQLite_Database_Examination.py")

with m7:
    st.markdown("#### 7. Ollama AI Analysis")
    st.write("Generate local neural interpretations using Ollama Llama 3.2:3B.")
    if st.button("Launch AI Analyzer →", key="btn_m7"):
        st.switch_page("pages/9_🤖_AI_Analysis.py")

with m8:
    st.markdown("#### 8. Report Generation")
    st.write("Download court-admissible 20-section PDF, JSON, and CSV reports.")
    if st.button("Generate Reports →", key="btn_m8"):
        st.switch_page("pages/11_📄_Report_Generation.py")

st.divider()

# Recent Activity Audit Stream
st.subheader("Recent Investigation Activity")
recent_logs = metrics["recent_activity"]
if recent_logs:
    import pandas as pd
    df_logs = pd.DataFrame(recent_logs)[["timestamp", "action_performed", "status", "details"]]
    df_logs.columns = ["Timestamp (UTC)", "Action", "Status", "Details"]
    st.dataframe(df_logs, use_container_width=True, hide_index=True)
else:
    st.info("No activity logs recorded yet. Begin by acquiring evidence or running analysis.")

