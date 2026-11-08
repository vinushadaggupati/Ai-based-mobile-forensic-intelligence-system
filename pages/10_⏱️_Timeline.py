"""
10_⏱️_Timeline.py - Chronological Investigation Timeline Reconstruction
Correlates evidence acquisition, communication events, and forensic findings chronologically.
"""

import streamlit as st
import pandas as pd
from modules.database import get_case, get_evidence_by_case, get_analysis_results_by_case, get_audit_logs

st.set_page_config(page_title="Investigation Timeline", page_icon="⏱️", layout="wide")

case_id = st.session_state.get("active_case_id")
if not case_id:
    st.warning("Please select an active investigation case first.")
    st.stop()

case_info = get_case(case_id) or {}
st.title("⏱️ Investigation Timeline Reconstruction")
st.caption(f"Chronological sequence of evidence acquisition, detected incidents, and examiner operations.")

# Build unified timeline events list
events = []

# Case creation
events.append({
    "Timestamp": case_info.get("created_at", ""),
    "Category": "CASE_LIFECYCLE",
    "Source": "System",
    "Description": f"Investigation Case Initiated: {case_info.get('case_name')}",
    "Severity": "INFO",
})

# Evidence Ingestion
evidence_list = get_evidence_by_case(case_id)
for ev in evidence_list:
    events.append({
        "Timestamp": ev["acquisition_timestamp"],
        "Category": "EVIDENCE_ACQUISITION",
        "Source": ev["filename"],
        "Description": f"Acquired evidence artifact: {ev['filename']} (SHA-256: {ev['sha256_hash'][:16]}... via {ev['acquisition_method']})",
        "Severity": "LOW",
    })

# Forensic Findings
findings = get_analysis_results_by_case(case_id)
for f in findings:
    events.append({
        "Timestamp": f["timestamp"],
        "Category": "FORENSIC_FINDING",
        "Source": f.get("filename", f["evidence_id"]),
        "Description": f"[{f['verification_status']}] {f['finding_description']}",
        "Severity": f["severity"],
    })

# Audit Logs
audits = get_audit_logs(case_id=case_id)
for a in audits:
    events.append({
        "Timestamp": a["timestamp"],
        "Category": "EXAMINER_ACTION",
        "Source": "Audit Trail",
        "Description": f"Action: {a['action_performed']} | Status: {a['status']} ({a.get('details', '')})",
        "Severity": "INFO",
    })

if events:
    # Sort chronologically
    events = sorted(events, key=lambda x: str(x.get("Timestamp", "")), reverse=True)
    df_timeline = pd.DataFrame(events)[["Timestamp", "Category", "Source", "Severity", "Description"]]
    
    st.subheader(f"Unified Forensic Timeline ({len(events)} Events)")
    st.dataframe(df_timeline, use_container_width=True, hide_index=True)
else:
    st.info("No timeline events recorded yet.")

