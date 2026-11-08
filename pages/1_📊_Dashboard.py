"""
1_📊_Dashboard.py - Executive Digital Forensic Dashboard
Visualizes case metrics, evidence categorization, severity charts, and integrity status.
"""

import streamlit as st
import pandas as pd
from modules.database import get_dashboard_metrics, get_case, get_evidence_by_case, get_analysis_results_by_case

st.set_page_config(page_title="Forensic Dashboard", page_icon="📊", layout="wide")

case_id = st.session_state.get("active_case_id")
if not case_id:
    st.warning("Please select or create an active investigation case first.")
    st.stop()

case_info = get_case(case_id) or {}
metrics = get_dashboard_metrics(case_id)

st.title("📊 Forensic Intelligence Dashboard")
st.caption(f"Active Case: {case_info.get('case_id')} · {case_info.get('case_name')}")

# KPI Row
k1, k2, k3, k4, k5 = st.columns(5)
k1.metric("Connected Devices", metrics["total_devices"])
k2.metric("Evidence Artifacts", metrics["total_evidence"])
k3.metric("Analyzed Items", metrics["total_analyzed"])
k4.metric("Confirmed Facts", metrics["confirmed_findings"])
k5.metric("Reports Generated", metrics["total_reports"])

st.divider()

# Charts & Breakdowns
c1, c2 = st.columns(2)

with c1:
    st.subheader("Evidence Artifact Distribution")
    evidence_items = get_evidence_by_case(case_id)
    if evidence_items:
        df_ev = pd.DataFrame(evidence_items)
        type_counts = df_ev["evidence_type"].value_counts().reset_index()
        type_counts.columns = ["Evidence Type", "Count"]
        st.bar_chart(type_counts.set_index("Evidence Type"), color="#0284c7")
    else:
        st.info("No evidence registered in this case yet.")

with c2:
    st.subheader("Findings by Classification")
    findings = get_analysis_results_by_case(case_id)
    if findings:
        df_f = pd.DataFrame(findings)
        class_counts = df_f["verification_status"].value_counts().reset_index()
        class_counts.columns = ["Classification", "Count"]
        st.bar_chart(class_counts.set_index("Classification"), color="#10b981")
    else:
        st.info("No analysis findings recorded yet.")

st.divider()

# Integrity & Audit Overview
col_left, col_right = st.columns([1, 1])

with col_left:
    st.subheader("SHA-256 Integrity Verification Status")
    st.metric("Integrity Verified", metrics["verified_count"], delta="Cryptographically Valid")
    st.metric("Integrity Mismatches", metrics["mismatch_count"], delta="Tamper Alert" if metrics["mismatch_count"] > 0 else "None", delta_color="inverse")
    st.caption("Hashes are computed from binary streams and verified against master acquisition records.")

with col_right:
    st.subheader("Recent Audit Trail")
    recent = metrics.get("recent_activity", [])
    if recent:
        df_recent = pd.DataFrame(recent)[["timestamp", "action_performed", "status", "details"]]
        df_recent.columns = ["Timestamp", "Action", "Status", "Details"]
        st.dataframe(df_recent, use_container_width=True, hide_index=True)
    else:
        st.write("No audit records available.")

