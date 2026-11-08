"""
12_📋_Audit_Logs.py - Immutable Forensic Chain-of-Custody & Action Audit Trail
Records every case creation, device registration, acquisition, verification, and analysis.
"""

import streamlit as st
import pandas as pd
from modules.database import get_case, get_audit_logs

st.set_page_config(page_title="Audit Logs", page_icon="📋", layout="wide")

st.title("📋 Forensic Chain-of-Custody Audit Trail")
st.caption("Immutable system log of all examiner operations, integrity checks, and evidence access events.")

case_id = st.session_state.get("active_case_id")
case_info = get_case(case_id) or {} if case_id else {}

c_scope, c_lim = st.columns([2, 1])
with c_scope:
    filter_case = st.checkbox("Filter by Active Case Only", value=True if case_id else False)
with c_lim:
    log_limit = st.selectbox("Log Display Limit", [50, 100, 200, 500], index=1)

target_cid = case_id if filter_case else None
logs = get_audit_logs(case_id=target_cid, limit=log_limit)

if logs:
    df_logs = pd.DataFrame(logs)[["log_id", "timestamp", "action_performed", "status", "case_id", "evidence_id", "details"]]
    df_logs.columns = ["Log ID", "Timestamp (UTC)", "Action", "Status", "Case ID", "Evidence ID", "Details"]
    
    st.dataframe(df_logs, use_container_width=True, hide_index=True)

    csv_data = df_logs.to_csv(index=False).encode("utf-8")
    st.download_button(
        "⬇️ Export Audit Trail (CSV)",
        data=csv_data,
        file_name=f"Audit_Trail_{case_id or 'All'}.csv",
        mime="text/csv"
    )
else:
    st.info("No audit logs recorded for this selection.")

