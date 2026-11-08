"""
2_📁_Case_Management.py - Case Creation, Selection & Lifecycle Management
"""

import streamlit as st
import pandas as pd
from modules.database import create_case, list_cases, get_case, update_case_status, get_evidence_by_case, get_devices_by_case

st.set_page_config(page_title="Case Management", page_icon="📁", layout="wide")

st.title("📁 Investigation Case Management")
st.caption("Create, inspect, configure, and maintain custody of forensic investigation case files.")

tab1, tab2, tab3 = st.tabs(["Create New Case", "Existing Cases & Selection", "Case Dossier & History"])

# ─── TAB 1: CREATE NEW CASE ───────────────────────────────────────────────────
with tab1:
    st.subheader("Register New Forensic Investigation")
    with st.form("new_case_form"):
        case_name = st.text_input("Investigation Case Name *", placeholder="e.g., Operation Nighthawk - Exfiltration Probe")
        description = st.text_area("Case Description & Objectives", placeholder="Detail the legal scope, suspect identifiers, and acquisition authorization...")
        
        submitted = st.form_submit_button("Create Case File", use_container_width=True)
        if submitted:
            if not case_name.strip():
                st.error("Case name is required.")
            else:
                new_c = create_case(case_name=case_name.strip(), description=description.strip())
                st.success(f"Case successfully initialized: {new_c['case_id']}")
                st.session_state["active_case_id"] = new_c["case_id"]
                st.rerun()

# ─── TAB 2: EXISTING CASES ───────────────────────────────────────────────────
with tab2:
    st.subheader("All Registered Cases")
    all_cases = list_cases()
    if all_cases:
        df_cases = pd.DataFrame(all_cases)[["case_id", "case_name", "created_at", "case_status", "description"]]
        df_cases.columns = ["Case ID", "Case Name", "Created Date", "Status", "Description"]
        st.dataframe(df_cases, use_container_width=True, hide_index=True)

        st.divider()
        st.subheader("Switch Active Case")
        target_case = st.selectbox(
            "Select Case to Open",
            options=[c["case_id"] for c in all_cases],
            format_func=lambda cid: f"{cid} - {[c['case_name'] for c in all_cases if c['case_id'] == cid][0]}"
        )
        if st.button("Set as Active Case"):
            st.session_state["active_case_id"] = target_case
            st.success(f"Active case switched to {target_case}")
            st.rerun()
    else:
        st.info("No cases created yet.")

# ─── TAB 3: CASE DOSSIER ─────────────────────────────────────────────────────
with tab3:
    active_cid = st.session_state.get("active_case_id")
    if active_cid:
        c_data = get_case(active_cid)
        if c_data:
            st.subheader(f"Case Dossier: {c_data['case_name']}")
            
            col_a, col_b = st.columns(2)
            with col_a:
                st.write(f"**Case ID:** `{c_data['case_id']}`")
                st.write(f"**Created At:** {c_data['created_at']}")
                st.write(f"**Status:** {c_data['case_status']}")
            with col_b:
                new_st = st.selectbox("Update Case Status", ["ACTIVE", "CLOSED", "PENDING_LEGAL_REVIEW", "ARCHIVED"], index=["ACTIVE", "CLOSED", "PENDING_LEGAL_REVIEW", "ARCHIVED"].index(c_data["case_status"]) if c_data["case_status"] in ["ACTIVE", "CLOSED", "PENDING_LEGAL_REVIEW", "ARCHIVED"] else 0)
                if st.button("Update Status"):
                    update_case_status(active_cid, new_st)
                    st.success("Status updated.")
                    st.rerun()

            st.write(f"**Description:** {c_data.get('description', '')}")

            st.divider()
            d_list = get_devices_by_case(active_cid)
            st.write(f"**Associated Devices ({len(d_list)}):**")
            if d_list:
                st.dataframe(pd.DataFrame(d_list)[["device_identifier", "model", "manufacturer", "android_version", "connection_status"]], use_container_width=True, hide_index=True)

            e_list = get_evidence_by_case(active_cid)
            st.write(f"**Associated Evidence Files ({len(e_list)}):**")
            if e_list:
                st.dataframe(pd.DataFrame(e_list)[["evidence_id", "filename", "evidence_type", "file_size", "sha256_hash", "acquisition_method"]], use_container_width=True, hide_index=True)
    else:
        st.info("Select an active case to view dossier.")

