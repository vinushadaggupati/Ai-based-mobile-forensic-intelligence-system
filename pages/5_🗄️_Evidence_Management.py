"""
5_🗄️_Evidence_Management.py - Evidence Catalog, Metadata & Working Copies
"""

import streamlit as st
import pandas as pd
import os
from modules.database import get_case, get_evidence_by_case, list_all_evidence

st.set_page_config(page_title="Evidence Management", page_icon="🗄️", layout="wide")

st.title("🗄️ Evidence Management & Storage")
st.caption("Inspect preserved master evidence files, working copies, and cryptographic hash registries.")

case_id = st.session_state.get("active_case_id")
case_info = get_case(case_id) or {} if case_id else {}

filter_scope = st.radio("Display Scope", ["Current Case Only", "All Cases Across System"], horizontal=True)

if filter_scope == "Current Case Only" and case_id:
    evidence_list = get_evidence_by_case(case_id)
    st.info(f"Showing evidence for: **{case_info.get('case_name', 'Case')}** (`{case_id}`)")
else:
    evidence_list = list_all_evidence()
    st.info("Showing all evidence across all investigations in database.")

if not evidence_list:
    st.info("No evidence registered yet. Navigate to Evidence Acquisition to add artifacts.")
    st.stop()

# Filter options
col_f1, col_f2 = st.columns(2)
with col_f1:
    types = list(set(e["evidence_type"] for e in evidence_list))
    sel_type = st.multiselect("Filter by Evidence Type", types, default=types)
with col_f2:
    methods = list(set(e["acquisition_method"] for e in evidence_list))
    sel_method = st.multiselect("Filter by Acquisition Method", methods, default=methods)

filtered_evidence = [e for e in evidence_list if e["evidence_type"] in sel_type and e["acquisition_method"] in sel_method]

st.subheader(f"Evidence Inventory ({len(filtered_evidence)} Items)")

df_ev = pd.DataFrame(filtered_evidence)[[
    "evidence_id", "filename", "evidence_type", "file_size", "acquisition_method",
    "sha256_hash", "acquisition_timestamp"
]]
df_ev.columns = ["Evidence ID", "Filename", "Type", "Size (bytes)", "Method", "SHA-256 Hash", "Timestamp"]
st.dataframe(df_ev, use_container_width=True, hide_index=True)

st.divider()

# Evidence File Inspector
st.subheader("Inspect Stored Artifact Details")
ev_options = {e["evidence_id"]: f"{e['evidence_id']} - {e['filename']}" for e in filtered_evidence}
selected_ev_id = st.selectbox("Select Evidence Record to Inspect", options=list(ev_options.keys()), format_func=lambda x: ev_options[x])

if selected_ev_id:
    ev_item = [e for e in filtered_evidence if e["evidence_id"] == selected_ev_id][0]
    
    c_m1, c_m2 = st.columns(2)
    with c_m1:
        st.write(f"**Evidence ID:** `{ev_item['evidence_id']}`")
        st.write(f"**Original Name:** {ev_item['original_filename']}")
        st.write(f"**Acquisition Method:** {ev_item['acquisition_method']}")
        st.write(f"**Acquired At:** {ev_item['acquisition_timestamp']}")
    with c_m2:
        st.write(f"**File Size:** {ev_item['file_size']} bytes")
        st.write(f"**Stored Path:** `{ev_item['stored_evidence_path']}`")
        st.write(f"**SHA-256:** `{ev_item['sha256_hash']}`")

    # Preview content if text/json/csv
    file_p = ev_item["stored_evidence_path"]
    if os.path.exists(file_p):
        ext = os.path.splitext(file_p)[1].lower()
        if ext in [".txt", ".json", ".log", ".csv", ".xml"]:
            with st.expander("📄 View File Content Excerpt (First 10 KB)"):
                try:
                    with open(file_p, "r", encoding="utf-8", errors="replace") as f:
                        excerpt = f.read(10240)
                    st.code(excerpt, language="json" if ext == ".json" else "text")
                except Exception as ex:
                    st.error(f"Cannot display preview: {ex}")
    else:
        st.error(f"File missing on disk: {file_p}")

