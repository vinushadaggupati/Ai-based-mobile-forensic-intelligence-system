"""
8_🗃️_SQLite_Database_Examination.py - Low-Level SQLite Structure & Freelist Inspector
Inspects tables, columns, schema definitions, and detects freelist deleted record pages.
"""

import streamlit as st
import pandas as pd
import os
from modules.database import get_case, get_evidence_by_case
from modules.sqlite_analyzer import inspect_sqlite_database, query_table_sample

st.set_page_config(page_title="SQLite Database Examination", page_icon="🗃️", layout="wide")

case_id = st.session_state.get("active_case_id")
if not case_id:
    st.warning("Please select an active investigation case first.")
    st.stop()

case_info = get_case(case_id) or {}
st.title("🗃️ SQLite Database Examination")
st.caption(f"Forensic structural inspection of Android SQLite databases (e.g., mmssms.db, contacts2.db, History).")

evidence_list = get_evidence_by_case(case_id)
sqlite_evidence = [e for e in evidence_list if "SQLITE" in e["evidence_type"] or e["filename"].endswith((".db", ".sqlite", ".sqlite3"))]

# Also allow inspecting internal database/forensic.db or any file
all_options = {e["evidence_id"]: f"{e['filename']} ({e['evidence_id']})" for e in sqlite_evidence}
all_options["INTERNAL_DB"] = "Internal Case Database (database/forensic.db)"

target_key = st.selectbox("Select SQLite Database to Examine", options=list(all_options.keys()), format_func=lambda k: all_options[k])

if target_key == "INTERNAL_DB":
    target_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "database", "forensic.db")
else:
    target_item = [e for e in sqlite_evidence if e["evidence_id"] == target_key][0]
    target_path = target_item["stored_evidence_path"]

if os.path.exists(target_path):
    report = inspect_sqlite_database(target_path)
    
    if not report.get("is_valid_sqlite"):
        st.error(f"File is not a valid SQLite database: {report.get('errors')}")
        st.stop()

    # Structural Telemetry Bar
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Database Format", "SQLite 3", delta="Valid Header")
    c2.metric("Page Size", f"{report.get('page_size')} bytes")
    c3.metric("Freelist Pages", report.get("freelist_count", 0), delta="Deleted Records" if report.get("freelist_count", 0) > 0 else "None", delta_color="inverse")
    c4.metric("User Tables", report.get("total_tables", 0))

    if report.get("freelist_count", 0) > 0:
        st.warning(
            f"⚠️ **Freelist Pages Detected ({report.get('freelist_count')}):** "
            "The database contains unallocated freelist blocks where deleted records may be carved using Autopsy or raw regex salvage tools."
        )

    st.divider()

    # Table Explorer
    tables_dict = report.get("tables", {})
    if tables_dict:
        selected_table = st.selectbox("Select Table to Explore", options=list(tables_dict.keys()), format_func=lambda t: f"{t} ({tables_dict[t]['row_count']} rows)")
        
        tbl_info = tables_dict[selected_table]
        st.write(f"**Schema Definition (`{selected_table}`):**")
        st.code(tbl_info["schema"], language="sql")

        st.write(f"**Sample Rows (First 50):**")
        rows = query_table_sample(target_path, selected_table, limit=50)
        if rows:
            st.dataframe(pd.DataFrame(rows), use_container_width=True)
        else:
            st.info("Table is currently empty.")
    else:
        st.info("Database contains no user tables.")
else:
    st.error(f"Database file not found at path: {target_path}")

