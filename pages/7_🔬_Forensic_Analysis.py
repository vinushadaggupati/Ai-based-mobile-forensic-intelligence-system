"""
7_🔬_Forensic_Analysis.py - Rule-Based Digital Forensic Analysis Engine
Executes metadata analysis, keyword extraction, log anomaly checks, and pattern classification.
"""

import streamlit as st
import pandas as pd
from modules.database import get_case, get_evidence_by_case, get_analysis_results_by_case
from modules.forensic_analyzer import run_full_case_analysis, run_evidence_file_analysis

st.set_page_config(page_title="Forensic Analysis", page_icon="🔬", layout="wide")

case_id = st.session_state.get("active_case_id")
if not case_id:
    st.warning("Please select an active investigation case first.")
    st.stop()

case_info = get_case(case_id) or {}
st.title("🔬 Digital Forensic Analysis")
st.caption(f"Active Case: **{case_info.get('case_name')}** (`{case_id}`)")

evidence_list = get_evidence_by_case(case_id)
if not evidence_list:
    st.info("No evidence registered in this case. Ingest evidence files to begin analysis.")
    st.stop()

# Execution Controls
c_run, c_stats = st.columns([1, 2])
with c_run:
    if st.button("⚡ Execute Full Forensic Examination", use_container_width=True):
        with st.spinner("Analyzing working copies of evidence artifacts..."):
            new_findings = run_full_case_analysis(case_id)
        st.success(f"Forensic examination complete. Cataloged {len(new_findings)} findings.")
        st.rerun()

# Display Findings
findings = get_analysis_results_by_case(case_id)
st.subheader(f"Cataloged Forensic Findings ({len(findings)})")

if findings:
    # Filter by classification
    col_f1, col_f2 = st.columns(2)
    with col_f1:
        c_types = ["ALL"] + list(set(f["verification_status"] for f in findings))
        sel_c_type = st.selectbox("Filter by Forensic Classification", c_types)
    with col_f2:
        sevs = ["ALL"] + list(set(f["severity"] for f in findings))
        sel_sev = st.selectbox("Filter by Severity", sevs)

    filtered = findings
    if sel_c_type != "ALL":
        filtered = [f for f in filtered if f["verification_status"] == sel_c_type]
    if sel_sev != "ALL":
        filtered = [f for f in filtered if f["severity"] == sel_sev]

    df_findings = pd.DataFrame(filtered)[[
        "analysis_id", "evidence_id", "filename", "analysis_type",
        "finding_description", "severity", "verification_status", "timestamp"
    ]]
    df_findings.columns = [
        "Analysis ID", "Evidence ID", "Filename", "Category",
        "Finding Description", "Severity", "Classification", "Timestamp"
    ]
    st.dataframe(df_findings, use_container_width=True, hide_index=True)
else:
    st.info("No findings yet. Click 'Execute Full Forensic Examination' to run rule-based detectors.")

st.divider()

# Explainable Forensic Detection Rules Documentation
st.subheader("Explainable Forensic Rules & Methodology")
st.markdown("""
The system employs transparent, deterministically verifiable forensic rules:
1. **Anti-Forensics Instruction Rules:** Scans string payloads for direct device sanitization or evidence destruction directives (`burn the phone`, `wipe the sd card`, `delete the logs`).
2. **Cryptocurrency Asset Movement Rules:** Identifies unhosted cold wallet generation, transaction instructions (`BTC`), and mixer interaction.
3. **Application Security Profiling:** Cross-references installed packages with known anti-forensic tools (military-grade wipers like `iShredder`, anonymity proxies like `Orbot/Tor`, ephemeral messengers like `Wickr`).
4. **SQLite Structural Examination:** Evaluates database freelist counts and unallocated page headers for evidence of deleted row salvageability.
5. **Chromium Artifact Rules:** Flags darknet access (`.onion`) and sanitization knowledge base queries.
6. **Classification Standard:**
   - **CONFIRMED EVIDENCE:** Artifacts directly present in bitstreams and verified by hash.
   - **AI OBSERVATION:** Inferred behavioral patterns requiring human corroboration.
   - **POSSIBLE LEAD:** Hypotheses for ongoing investigation.
""")

