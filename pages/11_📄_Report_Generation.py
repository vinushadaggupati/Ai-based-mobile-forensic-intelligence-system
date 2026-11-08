"""
11_📄_Report_Generation.py - Automated 20-Section Forensic Deliverables
Compiles and provides downloads for:
  - Official Court-Admissible PDF Report (ReportLab)
  - Complete Forensic JSON Deliverable
  - Forensic Findings CSV Spreadsheet
"""

import streamlit as st
import os
from modules.database import get_case, get_evidence_by_case, get_analysis_results_by_case
from modules.report_generator import generate_pdf_report, generate_json_report, generate_csv_findings

st.set_page_config(page_title="Report Generation", page_icon="📄", layout="wide")

case_id = st.session_state.get("active_case_id")
if not case_id:
    st.warning("Please select an active investigation case first.")
    st.stop()

case_info = get_case(case_id) or {}
st.title("📄 Automated Forensic Report Generation")
st.caption(f"Active Case: **{case_info.get('case_name')}** (`{case_id}`)")

st.markdown("""
Generates comprehensive, court-admissible forensic deliverables compliant with **NIST SP 800-101** and **ISO/IEC 27037**.
Includes full chain-of-custody checksums, evidence acquisition methods, rule-based findings, AI interpretation, and recommendations.
""")

# Report Compilation Buttons
c_pdf, c_json, c_csv = st.columns(3)

with c_pdf:
    st.subheader("1. Official PDF Report")
    st.write("20-section court deliverable with embedded SHA-256 integrity verification tables.")
    if st.button("📄 Compile PDF Report", use_container_width=True):
        with st.spinner("Generating ReportLab vector PDF..."):
            pdf_path = generate_pdf_report(case_id)
        st.session_state["generated_pdf_path"] = pdf_path
        st.success("PDF Report compiled successfully.")

    if "generated_pdf_path" in st.session_state and os.path.exists(st.session_state["generated_pdf_path"]):
        with open(st.session_state["generated_pdf_path"], "rb") as f:
            pdf_bytes = f.read()
        st.download_button(
            label="⬇️ Download Official PDF",
            data=pdf_bytes,
            file_name=f"Forensic_Report_{case_id}.pdf",
            mime="application/pdf",
            use_container_width=True
        )

with c_json:
    st.subheader("2. Full JSON Deliverable")
    st.write("Complete structured archive including evidence inventory, telemetry, and audit trail.")
    if st.button("🗂️ Compile JSON Archive", use_container_width=True):
        with st.spinner("Compiling JSON deliverable..."):
            json_path = generate_json_report(case_id)
        st.session_state["generated_json_path"] = json_path
        st.success("JSON Archive compiled.")

    if "generated_json_path" in st.session_state and os.path.exists(st.session_state["generated_json_path"]):
        with open(st.session_state["generated_json_path"], "rb") as f:
            json_bytes = f.read()
        st.download_button(
            label="⬇️ Download JSON Archive",
            data=json_bytes,
            file_name=f"Forensic_Report_{case_id}.json",
            mime="application/json",
            use_container_width=True
        )

with c_csv:
    st.subheader("3. Findings Spreadsheet (CSV)")
    st.write("Tabular export of all confirmed facts, AI observations, and possible leads.")
    if st.button("📊 Compile Findings CSV", use_container_width=True):
        with st.spinner("Exporting CSV findings..."):
            csv_path = generate_csv_findings(case_id)
        st.session_state["generated_csv_path"] = csv_path
        st.success("CSV export created.")

    if "generated_csv_path" in st.session_state and os.path.exists(st.session_state["generated_csv_path"]):
        with open(st.session_state["generated_csv_path"], "rb") as f:
            csv_bytes = f.read()
        st.download_button(
            label="⬇️ Download Findings CSV",
            data=csv_bytes,
            file_name=f"Forensic_Findings_{case_id}.csv",
            mime="text/csv",
            use_container_width=True
        )

st.divider()

# Section Checklist Documentation
st.subheader("Included Report Sections Checklist (20 Sections)")
sec_col1, sec_col2 = st.columns(2)
with sec_col1:
    st.markdown("""
    1. ✅ Investigation Title
    2. ✅ Case ID
    3. ✅ Investigation Date and Time
    4. ✅ Android Device Information
    5. ✅ Evidence Details & File Sizes
    6. ✅ Evidence Acquisition Methods
    7. ✅ Acquisition Timestamps
    8. ✅ SHA-256 Hashes
    9. ✅ Integrity Verification Results
    10. ✅ Forensic Methodology (ISO/IEC 27037)
    """)
with sec_col2:
    st.markdown("""
    11. ✅ Analysis Results
    12. ✅ Confirmed Evidence
    13. ✅ AI Observations
    14. ✅ Possible Leads
    15. ✅ Suspicious Activity Timeline
    16. ✅ Detailed Forensic Findings
    17. ✅ Ollama-Generated Summary
    18. ✅ Investigation Limitations
    19. ✅ Conclusion
    20. ✅ Actionable Recommendations
    """)

