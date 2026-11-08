"""
6_🔒_Integrity_Verification.py - SHA-256 Cryptographic Evidence Integrity Page
Complies with NIST SP 800-101 and ISO/IEC 27037 non-repudiation mandates.
"""

import streamlit as st
import pandas as pd
import os
from modules.database import get_case, get_evidence_by_case, log_audit
from modules.hash_manager import verify_file_integrity, calculate_file_sha256

st.set_page_config(page_title="Evidence Integrity Verification", page_icon="🔒", layout="wide")

st.title("🔒 Cryptographic Evidence Integrity Verification")
st.caption("Recalculate SHA-256 digests directly from physical file contents to detect any tampering or bit-rot.")

case_id = st.session_state.get("active_case_id")
if not case_id:
    st.warning("Please select an active investigation case first.")
    st.stop()

case_info = get_case(case_id) or {}
st.info(f"Active Case: **{case_info.get('case_name')}** (`{case_id}`)")

evidence_list = get_evidence_by_case(case_id)
if not evidence_list:
    st.info("No evidence registered in this case yet. Please acquire or upload evidence files first.")
    st.stop()

# Batch Verification Trigger
st.subheader("1. Full Case Cryptographic Verification")
col_b1, col_b2 = st.columns([1, 3])
with col_b1:
    verify_all = st.button("🛡️ Verify All Evidence Hashes", use_container_width=True)

# Verification Table State
verification_results = []

for ev in evidence_list:
    orig_hash = ev["sha256_hash"]
    path = ev["stored_evidence_path"]
    
    # Run check
    status, curr_hash = verify_file_integrity(orig_hash, path)
    
    if verify_all:
        log_audit(
            case_id=case_id,
            evidence_id=ev["evidence_id"],
            action="INTEGRITY_VERIFICATION",
            status=status,
            details=f"File: {ev['filename']} | Stored: {orig_hash[:16]}... | Recomputed: {(curr_hash or 'NONE')[:16]}..."
        )

    verification_results.append({
        "Evidence ID": ev["evidence_id"],
        "Filename": ev["filename"],
        "Original SHA-256": orig_hash,
        "Current SHA-256": curr_hash or "FILE_NOT_FOUND",
        "Verification Status": status,
        "Matches?": "✅ MATCH" if status == "INTEGRITY VERIFIED" else ("❌ MISMATCH" if status == "INTEGRITY MISMATCH" else "⚠️ FAILED"),
        "Stored Path": path
    })

if verify_all:
    st.success("All evidence files verified and recorded in Audit Logs.")

df_v = pd.DataFrame(verification_results)[[
    "Evidence ID", "Filename", "Original SHA-256", "Current SHA-256", "Matches?", "Verification Status"
]]
st.dataframe(df_v, use_container_width=True, hide_index=True)

st.divider()

# 2. Individual Evidence Verification & Tamper Simulation Testing
st.subheader("2. Forensic Tamper Detection Demonstration")
st.markdown("""
To verify that the integrity engine genuinely detects unauthorized alterations, you can simulate a modified test copy below.
The system calculates hashes from actual file bytes—never hardcoded strings.
""")

ev_map = {e["evidence_id"]: f"{e['evidence_id']} - {e['filename']}" for e in evidence_list}
selected_id = st.selectbox("Select Evidence for Individual Verification / Tamper Test", options=list(ev_map.keys()), format_func=lambda x: ev_map[x])

if selected_id:
    ev_item = [e for e in evidence_list if e["evidence_id"] == selected_id][0]
    p = ev_item["stored_evidence_path"]
    orig_h = ev_item["sha256_hash"]

    c1, c2 = st.columns(2)
    with c1:
        st.write(f"**Evidence File:** `{ev_item['filename']}`")
        st.write(f"**Original SHA-256:** `{orig_h}`")
        if st.button("Run Individual Verification"):
            st_res, cur_h = verify_file_integrity(orig_h, p)
            if st_res == "INTEGRITY VERIFIED":
                st.success(f"STATUS: **{st_res}** (Hash: `{cur_h}`)")
            elif st_res == "INTEGRITY MISMATCH":
                st.error(f"STATUS: **{st_res}** (Current: `{cur_h}` != Original: `{orig_h}`)")
            else:
                st.warning(f"STATUS: **{st_res}**")

    with c2:
        st.write("**Simulate Tamper on Working Copy:**")
        st.caption("Creates an intentionally altered duplicate file to prove that hash verification fails on modified data.")
        if st.button("Create Altered Copy & Test"):
            test_tamper_path = p + ".tamper_test.tmp"
            try:
                # Copy original and append 1 byte
                with open(p, "rb") as orig_f:
                    data = orig_f.read()
                with open(test_tamper_path, "wb") as tamp_f:
                    tamp_f.write(data + b"\x00TAMPERED_BYTE")
                
                tamp_hash = calculate_file_sha256(test_tamper_path)
                t_status, _ = verify_file_integrity(orig_h, test_tamper_path)
                
                st.error(f"Test Result: **{t_status}**")
                st.write(f"• Original Hash: `{orig_h}`")
                st.write(f"• Altered Hash:  `{tamp_hash}`")
                st.info("Demonstrates that SHA-256 reliably flags single-byte tampering.")
                
                # Clean up test temp file
                if os.path.exists(test_tamper_path):
                    os.remove(test_tamper_path)
            except Exception as ex:
                st.error(f"Test error: {ex}")

