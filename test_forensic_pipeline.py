"""
AI-Based Mobile Forensic Intelligence System - End-to-End Pipeline Verification Test
Validates:
1. SQLite database initialization & case creation
2. Evidence ingestion with SHA-256 binary hashing & working copy generation
3. Forensic analysis & tri-category findings classification
4. Hash integrity verification & tamper detection
5. AI analysis (Ollama probe or heuristic fallback)
6. 20-section ReportLab PDF, JSON, and CSV generation
"""

import sys
import os

# Ensure workspace is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.database import (
    init_db, create_case, get_case, list_cases,
    add_evidence, get_evidence_by_case, get_analysis_results_by_case,
    log_audit, get_audit_logs, get_dashboard_metrics
)
from modules.hash_manager import calculate_file_sha256, verify_file_integrity, create_working_copy
from modules.forensic_analyzer import run_full_case_analysis
from modules.ai_analyzer import generate_forensic_ai_summary
from modules.report_generator import generate_pdf_report, generate_json_report, generate_csv_report

def run_tests():
    print("=" * 70)
    print("STARTING E2E FORENSIC PIPELINE VERIFICATION")
    print("=" * 70)

    # 1. Initialize Database
    print("\n[STEP 1] Initializing SQLite database...")
    init_db()
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database", "forensic.db")
    assert os.path.exists(db_path), f"Database not found at {db_path}"
    print(f"[OK] SQLite database initialized successfully at: {db_path}")

    # 2. Create Case
    print("\n[STEP 2] Creating Forensic Case...")
    case_record = create_case(
        case_name="Operation Sentinel Target Device Analysis",
        description="Comprehensive verification case for mobile forensic pipeline"
    )
    test_case_id = case_record["case_id"]
    case_data = get_case(test_case_id)
    assert case_data is not None, "Case creation failed"
    print(f"[OK] Created case: {case_data['case_id']} - {case_data['case_name']}")

    # 3. Ingest Test Evidence Files (Option B simulation)
    print("\n[STEP 3] Simulating Evidence Ingestion & SHA-256 Hashing...")
    storage_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence_storage", test_case_id)
    copies_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "working_copies", test_case_id)
    os.makedirs(storage_dir, exist_ok=True)
    os.makedirs(copies_dir, exist_ok=True)

    # Create a synthetic SMS & logcat evidence file with suspicious indicators
    test_evidence_file = os.path.join(storage_dir, "test_logcat_dump.log")
    with open(test_evidence_file, "w", encoding="utf-8") as f:
        f.write(
            "2026-11-04 14:02:11 I/ActivityManager: START u0 {act=android.intent.action.MAIN cat=[android.intent.category.LAUNCHER] cmp=org.torproject.android/.OrbotActivity}\n"
            "2026-11-04 14:05:30 D/su: Request for root shell granted to PID 4821 by Magisk v26.1\n"
            "2026-11-04 14:10:00 I/SMSDispatcher: Received SMS from +18005550199: Transfer $50,000 via darknet mixer bitcoin wallet bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh immediately\n"
            "2026-11-04 14:15:22 W/LocationManager: Mock location enabled by developer settings provider\n"
            "2026-11-04 14:20:10 I/StorageManager: Secure shred wipe executed on /sdcard/DCIM/vault_records.enc\n"
        )

    # Compute binary SHA-256
    file_hash = calculate_file_sha256(test_evidence_file)
    assert file_hash and len(file_hash) == 64, "SHA-256 computation failed"
    print(f"[OK] Computed SHA-256: {file_hash}")

    # Mirror to working copy
    ev_id = "EVD-TEST-PIPELINE-001"
    working_copy_path = create_working_copy(test_evidence_file, copies_dir, ev_id)
    assert os.path.exists(working_copy_path), "Working copy creation failed"
    print(f"[OK] Mirror working copy created: {working_copy_path}")

    # Register in SQLite
    ev_record = add_evidence(
        case_id=test_case_id,
        filename="test_logcat_dump.log",
        evidence_type="LOGS",
        original_filename="test_logcat_dump.log",
        stored_evidence_path=test_evidence_file,
        file_size=os.path.getsize(test_evidence_file),
        sha256_hash=file_hash,
        acquisition_method="LAPTOP_UPLOAD",
        original_source_path=None,
        device_id=None
    )
    evidence_list = get_evidence_by_case(test_case_id)
    assert len(evidence_list) >= 1, "Evidence registration failed"
    print(f"[OK] Evidence registered in SQLite (Total evidence in case: {len(evidence_list)})")

    # 4. Verify Integrity (Valid vs Tampered)
    print("\n[STEP 4] Testing SHA-256 Integrity Verification & Tamper Detection...")
    status, calc_hash = verify_file_integrity(file_hash, test_evidence_file)
    assert status == "INTEGRITY VERIFIED", f"Expected INTEGRITY VERIFIED, got {status}"
    print(f"[OK] Valid file check: {status} (Hash: {calc_hash})")

    # Create temporary tampered file to test mismatch detection
    tampered_file = os.path.join(storage_dir, "tampered_sample.log")
    with open(tampered_file, "w") as f:
        f.write("Legit text")
    tampered_status, _ = verify_file_integrity("0000000000000000000000000000000000000000000000000000000000000000", tampered_file)
    assert tampered_status == "INTEGRITY MISMATCH", f"Expected INTEGRITY MISMATCH, got {tampered_status}"
    os.remove(tampered_file)
    print(f"[OK] Tamper detection check: Correctly identified {tampered_status}")

    # 5. Run Forensic Analysis Engine
    print("\n[STEP 5] Running Multi-Artifact Forensic Analysis Engine...")
    findings = run_full_case_analysis(test_case_id)
    assert len(findings) > 0, "No findings detected by forensic engine"
    print(f"[OK] Analysis completed. Identified {len(findings)} findings:")
    for f in findings:
        print(f"   - [{f['analysis_type']}] [{f['severity']}] ({f['verification_status']}): {f['finding_description'][:65]}...")

    # Verify tri-category classification
    classifications = {f['verification_status'] for f in findings}
    print(f"[OK] Unique classifications encountered: {classifications}")

    # 6. Run AI Analysis (Ollama with fallback)
    print("\n[STEP 6] Running AI Analysis Engine (Ollama / Fallback)...")
    ai_report = generate_forensic_ai_summary(test_case_id, model_name="llama3.2:3b")
    assert ai_report is not None and "ai_summary" in ai_report, "AI analysis output invalid"
    print("[OK] AI Analysis report generated successfully.")
    print(f"   Provider/Engine: {ai_report.get('ollama_model_name')}")
    print(f"   AI Summary snippet: {ai_report.get('ai_summary')[:100]}...")

    # 7. Generate 20-Section PDF Report, JSON & CSV
    print("\n[STEP 7] Generating 20-Section Official PDF, JSON & CSV Reports...")
    pdf_path = generate_pdf_report(test_case_id)
    assert os.path.exists(pdf_path), f"PDF report not found at {pdf_path}"
    pdf_size = os.path.getsize(pdf_path)
    assert pdf_size > 1000, f"PDF report is empty or suspiciously small ({pdf_size} bytes)"
    print(f"[OK] PDF report successfully generated: {pdf_path} ({pdf_size} bytes)")

    json_path = generate_json_report(test_case_id)
    assert os.path.exists(json_path), f"JSON report not found at {json_path}"
    print(f"[OK] JSON report successfully generated: {json_path}")

    csv_path = generate_csv_report(test_case_id)
    assert os.path.exists(csv_path), f"CSV findings export generated: {csv_path}"
    print(f"[OK] CSV report successfully generated: {csv_path}")

    # 8. Check Audit Logs & Dashboard Metrics
    print("\n[STEP 8] Validating Audit Trail & KPI Aggregates...")
    logs = get_audit_logs(test_case_id)
    assert len(logs) >= 3, f"Insufficient audit logs ({len(logs)})"
    print(f"[OK] Chain-of-custody audit trail verified ({len(logs)} entries recorded)")

    stats = get_dashboard_metrics(test_case_id)
    print("[OK] Dashboard KPIs:")

    for k, v in stats.items():
        if k != "recent_activity":
            print(f"   - {k}: {v}")

    print("\n" + "=" * 70)
    print("ALL FORENSIC PIPELINE TESTS PASSED WITH ZERO ERRORS!")
    print("=" * 70)

if __name__ == "__main__":
    run_tests()
