"""routes/reports.py - PDF report generation and download endpoints."""

import uuid
import os
from fastapi import APIRouter
from fastapi.responses import Response
from database import get_evidence, get_investigation, get_all_hashes, get_analysis_results
from report_generator import generate_forensic_report
from adb_manager import load_sample_data
from forensic_analyzer import run_full_analysis

router = APIRouter()

# In-memory cache for generated reports
_report_cache: dict[str, bytes] = {}


@router.post("/generate/{investigation_id}")
def generate_report(investigation_id: str):
    """Generate a full forensic PDF report for an investigation."""
    # Try to get investigation from DB; fall back to sample data
    inv = get_investigation(investigation_id)
    sample = load_sample_data()

    if not inv:
        inv = sample["investigation"]

    device_id = "dev-android-01"
    devices_db = get_evidence("sms_evidence", device_id)  # just to check if data exists
    if not devices_db:
        # Use sample data
        report_data = sample
        report_data["case"] = {
            "case_number": inv.get("case_number", sample["investigation"]["case_number"]),
            "title": inv.get("title", sample["investigation"]["title"]),
            "investigator": inv.get("investigator", sample["investigation"]["investigator"]),
            "agency": inv.get("agency", sample["investigation"]["agency"]),
            "suspect": inv.get("suspect", sample["investigation"]["suspect"]),
            "description": inv.get("description", ""),
            "status": inv.get("status", "active"),
            "openedAt": inv.get("created_at", "2026-11-02T09:00:00Z"),
        }
    else:
        report_data = {
            "case": {
                "case_number": inv.get("case_number", ""),
                "title": inv.get("title", ""),
                "investigator": inv.get("investigator", ""),
                "agency": inv.get("agency", ""),
                "suspect": inv.get("suspect", ""),
                "description": inv.get("description", ""),
                "status": inv.get("status", "active"),
                "openedAt": inv.get("created_at", ""),
            },
            "devices": [sample["device"]],
            "sms": get_evidence("sms_evidence", device_id),
            "calls": get_evidence("call_evidence", device_id),
            "contacts": get_evidence("contact_evidence", device_id),
            "gps": get_evidence("gps_evidence", device_id),
            "browser": get_evidence("browser_evidence", device_id),
            "apps": get_evidence("app_evidence", device_id),
            "media": get_evidence("media_evidence", device_id),
        }

    # Run analysis
    all_ev = {k: report_data.get(k, []) for k in ["sms", "calls", "contacts", "gps", "browser", "apps", "media"]}
    analysis = run_full_analysis(all_ev)

    # Try to get AI analysis results
    ai_results = get_analysis_results(investigation_id)
    ai_findings = []
    if ai_results:
        for r in ai_results:
            if r.get("analysis_type") == "ai-ollama":
                ai_findings = r.get("findings", [])
                break

    report_data["findings"] = analysis.get("findings", [])
    report_data["ai_findings"] = ai_findings
    report_data["hashes"] = get_all_hashes(device_id)
    report_data["summary"] = analysis.get("summary", "")
    report_data["risk_level"] = analysis.get("overall_risk", "Unknown")
    report_data["recommendations"] = analysis.get("recommendations", [])

    pdf_bytes = generate_forensic_report(report_data)
    report_id = str(uuid.uuid4())
    _report_cache[report_id] = pdf_bytes

    return {
        "success": True,
        "report_id": report_id,
        "investigation_id": investigation_id,
        "download_url": f"/api/reports/download/{report_id}",
        "size_kb": len(pdf_bytes) // 1024,
        "sections": 15,
    }


@router.get("/preview/{investigation_id}")
def get_report_preview(investigation_id: str):
    """Get structured report data for the frontend preview panel."""
    sample = load_sample_data()
    device_id = "dev-android-01"

    sms = get_evidence("sms_evidence", device_id) or sample["sms"]
    calls = get_evidence("call_evidence", device_id) or sample["calls"]
    contacts = get_evidence("contact_evidence", device_id) or sample["contacts"]
    apps = get_evidence("app_evidence", device_id) or sample["apps"]
    browser = get_evidence("browser_evidence", device_id) or sample["browser"]
    gps = get_evidence("gps_evidence", device_id) or sample["gps"]
    media = get_evidence("media_evidence", device_id) or sample["media"]

    analysis = run_full_analysis({"sms": sms, "calls": calls, "contacts": contacts, "gps": gps, "browser": browser, "apps": apps, "media": media})

    return {
        "success": True,
        "preview": {
            "case_number": "MFIS-2026-0042",
            "risk_level": analysis.get("overall_risk", "Unknown"),
            "total_evidence": len(sms) + len(calls) + len(contacts) + len(gps) + len(browser) + len(apps) + len(media),
            "findings_count": len(analysis.get("findings", [])),
            "suspicious_count": analysis.get("total_suspicious_items", 0),
            "sections": [
                "1. Investigation Information",
                "2. Android Device Information",
                "3. Evidence Collection Summary",
                "4. SMS Analysis",
                "5. Call Log Analysis",
                "6. Contact Analysis",
                "7. GPS Analysis",
                "8. Browser History Analysis",
                "9. Installed Application Analysis",
                "10. SHA-256 Hash Verification",
                "11. Suspicious Activities Identified",
                "12. AI-Generated Observations",
                "13. Risk Assessment",
                "14. Investigation Summary",
                "15. Recommendations",
            ],
        },
    }


@router.get("/download/{report_id}")
def download_report(report_id: str):
    """Download a previously generated PDF report."""
    if report_id not in _report_cache:
        return Response(content=b"Report not found or expired. Please generate again.", status_code=404)
    pdf_bytes = _report_cache[report_id]
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=forensic_report_{report_id[:8]}.pdf"},
    )

