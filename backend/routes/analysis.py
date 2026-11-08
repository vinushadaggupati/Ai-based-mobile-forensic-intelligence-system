"""routes/analysis.py - Forensic and AI analysis endpoints."""

from fastapi import APIRouter
from database import get_evidence, save_analysis_result, get_analysis_results
from forensic_analyzer import run_full_analysis
from ollama_analyzer import check_ollama_status, generate_ai_observations

router = APIRouter()


@router.get("/ollama-status")
def ollama_status():
    return check_ollama_status()


@router.post("/forensic/{device_id}")
def run_forensic_analysis(device_id: str):
    """Run Python-based rule/heuristic forensic analysis on collected evidence."""
    import time
    start = time.time()

    evidence = {
        "sms": get_evidence("sms_evidence", device_id),
        "calls": get_evidence("call_evidence", device_id),
        "contacts": get_evidence("contact_evidence", device_id),
        "gps": get_evidence("gps_evidence", device_id),
        "browser": get_evidence("browser_evidence", device_id),
        "apps": get_evidence("app_evidence", device_id),
        "media": get_evidence("media_evidence", device_id),
    }

    result = run_full_analysis(evidence)
    duration_ms = int((time.time() - start) * 1000)

    saved = save_analysis_result({
        "device_id": device_id,
        "investigation_id": f"inv-{device_id}",
        "analysis_type": "forensic-heuristic",
        "findings": result.get("findings", []),
        "summary": result.get("summary", ""),
        "risk_level": result.get("overall_risk", "Unknown"),
        "ai_model": "Python Heuristic Engine",
        "duration_ms": duration_ms,
    })

    return {
        "success": True,
        "result": result,
        "result_id": saved["id"],
        "duration_ms": duration_ms,
    }


@router.post("/ai/{device_id}")
def run_ai_analysis(device_id: str):
    """Run Ollama AI analysis on collected evidence. Falls back to heuristics if offline."""
    import time
    start = time.time()

    sms = get_evidence("sms_evidence", device_id)
    calls = get_evidence("call_evidence", device_id)
    browser = get_evidence("browser_evidence", device_id)
    apps = get_evidence("app_evidence", device_id)
    gps = get_evidence("gps_evidence", device_id)

    # Compute suspicious counts
    SUSPICIOUS_KW = ["burn", "wipe", "delete", "btc", "bitcoin", "cold wallet", "encrypted channel", "mixer", "sd card"]
    SUSPICIOUS_URL = [".onion", "darkforum", "mixer", "wipe-guide", "crypto-cashout"]

    suspicious_sms = sum(
        1 for m in sms
        if any(kw in (m.get("body") or "").lower() for kw in SUSPICIOUS_KW)
    )
    suspicious_apps = sum(1 for a in apps if a.get("suspicious"))
    suspicious_urls = sum(
        1 for b in browser
        if any(p in (b.get("url") or "").lower() for p in SUSPICIOUS_URL)
    )

    forensic_result = run_full_analysis({
        "sms": sms, "calls": calls, "contacts": [], "gps": gps,
        "browser": browser, "apps": apps, "media": [],
    })

    evidence_summary = {
        "case_number": "MFIS-2026-0042",
        "title": "Android Forensic Investigation",
        "device_model": "Android Device",
        "serial": device_id,
        "acquisition_method": "ADB",
        "sms_count": len(sms),
        "call_count": len(calls),
        "browser_count": len(browser),
        "gps_count": len(gps),
        "app_count": len(apps),
        "suspicious_sms": suspicious_sms,
        "suspicious_calls": len([c for c in calls if c.get("type") in ("missed", "rejected")]),
        "suspicious_urls": suspicious_urls,
        "suspicious_apps": suspicious_apps,
        "key_findings": forensic_result.get("findings", [])[:5],
    }

    ai_result = generate_ai_observations(evidence_summary)
    duration_ms = int((time.time() - start) * 1000)

    saved = save_analysis_result({
        "device_id": device_id,
        "investigation_id": f"inv-{device_id}",
        "analysis_type": "ai-ollama",
        "findings": ai_result.get("findings", []),
        "summary": ai_result.get("summary", ""),
        "risk_level": ai_result.get("risk_level", "Unknown"),
        "ai_model": ai_result.get("model_used", "Unknown"),
        "duration_ms": duration_ms,
    })

    return {
        "success": True,
        "result": ai_result,
        "result_id": saved["id"],
        "duration_ms": duration_ms,
        "source": ai_result.get("source", "unknown"),
    }


@router.get("/results/{investigation_id}")
def get_results(investigation_id: str):
    results = get_analysis_results(investigation_id)
    return {"success": True, "results": results, "count": len(results)}

