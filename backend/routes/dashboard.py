"""routes/dashboard.py - Dashboard statistics endpoint."""

from fastapi import APIRouter
from database import get_statistics, list_investigations
from ollama_analyzer import check_ollama_status

router = APIRouter()


@router.get("/stats")
def dashboard_stats():
    stats = get_statistics()
    investigations = list_investigations()
    ollama = check_ollama_status()

    return {
        "success": True,
        "stats": stats,
        "recent_investigations": investigations[:5],
        "ollama": {
            "connected": ollama["connected"],
            "model": ollama.get("active_model", "llama3.2:3b"),
            "latency_ms": ollama.get("latency_ms", 0),
        },
        "evidence_categories": {
            "sms": stats.get("total_sms", 0),
            "calls": stats.get("total_calls", 0),
            "contacts": stats.get("total_contacts", 0),
            "gps": stats.get("total_gps", 0),
            "browser": stats.get("total_browser", 0),
            "apps": stats.get("total_apps", 0),
            "media": stats.get("total_media", 0),
        },
    }

