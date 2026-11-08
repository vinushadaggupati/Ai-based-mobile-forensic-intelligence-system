"""
main.py - FastAPI Backend Server for AI-Based Mobile Forensic Intelligence System
Runs on port 5000. Handles ADB device management, evidence collection,
forensic analysis, Ollama AI integration, and PDF report generation.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

from database import init_db
from routes import devices, evidence, analysis, reports, dashboard

app = FastAPI(
    title="AI-Based Mobile Forensic Intelligence System",
    description="Android mobile forensic investigation backend with ADB, SQLite, Ollama AI, and ReportLab PDF",
    version="1.0.0",
)

# Allow frontend (Vite dev server + production) to access the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register route modules
app.include_router(devices.router, prefix="/api/devices", tags=["Devices"])
app.include_router(evidence.router, prefix="/api/evidence", tags=["Evidence"])
app.include_router(analysis.router, prefix="/api/analysis", tags=["Analysis"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])


@app.on_event("startup")
async def startup_event():
    """Initialize the SQLite database on startup."""
    init_db()
    print("✅ Forensic SQLite database initialized")
    print("🔍 AI-Based Mobile Forensic Intelligence System backend starting...")


@app.get("/", tags=["Health"])
async def root():
    return {
        "system": "AI-Based Mobile Forensic Intelligence System",
        "version": "1.0.0",
        "status": "operational",
        "endpoints": {
            "devices": "/api/devices",
            "evidence": "/api/evidence",
            "analysis": "/api/analysis",
            "reports": "/api/reports",
            "dashboard": "/api/dashboard",
        },
    }


@app.get("/health", tags=["Health"])
async def health_check():
    return {"status": "healthy", "service": "MFIS Backend", "port": 5000}


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=5000, reload=True)

