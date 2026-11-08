@echo off
echo ========================================
echo  AI-Based Mobile Forensic Intelligence
echo  System - Backend Server
echo ========================================
echo.

cd /d "%~dp0"

echo [1/3] Checking Python installation...
python --version 2>NUL
if errorlevel 1 (
    echo ERROR: Python not found. Please install Python 3.10+
    pause
    exit /b 1
)

echo [2/3] Installing Python dependencies...
pip install -r backend\requirements.txt --quiet

echo [3/3] Starting FastAPI backend on http://127.0.0.1:5000
echo.
echo  Endpoints:
echo    Health:    http://127.0.0.1:5000/health
echo    Devices:   http://127.0.0.1:5000/api/devices
echo    Evidence:  http://127.0.0.1:5000/api/evidence
echo    Analysis:  http://127.0.0.1:5000/api/analysis
echo    Reports:   http://127.0.0.1:5000/api/reports
echo    Dashboard: http://127.0.0.1:5000/api/dashboard
echo.
echo  Press Ctrl+C to stop the server.
echo.

cd backend
python -m uvicorn main:app --host 127.0.0.1 --port 5000 --reload

