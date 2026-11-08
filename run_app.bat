@echo off
title AI-Based Mobile Forensic Intelligence System (MFIS)
color 0A

echo ===============================================================================
echo     AI-BASED MOBILE FORENSIC INTELLIGENCE SYSTEM (MFIS)
echo     Android Digital Forensics & AI Investigation Suite
echo ===============================================================================
echo.

:: Check Python installation
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH!
    echo Please install Python 3.10+ from python.org and add to PATH.
    pause
    exit /b 1
)

:: Verify dependencies
echo [*] Checking dependencies...
python -c "import streamlit, pandas, reportlab, requests" >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Installing required Python libraries from requirements.txt...
    pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to install requirements. Please check your internet connection.
        pause
        exit /b 1
    )
)

echo [*] Starting Streamlit Forensic Workstation...
echo [*] Dashboard will open in your default browser at http://localhost:8501
echo.

python -m streamlit run app.py

pause

