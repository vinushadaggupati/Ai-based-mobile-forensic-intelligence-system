@echo off
title AI-Based Mobile Forensic Intelligence System (MFIS) - Launcher
color 0B
echo ===============================================================================
echo     AI-BASED MOBILE FORENSIC INTELLIGENCE SYSTEM (MFIS)
echo     Android Digital Forensics, Integrity Verification & AI Analysis
echo ===============================================================================
echo.
echo Choose your preferred interface to launch:
echo.
echo   [1] Streamlit Forensic Workstation (Recommended - Full Interactive GUI)
echo   [2] Dual Stack: FastAPI Backend (Port 5000) + React Dashboard (Port 5173)
echo   [3] Run Automated Verification Tests (test_forensic_pipeline.py)
echo   [4] Exit
echo.
set /p choice="Enter option [1, 2, 3, or 4] (Default is 1): "

if "%choice%"=="" set choice=1
if "%choice%"=="1" goto run_streamlit
if "%choice%"=="2" goto run_dual
if "%choice%"=="3" goto run_test
if "%choice%"=="4" exit /b 0

:run_streamlit
cls
echo [*] Launching Streamlit Forensic Workstation...
call run_app.bat
goto end

:run_dual
cls
echo [*] Launching FastAPI Backend and React Dashboard in separate windows...
cd /d "%~dp0"
start "MFIS Python Backend (Port 5000)" cmd /k "start-backend.bat"
timeout /t 3 /nobreak >nul
start "MFIS Frontend Dashboard (Vite)" cmd /k "start-frontend.bat"
echo [*] Both services launched:
echo     - Backend:  http://127.0.0.1:5000 (Docs: http://127.0.0.1:5000/docs)
echo     - Frontend: http://localhost:5173
pause
goto end

:run_test
cls
echo [*] Executing End-to-End Forensic Pipeline Test...
python test_forensic_pipeline.py
echo.
pause
goto end

:end
