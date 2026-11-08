@echo off
echo ========================================
echo  AI-Based Mobile Forensic Intelligence
echo  System - Frontend Dashboard
echo ========================================
echo.

cd /d "%~dp0"

if not exist node_modules (
    echo [1/2] Installing frontend dependencies...
    call npm install
)

echo [2/2] Starting Vite development server...
echo.
echo  Dashboard will be accessible at http://localhost:5173
echo.
call npm run dev

