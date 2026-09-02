@echo off
title VAJRA - Autonomous Cyber-Reasoning & Repair Installer
cd /d "%~dp0"
echo ============================================================
echo          VAJRA - Windows One-Click Installer
echo ============================================================
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\install.ps1"
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Installation encountered an issue.
)
pause
