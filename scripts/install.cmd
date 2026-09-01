@echo off
REM scripts/install.cmd
REM Double-clickable Windows Installer for VAJRA

title VAJRA Installer
echo Starting VAJRA Bootstrapper...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
pause
