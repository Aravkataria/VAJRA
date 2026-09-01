@echo off
setlocal enabledelayedexpansion
title Installing VAJRA...
color 0A

echo ==========================================================
echo               INSTALLING VAJRA FOR WINDOWS
echo ==========================================================
echo.
echo Installing VAJRA into %%LOCALAPPDATA%%\VAJRA...
echo.

:: 1. Create target installation folder
mkdir "%LOCALAPPDATA%\VAJRA" 2>nul
xcopy /E /I /Y "%~dp0*" "%LOCALAPPDATA%\VAJRA\" >nul

:: 2. Find pythonw / python executable
for /f "tokens=*" %%i in ('where pythonw 2^>nul') do set "PY_EXE=%%i"
if "%PY_EXE%"=="" (
    for /f "tokens=*" %%i in ('where python 2^>nul') do set "PY_EXE=%%i"
)
if "%PY_EXE%"=="" set "PY_EXE=py.exe"

:: 3. Create Desktop & Start Menu Shortcuts pointing directly to Python executable with script arguments
powershell -NoProfile -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut([Environment]::GetFolderPath('Desktop') + '\VAJRA.lnk'); $s.TargetPath = '%PY_EXE%'; $s.Arguments = '\"%LOCALAPPDATA%\VAJRA\app\gui_app.py\"'; $s.WorkingDirectory = '%LOCALAPPDATA%\VAJRA'; $s.IconLocation = 'shell32.dll,48'; $s.Description = 'VAJRA - AI Cyber Security Assistant'; $s.Save()"
powershell -NoProfile -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut([Environment]::GetFolderPath('Programs') + '\VAJRA.lnk'); $s.TargetPath = '%PY_EXE%'; $s.Arguments = '\"%LOCALAPPDATA%\VAJRA\app\gui_app.py\"'; $s.WorkingDirectory = '%LOCALAPPDATA%\VAJRA'; $s.IconLocation = 'shell32.dll,48'; $s.Description = 'VAJRA - AI Cyber Security Assistant'; $s.Save()"

echo ==========================================================
echo  INSTALLATION COMPLETE!
echo.
echo  A "VAJRA" shortcut has been added to your Desktop!
echo ==========================================================
echo.
echo Launching VAJRA now...
timeout /t 2 >nul

:: 4. Start the application
cd /d "%LOCALAPPDATA%\VAJRA"
py -m app.gui_app
exit /b