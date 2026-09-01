# scripts/install.ps1
# Universal 1-Line Bootstrapper & Installer for Windows
# Usage in PowerShell: irm https://raw.githubusercontent.com/Aravkataria/VAJRA/main/scripts/install.ps1 | iex

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "    VAJRA · Autonomous Cyber-Reasoning & Verification System    " -ForegroundColor Cyan
Write-Host "             Universal Bootstrapper for Windows                 " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check for Python 3.10+
Write-Host "[1/5] Checking Python environment..." -ForegroundColor Yellow

$pythonExe = $null
$candidates = @("py", "python", "python3")

foreach ($cmd in $candidates) {
    try {
        $verStr = & $cmd -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
        if ($verStr) {
            $major, $minor = $verStr.Split('.')
            if ([int]$major -ge 3 -and [int]$minor -ge 10) {
                $pythonExe = $cmd
                break
            }
        }
    } catch {}
}

if (-not $pythonExe) {
    Write-Host "[ERROR] Python 3.10 or higher is required." -ForegroundColor Red
    Write-Host "Please install Python from https://www.python.org/downloads/ or via Windows Terminal: winget install Python.Python.3.12" -ForegroundColor Yellow
    exit 1
}

$pyVersion = & $pythonExe --version
Write-Host "[2/5] Using Python: $pyVersion ($pythonExe)" -ForegroundColor Green

# 2. Setup Directories in $HOME\.vajra
$vajraHome = Join-Path $env:USERPROFILE ".vajra"
$vajraApp = Join-Path $vajraHome "app"
$vajraVenv = Join-Path $vajraHome "venv"
$vajraBin = Join-Path $vajraHome "bin"

New-Item -ItemType Directory -Force -Path $vajraHome, $vajraBin | Out-Null

Write-Host "[3/5] Setting up isolated application environment in $vajraHome..." -ForegroundColor Yellow

# Download latest source code
$repoUrl = "https://github.com/Aravkataria/VAJRA/archive/refs/heads/main.zip"
$tempZip = Join-Path $vajraHome "source.zip"

Write-Host "      Downloading latest VAJRA release..."
Invoke-WebRequest -Uri $repoUrl -OutFile $tempZip -UseBasicParsing

if (Test-Path $vajraApp) {
    Remove-Item -Recurse -Force $vajraApp
}
New-Item -ItemType Directory -Force -Path $vajraApp | Out-Null

Expand-Archive -Path $tempZip -DestinationPath $vajraHome -Force

$extractedFolder = Get-ChildItem -Path $vajraHome -Directory | Where-Object { $_.Name -like "VAJRA-test-*" } | Select-Object -First 1
if ($extractedFolder) {
    Get-ChildItem -Path $extractedFolder.FullName | Move-Item -Destination $vajraApp -Force
    Remove-Item -Recurse -Force $extractedFolder.FullName
}
Remove-Item -Force $tempZip

# 3. Create Virtual Environment
Write-Host "[4/5] Provisioning isolated Python virtual environment..." -ForegroundColor Yellow
$venvPython = Join-Path $vajraVenv "Scripts\python.exe"

if (-not (Test-Path $venvPython)) {
    & $pythonExe -m venv $vajraVenv
}

& $venvPython -m pip install --upgrade pip --quiet
& $venvPython -m pip install -r (Join-Path $vajraApp "requirements.txt") --quiet

# 4. Create Executable CLI Shims in .vajra\bin
$cmdShim = Join-Path $vajraBin "vajra.cmd"
$cmdContent = @"
@echo off
set "PYTHONPATH=$vajraApp;%PYTHONPATH%"
"$venvPython" -m app.launcher %*
"@
Set-Content -Path $cmdShim -Value $cmdContent -Encoding ASCII

$ps1Shim = Join-Path $vajraBin "vajra.ps1"
$ps1Content = @"
`$env:PYTHONPATH = "$vajraApp;" + `$env:PYTHONPATH
& "$venvPython" -m app.launcher `$args
"@
Set-Content -Path $ps1Shim -Value $ps1Content -Encoding UTF8

# Add to User PATH
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$vajraBin*") {
    [Environment]::SetEnvironmentVariable("Path", "$vajraBin;$userPath", "User")
    $env:Path = "$vajraBin;$env:Path"
}

# 5. Create Desktop & Start Menu Shortcuts
Write-Host "[5/5] Creating Desktop & Start Menu Shortcuts..." -ForegroundColor Yellow

try {
    $wshShell = New-Object -ComObject WScript.Shell
    
    # Desktop Shortcut
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $shortcutDesktop = $wshShell.CreateShortcut((Join-Path $desktopPath "VAJRA.lnk"))
    $shortcutDesktop.TargetPath = $cmdShim
    $shortcutDesktop.WorkingDirectory = $vajraApp
    $shortcutDesktop.Description = "VAJRA: Autonomous Cyber-Reasoning & Software Repair System"
    $shortcutDesktop.Save()

    # Start Menu Shortcut
    $startMenuPath = [Environment]::GetFolderPath("Programs")
    $shortcutStart = $wshShell.CreateShortcut((Join-Path $startMenuPath "VAJRA.lnk"))
    $shortcutStart.TargetPath = $cmdShim
    $shortcutStart.WorkingDirectory = $vajraApp
    $shortcutStart.Description = "VAJRA: Autonomous Cyber-Reasoning & Software Repair System"
    $shortcutStart.Save()

    Write-Host "      Created Desktop and Start Menu shortcuts." -ForegroundColor Green
} catch {
    Write-Host "      (Note: Desktop shortcut creation skipped)" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "        VAJRA Installation Complete! Ready to Run.              " -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  To launch the Desktop App:      vajra" -ForegroundColor Cyan
Write-Host "  To launch the Local Web Server: vajra --web" -ForegroundColor Cyan
Write-Host "  To scan a folder from CLI:      vajra scan C:\path\to\project" -ForegroundColor Cyan
Write-Host "  To check for updates:           vajra update" -ForegroundColor Cyan
Write-Host ""
