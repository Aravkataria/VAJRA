# scripts/build_setup_exe.py

"""
Build script to compile a single-file standalone 'VAJRA-Setup.exe' wizard.

Users can download 'VAJRA-Setup.exe' directly from GitHub Releases and double-click
to install VAJRA without any PowerShell command or terminal usage.

Usage:
    python scripts/build_setup_exe.py
"""

import sys
import os
import subprocess
from pathlib import Path


def build_setup_exe():
    print("=" * 60)
    print("      COMPILING STANDALONE VAJRA-SETUP.EXE (GRAPHICAL WIZARD)")
    print("=" * 60)

    # 1. Install pyinstaller if missing
    try:
        __import__("PyInstaller")
    except ImportError:
        print("[+] Installing PyInstaller...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

    project_root = Path(__file__).resolve().parent.parent
    gui_script = project_root / "scripts" / "bootstrap_gui.py"
    dist_dir = project_root / "dist"

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--onefile",           # Single standalone executable
        "--windowed",          # Zero console / terminal window
        "--name", "VAJRA-Setup",
        "--distpath", str(dist_dir),
        str(gui_script)
    ]

    print(f"\n[+] Running PyInstaller build command...")
    subprocess.check_call(cmd, cwd=str(project_root))

    out_exe = dist_dir / "VAJRA-Setup.exe"
    print("\n" + "=" * 60)
    print(" BUILD SUCCESSFUL!")
    print(f" Executable: {out_exe}")
    print(" Non-technical users can double-click this file to install VAJRA!")
    print("=" * 60)


if __name__ == "__main__":
    build_setup_exe()
