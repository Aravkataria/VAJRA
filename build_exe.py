# build_exe.py

"""
Build script to generate a single standalone double-clickable VAJRA.exe
with a custom native Windows GUI (zero terminal window, zero browser).

Usage:
    python build_exe.py
"""

import os
import subprocess
import sys


def build():
    print("=" * 60)
    print("      BUILDING STANDALONE VAJRA.EXE (NATIVE WINDOWS GUI)")
    print("=" * 60)

    # 1. Install pyinstaller if missing
    try:
        __import__("PyInstaller")
    except ImportError:
        print("[+] Installing pyinstaller...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

    # 2. Build windowed standalone executable
    print("\n[+] Compiling VAJRA.exe (windowed native GUI)...")
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--onedir",
        "--windowed",          # Completely hides black CMD terminal window
        "--name", "VAJRA",
        "--add-data", "requirements.txt;.",
        "--hidden-import", "tkinter",
        "--hidden-import", "tkinter.ttk",
        "--hidden-import", "tkinter.filedialog",
        "--hidden-import", "tkinter.messagebox",
        "--hidden-import", "app.analysis.python_static",
        "--hidden-import", "app.verification.verifier",
        "--hidden-import", "app.repair.repairer",
        "app/gui_app.py",
    ]

    subprocess.check_call(cmd)

    print("\n" + "=" * 60)
    print(" BUILD COMPLETE!")
    print(" Your executable is located at: dist/VAJRA/VAJRA.exe")
    print(" Double click VAJRA.exe to open the native Windows desktop app!")
    print("=" * 60)


if __name__ == "__main__":
    build()