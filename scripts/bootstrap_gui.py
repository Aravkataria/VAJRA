# scripts/bootstrap_gui.py

"""
VAJRA · Universal Cross-Platform Graphical Setup Wizard (Windows, macOS, Linux).

Provides a modern, double-clickable graphical setup wizard for all platforms.
Downloads, installs, configures virtual environment, creates desktop shortcuts,
and launches VAJRA with a single click.
"""

import os
import sys
import platform
import threading
import urllib.request
import zipfile
import shutil
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path

APP_NAME = "VAJRA"
VERSION = "2.4.0"
REPO_OWNER = "Aravkataria"
REPO_NAME = "VAJRA"
REPO_ZIP_URL = f"https://github.com/{REPO_OWNER}/{REPO_NAME}/archive/refs/heads/main.zip"


class VajraInstallerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title(f"{APP_NAME} Universal Setup Wizard v{VERSION}")
        self.root.geometry("540x400")
        self.root.resizable(False, False)
        self.root.configure(bg="#000000")

        # Center on screen
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (540 // 2)
        y = (self.root.winfo_screenheight() // 2) - (400 // 2)
        self.root.geometry(f"+{x}+{y}")

        self.setup_ui()
        self.is_installing = False

    def setup_ui(self):
        # Header banner
        header_frame = tk.Frame(self.root, bg="#080808", height=80)
        header_frame.pack(fill="x", side="top")

        title_lbl = tk.Label(
            header_frame,
            text="VAJRA",
            font=("Segoe UI", 18, "bold"),
            fg="#ffffff",
            bg="#080808",
        )
        title_lbl.pack(anchor="w", padx=25, pady=(15, 2))

        os_str = "Windows" if sys.platform == "win32" else ("macOS" if sys.platform == "darwin" else "Linux")
        subtitle_lbl = tk.Label(
            header_frame,
            text=f"Autonomous Cyber-Reasoning & Software Repair System ({os_str})",
            font=("Segoe UI", 9),
            fg="#a1a1aa",
            bg="#080808",
        )
        subtitle_lbl.pack(anchor="w", padx=25)

        # Body frame
        self.body_frame = tk.Frame(self.root, bg="#000000", padx=25, pady=20)
        self.body_frame.pack(fill="both", expand=True)

        self.desc_lbl = tk.Label(
            self.body_frame,
            text="This wizard installs VAJRA in an isolated environment,\ncreates native desktop application shortcuts, and configures self-updates.",
            font=("Segoe UI", 10),
            fg="#cccccc",
            bg="#000000",
            justify="left",
        )
        self.desc_lbl.pack(anchor="w", pady=(0, 15))

        # Status text
        self.status_lbl = tk.Label(
            self.body_frame,
            text="Ready to install.",
            font=("Segoe UI", 9),
            fg="#a1a1aa",
            bg="#000000",
        )
        self.status_lbl.pack(anchor="w", pady=(5, 5))

        # Progress bar
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TProgressbar", thickness=8, troughcolor="#161616", background="#ffffff")
        self.progress = ttk.Progressbar(self.body_frame, style="TProgressbar", mode="determinate", maximum=100)
        self.progress.pack(fill="x", pady=(0, 15))

        # Destination info
        dest_path = str(Path.home() / ".vajra")
        self.dest_lbl = tk.Label(
            self.body_frame,
            text=f"Install location: {dest_path}",
            font=("Consolas", 8),
            fg="#666666",
            bg="#000000",
        )
        self.dest_lbl.pack(anchor="w")

        # Footer Actions
        footer_frame = tk.Frame(self.root, bg="#080808", height=60)
        footer_frame.pack(fill="x", side="bottom")

        self.btn_cancel = tk.Button(
            footer_frame,
            text="Cancel",
            font=("Segoe UI", 9),
            bg="#161616",
            fg="#ffffff",
            activebackground="#202020",
            activeforeground="#ffffff",
            relief="flat",
            padx=15,
            pady=4,
            command=self.root.quit,
        )
        self.btn_cancel.pack(side="right", padx=(5, 20), pady=15)

        self.btn_install = tk.Button(
            footer_frame,
            text="Install VAJRA",
            font=("Segoe UI", 9, "bold"),
            bg="#ffffff",
            fg="#000000",
            activebackground="#e5e5e5",
            activeforeground="#000000",
            relief="flat",
            padx=20,
            pady=4,
            command=self.start_installation,
        )
        self.btn_install.pack(side="right", pady=15)

    def set_status(self, text, percent=None):
        def _update():
            self.status_lbl.config(text=text)
            if percent is not None:
                self.progress["value"] = percent
        self.root.after(0, _update)

    def start_installation(self):
        if self.is_installing:
            return
        self.is_installing = True
        self.btn_install.config(state="disabled", text="Installing...")
        self.btn_cancel.config(state="disabled")

        threading.Thread(target=self._run_install_thread, daemon=True).start()

    def _run_install_thread(self):
        try:
            # Step 1: Detect Python
            self.set_status("Detecting Python 3.10+ runtime...", 10)
            python_exe = self._detect_python()
            if not python_exe:
                raise RuntimeError("Python 3.10 or higher is required. Please install Python from https://python.org")

            # Step 2: Prepare Directories
            self.set_status("Preparing isolated storage directories...", 25)
            vajra_home = Path.home() / ".vajra"
            vajra_app = vajra_home / "app"
            vajra_venv = vajra_home / "venv"
            vajra_bin = vajra_home / "bin"

            vajra_home.mkdir(parents=True, exist_ok=True)
            vajra_bin.mkdir(parents=True, exist_ok=True)

            # Step 3: Download & Extract Release
            self.set_status("Downloading latest VAJRA release package...", 45)
            temp_zip = vajra_home / "source.zip"
            urllib.request.urlretrieve(REPO_ZIP_URL, str(temp_zip))

            self.set_status("Extracting application package...", 60)
            if vajra_app.exists():
                shutil.rmtree(str(vajra_app), ignore_errors=True)
            vajra_app.mkdir(parents=True, exist_ok=True)

            with zipfile.ZipFile(str(temp_zip), "r") as zf:
                zf.extractall(str(vajra_home))

            extracted_folder = None
            for item in os.listdir(str(vajra_home)):
                full = vajra_home / item
                if full.is_dir() and item.startswith("VAJRA-test-"):
                    extracted_folder = full
                    break

            if extracted_folder:
                for sub in os.listdir(str(extracted_folder)):
                    shutil.move(str(extracted_folder / sub), str(vajra_app / sub))
                shutil.rmtree(str(extracted_folder), ignore_errors=True)

            if temp_zip.exists():
                temp_zip.unlink()

            # Step 4: Provision Virtual Environment & Dependencies
            self.set_status("Setting up Python virtual environment & dependencies...", 75)
            is_win = sys.platform == "win32"
            venv_python = vajra_venv / ("Scripts/python.exe" if is_win else "bin/python3")

            flags = subprocess.CREATE_NO_WINDOW if (is_win and hasattr(subprocess, "CREATE_NO_WINDOW")) else 0

            if not venv_python.exists():
                subprocess.check_call([python_exe, "-m", "venv", str(vajra_venv)], creationflags=flags)

            req_file = vajra_app / "requirements.txt"
            if req_file.exists():
                subprocess.check_call([str(venv_python), "-m", "pip", "install", "--upgrade", "pip", "--quiet"], creationflags=flags)
                subprocess.check_call([str(venv_python), "-m", "pip", "install", "-r", str(req_file), "--quiet"], creationflags=flags)

            # Step 5: Create Shims & Shortcuts
            self.set_status("Creating Desktop and application shortcuts...", 90)
            launch_target = self._create_shortcuts_and_shims(venv_python, vajra_app, vajra_bin)

            # Done!
            self.set_status("Installation complete!", 100)
            self._on_success(launch_target)

        except Exception as err:
            self.root.after(0, lambda: self._on_error(str(err)))

    def _detect_python(self):
        for cmd in ["py", "python3", "python"]:
            try:
                flags = subprocess.CREATE_NO_WINDOW if (sys.platform == "win32" and hasattr(subprocess, "CREATE_NO_WINDOW")) else 0
                res = subprocess.check_output([cmd, "-c", "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"], text=True, creationflags=flags).strip()
                major, minor = map(int, res.split("."))
                if major >= 3 and minor >= 10:
                    return cmd
            except Exception:
                continue
        return None

    def _create_shortcuts_and_shims(self, venv_python, vajra_app, vajra_bin):
        is_win = sys.platform == "win32"
        is_mac = sys.platform == "darwin"

        if is_win:
            cmd_shim = vajra_bin / "vajra.cmd"
            with open(str(cmd_shim), "w", encoding="ascii") as f:
                f.write(f'@echo off\nset "PYTHONPATH={vajra_app};%PYTHONPATH%"\n"{venv_python}" -m app.launcher %*\n')

            desktop_path = Path.home() / "Desktop" / "VAJRA.lnk"
            programs_path = Path(os.environ.get("APPDATA", "")) / "Microsoft/Windows/Start Menu/Programs/VAJRA.lnk"
            ps_script = f"""
            $wsh = New-Object -ComObject WScript.Shell
            $s1 = $wsh.CreateShortcut('{desktop_path}')
            $s1.TargetPath = '{cmd_shim}'
            $s1.WorkingDirectory = '{vajra_app}'
            $s1.Save()
            if (Test-Path '{programs_path.parent}') {{
                $s2 = $wsh.CreateShortcut('{programs_path}')
                $s2.TargetPath = '{cmd_shim}'
                $s2.WorkingDirectory = '{vajra_app}'
                $s2.Save()
            }}
            """
            subprocess.run(["powershell", "-NoProfile", "-Command", ps_script], creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0)
            return str(cmd_shim)

        elif is_mac:
            # POSIX shim
            shim = vajra_bin / "vajra"
            with open(str(shim), "w") as f:
                f.write(f'#!/usr/bin/env bash\nexport PYTHONPATH="{vajra_app}:$PYTHONPATH"\nexec "{venv_python}" -m app.launcher "$@"\n')
            shim.chmod(0o755)

            # Create ~/Applications/VAJRA.app
            app_dir = Path.home() / "Applications" / "VAJRA.app" / "Contents" / "MacOS"
            app_dir.mkdir(parents=True, exist_ok=True)
            app_exec = app_dir / "VAJRA"
            with open(str(app_exec), "w") as f:
                f.write(f'#!/usr/bin/env bash\nexec "{shim}"\n')
            app_exec.chmod(0o755)

            # Global symlink
            local_bin = Path.home() / ".local" / "bin"
            local_bin.mkdir(parents=True, exist_ok=True)
            try:
                (local_bin / "vajra").unlink(missing_ok=True)
                (local_bin / "vajra").symlink_to(shim)
            except Exception:
                pass
            return str(shim)

        else:
            # Linux
            shim = vajra_bin / "vajra"
            with open(str(shim), "w") as f:
                f.write(f'#!/usr/bin/env bash\nexport PYTHONPATH="{vajra_app}:$PYTHONPATH"\nexec "{venv_python}" -m app.launcher "$@"\n')
            shim.chmod(0o755)

            # Create ~/.local/share/applications/vajra.desktop
            apps_dir = Path.home() / ".local" / "share" / "applications"
            apps_dir.mkdir(parents=True, exist_ok=True)
            desktop_file = apps_dir / "vajra.desktop"
            with open(str(desktop_file), "w") as f:
                f.write(f"[Desktop Entry]\nName=VAJRA\nComment=Autonomous Cyber-Reasoning System\nExec={shim}\nTerminal=false\nType=Application\nCategories=Development;Security;\n")

            # Desktop link
            linux_desktop = Path.home() / "Desktop" / "vajra.desktop"
            try:
                shutil.copy(str(desktop_file), str(linux_desktop))
                linux_desktop.chmod(0o755)
            except Exception:
                pass
            return str(shim)

    def _on_success(self, launch_target):
        def _show():
            self.btn_install.config(state="normal", text="Launch VAJRA", command=lambda: self._launch_and_exit(launch_target))
            self.btn_cancel.config(state="normal", text="Finish", command=self.root.quit)
            messagebox.showinfo("Success", "VAJRA has been successfully installed!\nDesktop and Application shortcuts have been created.")
        self.root.after(0, _show)

    def _launch_and_exit(self, launch_target):
        if sys.platform == "win32":
            subprocess.Popen([launch_target], shell=True)
        else:
            subprocess.Popen([launch_target], shell=False)
        self.root.quit()

    def _on_error(self, err_msg):
        self.btn_install.config(state="normal", text="Retry", command=self.start_installation)
        self.btn_cancel.config(state="normal", text="Close", command=self.root.quit)
        self.set_status(f"Error: {err_msg}")
        messagebox.showerror("Installation Error", f"Installation failed:\n\n{err_msg}")


def main():
    root = tk.Tk()
    app = VajraInstallerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
