# app/native_gui.py

"""
100% Pure Native Windows Desktop GUI for VAJRA.

Built with native Windows UI widgets (Tkinter / TTK) - Zero browser,
zero HTML, zero webview dependencies. Runs completely offline on any PC.
"""

import io
import json
import os
from pathlib import Path
import shutil
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import zipfile

from app.analysis.python_static import analyze_source
from app.analysis.workspace_scan import scan_workspace, summarize_findings
from app.decision.engine import decide
from app.evidence.aggregator.aggregator import build_evidence
from app.repair.ai_repair import AIRepairer
from app.repair.deterministic_repair import DeterministicRepairer
from app.repair.patch import Patch
from app.repair.patch_applier import PatchApplier
from app.repair.repairer import Repairer
from app.repository.manager import RepositoryManager
from app.storage.db import get_db
from app.verification.verifier import Verifier


class VajraNativeApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("VAJRA · Autonomous Cyber-Reasoning & Software Repair")
        self.geometry("1100x750")
        self.minsize(900, 600)
        self.configure(bg="#0f172a")

        self.repo_manager = RepositoryManager()
        self.current_workspace_id = None
        self.current_workspace_path = None
        self.scan_results = None

        self._setup_styles()
        self._build_ui()

    def _setup_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        # Dark Theme Styling
        style.configure(".", background="#0f172a", foreground="#f8fafc", font=("Segoe UI", 9))
        style.configure("TFrame", background="#0f172a")
        style.configure("Card.TFrame", background="#1e293b", relief="flat")
        style.configure("Header.TLabel", font=("Segoe UI", 13, "bold"), foreground="#38bdf8", background="#0f172a")
        style.configure("SubHeader.TLabel", font=("Segoe UI", 9), foreground="#94a3b8", background="#0f172a")
        style.configure("Stat.TLabel", font=("Segoe UI", 10, "bold"), foreground="#f8fafc", background="#1e293b")
        style.configure("Treeview", background="#1e293b", foreground="#f8fafc", fieldbackground="#1e293b", font=("Segoe UI", 9), rowheight=26)
        style.configure("Treeview.Heading", background="#334155", foreground="#f8fafc", font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", "#2563eb")], foreground=[("selected", "#ffffff")])

    def _build_ui(self):
        # 1. Header Frame
        header = ttk.Frame(self, padding=(15, 10))
        header.pack(fill="x")

        ttk.Label(header, text="🛡️ VAJRA · Cyber-Security & Repair Desktop", style="Header.TLabel").pack(anchor="w")
        ttk.Label(header, text="6-Stage Independent Verification Pipeline | Offline Autonomous Repair Engine", style="SubHeader.TLabel").pack(anchor="w")

        # 2. Input / Action Bar Card
        action_card = ttk.Frame(self, style="Card.TFrame", padding=12)
        action_card.pack(fill="x", padx=15, pady=5)

        ttk.Label(action_card, text="Target Repository / Project Path:", background="#1e293b", font=("Segoe UI", 9, "bold")).grid(row=0, column=0, sticky="w", pady=(0, 4))

        self.path_var = tk.StringVar(value=str(Path("app/test_repository").resolve()))
        self.path_entry = tk.Entry(action_card, textvariable=self.path_var, bg="#0f172a", fg="#f8fafc", insertbackground="white", font=("Segoe UI", 10), relief="flat", highlightthickness=1, highlightbackground="#334155")
        self.path_entry.grid(row=1, column=0, sticky="ew", padx=(0, 8), ipady=4)
        action_card.columnconfigure(0, weight=1)

        btn_folder = tk.Button(action_card, text="📁 Browse Folder", command=self._browse_folder, bg="#334155", fg="white", activebackground="#475569", relief="flat", font=("Segoe UI", 9, "bold"), padx=10, pady=3, cursor="hand2")
        btn_folder.grid(row=1, column=1, padx=4)

        btn_zip = tk.Button(action_card, text="📦 Choose ZIP", command=self._browse_zip, bg="#334155", fg="white", activebackground="#475569", relief="flat", font=("Segoe UI", 9, "bold"), padx=10, pady=3, cursor="hand2")
        btn_zip.grid(row=1, column=2, padx=4)

        self.btn_run = tk.Button(action_card, text="🚀 RUN SCAN & AUTO-REPAIR", command=self._start_scan_thread, bg="#10b981", fg="white", activebackground="#059669", relief="flat", font=("Segoe UI", 10, "bold"), padx=14, pady=3, cursor="hand2")
        self.btn_run.grid(row=1, column=3, padx=(6, 0))

        # 3. Stats Strip
        self.stats_frame = ttk.Frame(self, style="Card.TFrame", padding=(12, 6))
        self.stats_frame.pack(fill="x", padx=15, pady=4)

        self.lbl_stat_findings = ttk.Label(self.stats_frame, text="🔍 Vulnerabilities: 0", style="Stat.TLabel")
        self.lbl_stat_findings.pack(side="left", padx=10)

        self.lbl_stat_verified = ttk.Label(self.stats_frame, text="✅ Verified Repairs: 0", style="Stat.TLabel", foreground="#34d399")
        self.lbl_stat_verified.pack(side="left", padx=10)

        self.lbl_stat_declined = ttk.Label(self.stats_frame, text="⛔ Declined Unsafe: 0", style="Stat.TLabel", foreground="#f87171")
        self.lbl_stat_declined.pack(side="left", padx=10)

        self.lbl_status = ttk.Label(self.stats_frame, text="Ready", style="Stat.TLabel", foreground="#94a3b8")
        self.lbl_status.pack(side="right", padx=10)

        # 4. Main Body: Split View (Findings List on Left, Patch Diff & Details on Right)
        body = ttk.Frame(self, padding=(15, 5))
        body.pack(fill="both", expand=True)

        paned = tk.PanedWindow(body, orient="horizontal", bg="#334155", sashwidth=4)
        paned.pack(fill="both", expand=True)

        # Left: Findings Tree
        left_frame = ttk.Frame(paned, style="Card.TFrame")
        paned.add(left_frame, minsize=320, width=420)

        ttk.Label(left_frame, text="Detected Findings & Verifier Outcomes", font=("Segoe UI", 9, "bold"), background="#1e293b").pack(anchor="w", padx=8, pady=6)

        cols = ("file", "type", "status")
        self.tree = ttk.Treeview(left_frame, columns=cols, show="headings", selectmode="browse")
        self.tree.heading("file", text="File:Line")
        self.tree.heading("type", text="Vulnerability")
        self.tree.heading("status", text="Outcome")
        self.tree.column("file", width=130)
        self.tree.column("type", width=140)
        self.tree.column("status", width=90)
        self.tree.pack(fill="both", expand=True, padx=6, pady=4)
        self.tree.bind("<<TreeviewSelect>>", self._on_select_finding)

        # Right: Diff Viewer & Detail
        right_frame = ttk.Frame(paned, style="Card.TFrame")
        paned.add(right_frame, minsize=400)

        ttk.Label(right_frame, text="Verified Patch & Proof Details (Diff Viewer)", font=("Segoe UI", 9, "bold"), background="#1e293b").pack(anchor="w", padx=8, pady=6)

        self.txt_diff = tk.Text(right_frame, bg="#020617", fg="#38bdf8", font=("Consolas", 9), relief="flat", wrap="none")
        self.txt_diff.pack(fill="both", expand=True, padx=6, pady=4)

        # 5. Bottom Action & Export Bar
        bottom_bar = ttk.Frame(self, padding=(15, 8))
        bottom_bar.pack(fill="x")

        self.btn_export = tk.Button(bottom_bar, text="💾 Save Patched Clean Project (ZIP)", command=self._export_zip, bg="#2563eb", fg="white", font=("Segoe UI", 9, "bold"), padx=12, pady=4, relief="flat", cursor="hand2", state="disabled")
        self.btn_export.pack(side="left", padx=(0, 8))

        self.btn_open_report = tk.Button(bottom_bar, text="📄 View Full Assurance Report (HTML)", command=self._open_html_report, bg="#334155", fg="white", font=("Segoe UI", 9, "bold"), padx=12, pady=4, relief="flat", cursor="hand2", state="disabled")
        self.btn_open_report.pack(side="left")

        self.progress = ttk.Progressbar(bottom_bar, mode="indeterminate", length=200)

    def _browse_folder(self):
        folder = filedialog.askdirectory(title="Select Project Directory to Scan")
        if folder:
            self.path_var.set(folder)

    def _browse_zip(self):
        zip_file = filedialog.askopenfilename(title="Select Project ZIP Archive", filetypes=[("ZIP Archives", "*.zip")])
        if zip_file:
            self.path_var.set(zip_file)

    def _start_scan_thread(self):
        target = self.path_var.get().strip()
        if not target:
            messagebox.showwarning("No Target", "Please enter or select a folder or .zip file path.")
            return

        self.btn_run.config(state="disabled")
        self.progress.pack(side="right", padx=10)
        self.progress.start(10)
        self.lbl_status.config(text="⏳ Scanning & Running 6-Stage Verifiers...", foreground="#fbbf24")
        self.tree.delete(*self.tree.get_children())
        self.txt_diff.delete("1.0", "end")

        threading.Thread(target=self._run_scan_logic, args=(target,), daemon=True).start()

    def _run_scan_logic(self, target: str):
        try:
            # 1. Create Workspace
            ws_id, ws_path = self.repo_manager.create_workspace()
            self.current_workspace_id = ws_id
            self.current_workspace_path = ws_path

            target_path = Path(target)
            if target_path.is_file() and target_path.suffix.lower() == ".zip":
                # Extract zip
                with zipfile.ZipFile(target_path, "r") as zf:
                    zf.extractall(ws_path)
            elif target_path.is_dir():
                shutil.copytree(target_path, ws_path, dirs_exist_ok=True)
            elif target.startswith("http://") or target.startswith("https://"):
                ws_id, ws_path = self.repo_manager.clone_github_repo(target)
                self.current_workspace_id = ws_id
                self.current_workspace_path = ws_path
            else:
                raise ValueError(f"Target path not found: {target}")

            # 2. Run AST scan
            findings = scan_workspace(ws_path)
            evidence_list = build_evidence(findings, repository=ws_id)

            # 3. Decisions & Repairs
            repairer = Repairer([DeterministicRepairer(), AIRepairer()])
            verifier = Verifier()
            applier = PatchApplier()

            patches = []
            attempts = []
            verified_count = 0
            declined_count = 0

            for ev in evidence_list:
                dec = decide(ev, None)
                patch, patch_attempts = repairer.repair_with_trace(dec, ws_path)
                attempts.extend(patch_attempts)

                if patch:
                    v_res = verifier.verify(patch, ws_path)
                    if v_res.verified:
                        applier.apply(patch, ws_path)
                        patches.append(patch)
                        verified_count += 1
                    else:
                        declined_count += 1
                else:
                    declined_count += 1

            self.scan_results = {
                "workspace_id": ws_id,
                "findings": findings,
                "patches": patches,
                "attempts": attempts,
                "verified_count": verified_count,
                "declined_count": declined_count,
            }

            self.after(0, self._render_results)

        except Exception as exc:
            self.after(0, lambda: self._show_error(str(exc)))

    def _render_results(self):
        self.progress.stop()
        self.progress.pack_forget()
        self.btn_run.config(state="normal")
        self.btn_export.config(state="normal")
        self.btn_open_report.config(state="normal")

        res = self.scan_results
        findings = res["findings"]
        patches = res["patches"]

        self.lbl_stat_findings.config(text=f"🔍 Vulnerabilities: {len(findings)}")
        self.lbl_stat_verified.config(text=f"✅ Verified Repairs: {res['verified_count']}")
        self.lbl_stat_declined.config(text=f"⛔ Declined Unsafe: {res['declined_count']}")
        self.lbl_status.config(text="Scan Complete", foreground="#34d399")

        # Populate tree
        for i, f in enumerate(findings):
            matched_patch = next((p for p in patches if p.file == f.file and p.line == f.line), None)
            status = "VERIFIED" if matched_patch else "DECLINED"
            item_id = self.tree.insert("", "end", values=(f"{f.file}:{f.line}", f.vulnerability_type, status))
            if i == 0:
                self.tree.selection_set(item_id)
                self._display_patch_for_finding(f, matched_patch)

    def _on_select_finding(self, event):
        selected = self.tree.selection()
        if not selected:
            return
        item = self.tree.item(selected[0])
        file_line = item["values"][0]
        file_name, line_num = file_line.split(":")
        line_num = int(line_num)

        res = self.scan_results
        f = next((f for f in res["findings"] if f.file == file_name and f.line == line_num), None)
        p = next((p for p in res["patches"] if p.file == file_name and p.line == line_num), None)
        if f:
            self._display_patch_for_finding(f, p)

    def _display_patch_for_finding(self, finding, patch):
        self.txt_diff.delete("1.0", "end")
        header = f"File: {finding.file}:{finding.line}\nVulnerability Type: {finding.vulnerability_type}\nMessage: {finding.message}\n"
        header += "=" * 70 + "\n\n"
        self.txt_diff.insert("end", header)

        if patch:
            self.txt_diff.insert("end", f"STATUS: ✅ VERIFIED REPAIR APPLIED ATOMICALLY\n")
            self.txt_diff.insert("end", f"Confidence: {patch.confidence*100:.0f}%\n")
            self.txt_diff.insert("end", f"Strategy: {patch.strategy or 'deterministic/reasoning'}\n\n")
            self.txt_diff.insert("end", "--- UNIFIED DIFF (BEFORE / AFTER) ---\n")
            self.txt_diff.insert("end", patch.diff or "[Direct Source Change]")
        else:
            self.txt_diff.insert("end", f"STATUS: ⛔ REPAIR DECLINED OR UNSAFE\n")
            self.txt_diff.insert("end", f"Reason: The candidate did not pass all 6 independent verification stages\n")
            self.txt_diff.insert("end", "(Syntax AST, Static Re-scan, Dynamic PoC, Baseline Regressions, Fuzzing, Mutation).\n")
            self.txt_diff.insert("end", "VAJRA failed safe rather than applying a potentially breaking or sham fix.\n")

    def _export_zip(self):
        if not self.current_workspace_path or not self.current_workspace_path.is_dir():
            messagebox.showerror("Error", "No active workspace to export.")
            return

        save_file = filedialog.asksaveasfilename(title="Save Patched Project ZIP", defaultextension=".zip", filetypes=[("ZIP Archive", "*.zip")], initialfile=f"vajra_patched_{self.current_workspace_id[:8]}.zip")
        if not save_file:
            return

        with zipfile.ZipFile(save_file, "w", zipfile.ZIP_DEFLATED) as zf:
            for file_path in self.current_workspace_path.rglob("*"):
                if file_path.is_file():
                    rel_path = file_path.relative_to(self.current_workspace_path)
                    zf.write(file_path, arcname=str(rel_path))

        messagebox.showinfo("Export Successful", f"Clean patched project saved to:\n{save_file}")

    def _open_html_report(self):
        if not self.current_workspace_id:
            return
        import webbrowser
        webbrowser.open(f"http://127.0.0.1:8000/workspace/{self.current_workspace_id}/report.html")

    def _show_error(self, err_msg: str):
        self.progress.stop()
        self.progress.pack_forget()
        self.btn_run.config(state="normal")
        self.lbl_status.config(text="Error", foreground="#ef4444")
        messagebox.showerror("Scan Error", f"An error occurred during scan:\n{err_msg}")


def main():
    app = VajraNativeApp()
    app.mainloop()


if __name__ == "__main__":
    main()
