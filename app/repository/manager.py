# app/repository/manager.py

import os
import re
import shutil
import subprocess
import uuid
import zipfile
from pathlib import Path
from typing import Optional, Tuple

from app.repository.language import detect_language
from app.repository.metadata import RepositoryMetadata

# Security limits to prevent DoS, zip bombs, and disk exhaustion
MAX_UPLOAD_SIZE_BYTES = 50 * 1024 * 1024       # 50 MB zip upload cap
MAX_EXTRACTED_TOTAL_BYTES = 200 * 1024 * 1024  # 200 MB extracted cap
MAX_FILE_SIZE_BYTES = 20 * 1024 * 1024         # 20 MB per file cap
MAX_MEMBER_COUNT = 10_000                       # Max 10,000 files in archive

# Strict GitHub URL regex: only https://github.com/owner/repo[.git] or with /tree/branch
GITHUB_URL_PATTERN = re.compile(
    r"^https://github\.com/([a-zA-Z0-9_.-]+)/([a-zA-Z0-9_.-]+?)(?:\.git)?(?:/tree/([a-zA-Z0-9_.-/]+))?/?$"
)


class RepositoryManager:
    """
    Handles uploaded and cloned repositories for VAJRA with strict security bounds.

    Responsibilities:
    - Create isolated workspaces
    - Safely clone validated GitHub repositories
    - Defend against zip bombs and path traversal
    - Scan repository files
    - Detect programming languages
    - Generate repository metadata
    - Delete workspaces
    """

    def __init__(
        self,
        uploads_dir="uploads",
        workspaces_dir="workspaces"
    ):
        self.uploads_dir = Path(uploads_dir)
        self.workspaces_dir = Path(workspaces_dir)

        self.uploads_dir.mkdir(parents=True, exist_ok=True)
        self.workspaces_dir.mkdir(parents=True, exist_ok=True)

    def create_workspace(self) -> Tuple[str, Path]:
        workspace_id = str(uuid.uuid4())
        workspace_path = self.workspaces_dir / workspace_id
        workspace_path.mkdir(parents=True, exist_ok=False)
        return workspace_id, workspace_path

    def clone_github_repo(self, repo_url: str, branch: Optional[str] = None) -> Tuple[str, Path]:
        clean_url = repo_url.strip()
        match = GITHUB_URL_PATTERN.match(clean_url)
        if not match:
            raise ValueError(
                "Invalid GitHub URL. Must be an https://github.com/owner/repo URL (e.g. https://github.com/owner/repo)."
            )

        owner, repo_name, extracted_branch = match.groups()
        target_branch = branch or extracted_branch
        canonical_clone_url = f"https://github.com/{owner}/{repo_name}.git"

        workspace_id, workspace_path = self.create_workspace()

        cmd = ["git", "clone", "--depth", "1"]
        if target_branch:
            cmd.extend(["-b", target_branch])
        cmd.extend([canonical_clone_url, str(workspace_path)])

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if res.returncode != 0:
                shutil.rmtree(workspace_path, ignore_errors=True)
                raise ValueError(f"Git clone failed: {res.stderr.strip() or res.stdout.strip()}")

            total_size = sum(f.stat().st_size for f in workspace_path.rglob("*") if f.is_file())
            if total_size > MAX_EXTRACTED_TOTAL_BYTES:
                shutil.rmtree(workspace_path, ignore_errors=True)
                raise ValueError(
                    f"Cloned repository exceeds size cap ({total_size} bytes > {MAX_EXTRACTED_TOTAL_BYTES} bytes limit)."
                )

        except Exception as exc:
            shutil.rmtree(workspace_path, ignore_errors=True)
            raise ValueError(f"Failed to clone repository '{repo_url}': {exc}")

        return workspace_id, workspace_path

    def extract_zip(self, zip_path: Path) -> Tuple[str, Path]:
        zip_path = Path(zip_path)

        if not zip_path.is_file():
            raise FileNotFoundError(f"ZIP file not found: {zip_path}")

        if zip_path.stat().st_size > MAX_UPLOAD_SIZE_BYTES:
            raise ValueError(
                f"Uploaded ZIP exceeds maximum allowed size ({zip_path.stat().st_size} bytes > {MAX_UPLOAD_SIZE_BYTES} bytes)."
            )

        workspace_id, workspace_path = self.create_workspace()
        total_extracted_bytes = 0
        member_count = 0

        try:
            with zipfile.ZipFile(zip_path, "r") as archive:
                infolist = archive.infolist()
                if len(infolist) > MAX_MEMBER_COUNT:
                    raise ValueError(f"ZIP contains too many files ({len(infolist)} > {MAX_MEMBER_COUNT}).")

                for member in infolist:
                    member_count += 1
                    if member_count > MAX_MEMBER_COUNT:
                        raise ValueError("ZIP member count limit exceeded.")

                    if member.file_size > MAX_FILE_SIZE_BYTES:
                        raise ValueError(f"File '{member.filename}' exceeds per-file size limit ({member.file_size} bytes).")

                    total_extracted_bytes += member.file_size
                    if total_extracted_bytes > MAX_EXTRACTED_TOTAL_BYTES:
                        raise ValueError(
                            f"ZIP decompressed size exceeds safety limit ({total_extracted_bytes} bytes > {MAX_EXTRACTED_TOTAL_BYTES} bytes)."
                        )

                    member_path = Path(member.filename)
                    if member_path.is_absolute() or member_path.drive:
                        raise ValueError(f"Unsafe ZIP path detected: {member.filename}")

                    workspace_root = workspace_path.resolve()
                    destination = (workspace_path / member_path).resolve()

                    try:
                        destination.relative_to(workspace_root)
                    except ValueError:
                        raise ValueError(f"Unsafe ZIP path detected (path traversal): {member.filename}")

                    if member.is_dir():
                        destination.mkdir(parents=True, exist_ok=True)
                        continue

                    destination.parent.mkdir(parents=True, exist_ok=True)

                    with archive.open(member, "r") as source:
                        with open(destination, "wb") as target:
                            shutil.copyfileobj(source, target)

        except Exception:
            shutil.rmtree(workspace_path, ignore_errors=True)
            raise

        return workspace_id, workspace_path

    def scan_repository(self, workspace_path: Path):
        workspace_path = Path(workspace_path)
        if not workspace_path.is_dir():
            raise FileNotFoundError(f"Workspace not found: {workspace_path}")

        files = []
        for file in workspace_path.rglob("*"):
            if not file.is_file():
                continue

            relative_path = file.relative_to(workspace_path)
            language = detect_language(file.name)
            files.append({
                "name": file.name,
                "path": str(relative_path),
                "language": language,
                "size": file.stat().st_size,
            })

        files.sort(key=lambda item: item["path"].lower())
        return files

    def build_metadata(self, workspace_id: str, workspace_path: Path) -> RepositoryMetadata:
        files = self.scan_repository(workspace_path)
        metadata = RepositoryMetadata(workspace_id=workspace_id)
        for file_info in files:
            metadata.add_file(file_info)
        return metadata

    def delete_workspace(self, workspace_path: Path):
        workspace_path = Path(workspace_path)
        if workspace_path.exists():
            shutil.rmtree(workspace_path, ignore_errors=True)