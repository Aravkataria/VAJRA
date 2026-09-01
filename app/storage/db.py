# app/storage/db.py

"""
SQLite storage and Failure Memory for VAJRA.
"""

import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.report.models import AssuranceReport, AttemptReport

DEFAULT_DB_PATH = Path(
    os.environ.get(
        "VAJRA_DB_PATH",
        str(Path(__file__).resolve().parent.parent.parent / "workspaces" / ".vajra" / "vajra.db"),
    )
)


class Database:
    def __init__(self, db_path: Path = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS repair_attempts (
                    attempt_id TEXT PRIMARY KEY,
                    workspace_id TEXT,
                    generated_at TEXT,
                    file TEXT,
                    line INTEGER,
                    function TEXT,
                    vulnerability_type TEXT,
                    severity TEXT,
                    decision_route TEXT,
                    patch_diff TEXT,
                    final_method TEXT,
                    final_passed INTEGER,
                    final_reason TEXT,
                    outcome TEXT,
                    outcome_reason TEXT,
                    report_json TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS assurance_reports (
                    workspace_id TEXT PRIMARY KEY,
                    generated_at TEXT,
                    initial_findings INTEGER,
                    final_findings INTEGER,
                    verified_repairs INTEGER,
                    structured_non_repairs INTEGER,
                    report_json TEXT,
                    html_content TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_attempts_vuln ON repair_attempts (vulnerability_type)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_attempts_ws ON repair_attempts (workspace_id)"
            )
            conn.commit()

    def record_attempt(self, attempt: AttemptReport, workspace_id: str) -> None:
        report_dict = attempt.to_dict()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO repair_attempts (
                    attempt_id, workspace_id, generated_at, file, line, function,
                    vulnerability_type, severity, decision_route, patch_diff,
                    final_method, final_passed, final_reason, outcome,
                    outcome_reason, report_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    attempt.attempt_id,
                    workspace_id,
                    attempt.generated_at,
                    attempt.file,
                    attempt.line,
                    attempt.function,
                    attempt.vulnerability_type,
                    attempt.severity,
                    attempt.decision_route,
                    attempt.patch_diff,
                    attempt.final_verification_method,
                    1 if attempt.final_verification_passed else (0 if attempt.final_verification_passed is False else None),
                    attempt.final_verification_reason,
                    attempt.outcome,
                    attempt.outcome_reason,
                    json.dumps(report_dict),
                ),
            )
            conn.commit()

    def record_assurance_report(self, report: AssuranceReport, html_content: str) -> None:
        report_dict = report.to_dict()
        summary = report.summary
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO assurance_reports (
                    workspace_id, generated_at, initial_findings, final_findings,
                    verified_repairs, structured_non_repairs, report_json, html_content
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report.workspace_id,
                    report.generated_at,
                    summary.get("initial_findings", 0),
                    summary.get("final_findings", 0),
                    summary.get("verified_repairs", 0),
                    summary.get("structured_non_repairs", 0),
                    json.dumps(report_dict),
                    html_content,
                ),
            )
            conn.commit()

    def get_assurance_report(self, workspace_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT report_json FROM assurance_reports WHERE workspace_id = ?",
                (workspace_id,),
            ).fetchone()
            if row:
                return json.loads(row["report_json"])
            return None

    def get_assurance_report_html(self, workspace_id: str) -> Optional[str]:
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT html_content FROM assurance_reports WHERE workspace_id = ?",
                (workspace_id,),
            ).fetchone()
            if row:
                return row["html_content"]
            return None

    def get_attempt(self, attempt_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT report_json FROM repair_attempts WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            if row:
                return json.loads(row["report_json"])
            return None

    def get_all_reports(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT workspace_id, generated_at, initial_findings, final_findings,
                       verified_repairs, structured_non_repairs, report_json
                FROM assurance_reports
                ORDER BY generated_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [json.loads(row["report_json"]) for row in rows]

    def get_declined_attempts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT report_json FROM repair_attempts
                WHERE outcome = 'structured_non_repair'
                ORDER BY generated_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [json.loads(row["report_json"]) for row in rows]

    def get_failure_memory(
        self, vulnerability_type: str, file: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            if file:
                rows = conn.execute(
                    """
                    SELECT attempt_id, file, line, function, vulnerability_type,
                           final_method, final_reason, patch_diff, outcome_reason
                    FROM repair_attempts
                    WHERE vulnerability_type = ? AND file = ? AND outcome = 'structured_non_repair'
                    ORDER BY generated_at DESC
                    LIMIT 10
                    """,
                    (vulnerability_type, file),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT attempt_id, file, line, function, vulnerability_type,
                           final_method, final_reason, patch_diff, outcome_reason
                    FROM repair_attempts
                    WHERE vulnerability_type = ? AND outcome = 'structured_non_repair'
                    ORDER BY generated_at DESC
                    LIMIT 10
                    """,
                    (vulnerability_type,),
                ).fetchall()

            return [dict(row) for row in rows]


_default_db: Optional[Database] = None


def get_db() -> Database:
    global _default_db
    if _default_db is None:
        _default_db = Database()
    return _default_db