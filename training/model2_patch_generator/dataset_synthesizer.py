# training/model2_patch_generator/dataset_synthesizer.py
from __future__ import annotations

import difflib
import random
from typing import Any, Dict, List, Tuple
from training.model2_patch_generator.schema import PatchTrainingSample, RepairStrategy


def generate_unified_diff(original: str, repaired: str, filename: str = "app/service.py") -> str:
    """Generates standard unified diff format."""
    orig_lines = original.splitlines(keepends=True)
    rep_lines = repaired.splitlines(keepends=True)
    diff = difflib.unified_diff(
        orig_lines,
        rep_lines,
        fromfile=f"a/{filename}",
        tofile=f"b/{filename}",
        lineterm=""
    )
    return "".join(diff)


class PatchDatasetSynthesizer:
    """
    Generates high-precision, multilingual vulnerability repair datasets
    for training VAJRA Model 2 (Neural Patch Generator).
    """

    def __init__(self, seed: int = 42):
        random.seed(seed)
        self.resources = ["user", "order", "invoice", "payment", "account", "profile", "document", "item", "token", "report"]
        self.params = ["id", "uuid", "account_no", "user_key", "email", "ref_code", "session_id", "filter_val", "lookup_id"]
        self.tables = ["users", "orders", "invoices", "payments", "accounts", "profiles", "documents", "items", "tokens", "reports"]
        self.columns = ["id", "user_uuid", "account_num", "access_key", "email_address", "reference_id", "session_token"]
        self.tools = ["ping", "traceroute", "nslookup", "dig", "curl", "whois", "stat", "nmap"]

    def _generate_sqli_python(self, idx: int) -> PatchTrainingSample:
        res = self.resources[idx % len(self.resources)]
        param = self.params[idx % len(self.params)]
        tbl = self.tables[idx % len(self.tables)]
        col = self.columns[idx % len(self.columns)]
        
        vuln = (
            "from flask import request, jsonify\n"
            "import sqlite3\n\n"
            f"@app.route('/api/v1/{res}s', methods=['GET'])\n"
            f"def get_{res}():\n"
            f"    {param} = request.args.get('{param}', '')\n"
            "    conn = sqlite3.connect('prod.db')\n"
            "    cursor = conn.cursor()\n"
            f"    cursor.execute('SELECT * FROM {tbl} WHERE {col} = \'' + {param} + '\'')\n"
            "    rows = cursor.fetchall()\n"
            "    conn.close()\n"
            "    return jsonify(rows)\n"
        )
        
        rep = (
            "from flask import request, jsonify\n"
            "import sqlite3\n\n"
            f"@app.route('/api/v1/{res}s', methods=['GET'])\n"
            f"def get_{res}():\n"
            f"    {param} = request.args.get('{param}', '')\n"
            "    conn = sqlite3.connect('prod.db')\n"
            "    cursor = conn.cursor()\n"
            f"    cursor.execute('SELECT * FROM {tbl} WHERE {col} = ?', ({param},))\n"
            "    rows = cursor.fetchall()\n"
            "    conn.close()\n"
            "    return jsonify(rows)\n"
        )
        
        target = f"app/routes/{res}.py"
        return PatchTrainingSample(
            sample_id=f"PATCH-SQLI-PY-{idx:04d}",
            language="python",
            cwe_id="CWE-89",
            vulnerability_category="sql_injection",
            strategy=RepairStrategy.PARAMETERIZATION,
            vulnerable_code=vuln,
            repaired_code=rep,
            unified_diff=generate_unified_diff(vuln, rep, target),
            diagnostic_message=f"Tainted query parameter '{param}' is interpolated directly into SQL query.",
            target_file=target,
            start_line=8,
            end_line=8,
            ast_invariants=["sqlite3.cursor.execute with parameterized query tuple"]
        )

    def _generate_sqli_javascript(self, idx: int) -> PatchTrainingSample:
        res = self.resources[idx % len(self.resources)]
        param = self.params[idx % len(self.params)]
        tbl = self.tables[idx % len(self.tables)]
        col = self.columns[idx % len(self.columns)]
        
        vuln = (
            "import { Request, Response } from 'express';\n"
            "import db from '../database';\n\n"
            f"export async function get{res.capitalize()}(req: Request, res: Response) {{\n"
            f"    const {param} = req.query.{param};\n"
            f"    const result = await db.raw('SELECT * FROM {tbl} WHERE {col} = ' + {param});\n"
            "    return res.json(result.rows);\n"
            "}\n"
        )
        
        rep = (
            "import { Request, Response } from 'express';\n"
            "import db from '../database';\n\n"
            f"export async function get{res.capitalize()}(req: Request, res: Response) {{\n"
            f"    const {param} = req.query.{param};\n"
            f"    const result = await db.raw('SELECT * FROM {tbl} WHERE {col} = ?', [{param}]);\n"
            "    return res.json(result.rows);\n"
            "}\n"
        )
        
        target = f"src/controllers/{res}Controller.ts"
        return PatchTrainingSample(
            sample_id=f"PATCH-SQLI-TS-{idx:04d}",
            language="typescript",
            cwe_id="CWE-89",
            vulnerability_category="sql_injection",
            strategy=RepairStrategy.PARAMETERIZATION,
            vulnerable_code=vuln,
            repaired_code=rep,
            unified_diff=generate_unified_diff(vuln, rep, target),
            diagnostic_message=f"Direct concatenation of 'req.query.{param}' into SQL raw query.",
            target_file=target,
            start_line=6,
            end_line=6,
            ast_invariants=["db.raw parameterized replacement placeholder"]
        )

    def _generate_cmdi_python(self, idx: int) -> PatchTrainingSample:
        tool = self.tools[idx % len(self.tools)]
        
        vuln = (
            "import subprocess\n"
            "from flask import request, jsonify\n\n"
            f"@app.route('/tools/{tool}', methods=['POST'])\n"
            f"def run_{tool}():\n"
            "    host = request.json.get('host', '127.0.0.1')\n"
            f"    cmd = '{tool} -c 2 ' + host\n"
            "    output = subprocess.check_output(cmd, shell=True)\n"
            "    return jsonify({'result': output.decode('utf-8')})\n"
        )
        
        rep = (
            "import subprocess\n"
            "import ipaddress\n"
            "from flask import request, jsonify, abort\n\n"
            f"@app.route('/tools/{tool}', methods=['POST'])\n"
            f"def run_{tool}():\n"
            "    host = request.json.get('host', '127.0.0.1')\n"
            "    try:\n"
            "        clean_ip = str(ipaddress.ip_address(host.strip()))\n"
            "    except ValueError:\n"
            "        abort(400, description='Invalid IP address format')\n"
            f"    cmd = ['{tool}', '-c', '2', clean_ip]\n"
            "    output = subprocess.check_output(cmd, shell=False)\n"
            "    return jsonify({'result': output.decode('utf-8')})\n"
        )
        
        target = f"app/services/{tool}_runner.py"
        return PatchTrainingSample(
            sample_id=f"PATCH-CMDI-PY-{idx:04d}",
            language="python",
            cwe_id="CWE-78",
            vulnerability_category="command_injection",
            strategy=RepairStrategy.SAFE_API_SUBSTITUTION,
            vulnerable_code=vuln,
            repaired_code=rep,
            unified_diff=generate_unified_diff(vuln, rep, target),
            diagnostic_message="Unsanitized host parameter concatenated into shell=True subprocess execution.",
            target_file=target,
            start_line=7,
            end_line=8,
            ast_invariants=["subprocess list arguments with shell=False and strict IP validation"]
        )

    def _generate_path_traversal_python(self, idx: int) -> PatchTrainingSample:
        res = self.resources[idx % len(self.resources)]
        
        vuln = (
            "import os\n"
            "from flask import request, send_file, abort\n\n"
            f"@app.route('/download/{res}')\n"
            f"def download_{res}():\n"
            "    filename = request.args.get('filename', '')\n"
            f"    filepath = os.path.join('/var/storage/{res}s', filename)\n"
            "    return send_file(filepath)\n"
        )
        
        rep = (
            "import os\n"
            "from flask import request, send_file, abort\n"
            "from werkzeug.utils import secure_filename\n\n"
            f"BASE_DIR = os.path.abspath('/var/storage/{res}s')\n\n"
            f"@app.route('/download/{res}')\n"
            f"def download_{res}():\n"
            "    raw_name = request.args.get('filename', '')\n"
            "    safe_name = secure_filename(raw_name)\n"
            "    filepath = os.path.abspath(os.path.join(BASE_DIR, safe_name))\n"
            "    if not filepath.startswith(BASE_DIR + os.sep):\n"
            "        abort(403, description='Access denied: path outside storage boundary')\n"
            "    return send_file(filepath)\n"
        )
        
        target = f"app/controllers/{res}_download.py"
        return PatchTrainingSample(
            sample_id=f"PATCH-PATH-PY-{idx:04d}",
            language="python",
            cwe_id="CWE-22",
            vulnerability_category="path_traversal",
            strategy=RepairStrategy.BOUNDS_ENFORCEMENT,
            vulnerable_code=vuln,
            repaired_code=rep,
            unified_diff=generate_unified_diff(vuln, rep, target),
            diagnostic_message="os.path.join without prefix validation allows directory traversal sequences ('../').",
            target_file=target,
            start_line=6,
            end_line=7,
            ast_invariants=["secure_filename + canonical abspath prefix verification"]
        )

    def _generate_ssrf_python(self, idx: int) -> PatchTrainingSample:
        vuln = (
            "import requests\n"
            "from flask import request, jsonify\n\n"
            "@app.route('/api/webhook/preview', methods=['POST'])\n"
            "def preview_url():\n"
            "    target_url = request.json.get('url', '')\n"
            "    resp = requests.get(target_url, timeout=5)\n"
            "    return jsonify({'status': resp.status_code, 'body': resp.text[:500]})\n"
        )
        
        rep = (
            "import requests\n"
            "import ipaddress\n"
            "from urllib.parse import urlparse\n"
            "from flask import request, jsonify, abort\n\n"
            "def is_safe_url(target: str) -> bool:\n"
            "    parsed = urlparse(target)\n"
            "    if parsed.scheme not in ('http', 'https'): return False\n"
            "    hostname = parsed.hostname or ''\n"
            "    if hostname in ('localhost', '127.0.0.1', '::1', '169.254.169.254'): return False\n"
            "    try:\n"
            "        ip = ipaddress.ip_address(hostname)\n"
            "        if ip.is_private or ip.is_loopback: return False\n"
            "    except ValueError:\n"
            "        pass\n"
            "    return True\n\n"
            "@app.route('/api/webhook/preview', methods=['POST'])\n"
            "def preview_url():\n"
            "    target_url = request.json.get('url', '')\n"
            "    if not is_safe_url(target_url):\n"
            "        abort(400, description='SSRF Protection: Private and internal targets forbidden')\n"
            "    resp = requests.get(target_url, timeout=5, allow_redirects=False)\n"
            "    return jsonify({'status': resp.status_code, 'body': resp.text[:500]})\n"
        )
        
        target = "app/services/webhook_proxy.py"
        return PatchTrainingSample(
            sample_id=f"PATCH-SSRF-PY-{idx:04d}",
            language="python",
            cwe_id="CWE-918",
            vulnerability_category="ssrf",
            strategy=RepairStrategy.INPUT_SANITIZATION,
            vulnerable_code=vuln,
            repaired_code=rep,
            unified_diff=generate_unified_diff(vuln, rep, target),
            diagnostic_message="Unchecked HTTP request to user-supplied URL allows internal network SSRF exploration.",
            target_file=target,
            start_line=6,
            end_line=7,
            ast_invariants=["Scheme whitelist + IP loopback/private range blocking + allow_redirects=False"]
        )

    def _generate_deserialization_python(self, idx: int) -> PatchTrainingSample:
        vuln = (
            "import pickle\n"
            "import base64\n"
            "from flask import request, jsonify\n\n"
            "@app.route('/session/restore', methods=['POST'])\n"
            "def restore_session():\n"
            "    token = request.headers.get('X-Session-Token', '')\n"
            "    raw_bytes = base64.b64decode(token)\n"
            "    session_data = pickle.loads(raw_bytes)\n"
            "    return jsonify({'user': session_data.get('username')})\n"
        )
        
        rep = (
            "import json\n"
            "import base64\n"
            "from flask import request, jsonify, abort\n\n"
            "@app.route('/session/restore', methods=['POST'])\n"
            "def restore_session():\n"
            "    token = request.headers.get('X-Session-Token', '')\n"
            "    try:\n"
            "        raw_json = base64.b64decode(token).decode('utf-8')\n"
            "        session_data = json.loads(raw_json)\n"
            "    except Exception:\n"
            "        abort(400, description='Invalid session payload format')\n"
            "    return jsonify({'user': session_data.get('username')})\n"
        )
        
        target = "app/auth/session_loader.py"
        return PatchTrainingSample(
            sample_id=f"PATCH-DESER-PY-{idx:04d}",
            language="python",
            cwe_id="CWE-502",
            vulnerability_category="deserialization",
            strategy=RepairStrategy.SAFE_DESERIALIZATION,
            vulnerable_code=vuln,
            repaired_code=rep,
            unified_diff=generate_unified_diff(vuln, rep, target),
            diagnostic_message="Arbitrary code execution via pickle.loads on untrusted client session token.",
            target_file=target,
            start_line=8,
            end_line=8,
            ast_invariants=["Replace unsafe pickle.loads with deterministic json.loads"]
        )

    def _generate_idor_javascript(self, idx: int) -> PatchTrainingSample:
        res = self.resources[idx % len(self.resources)]
        
        vuln = (
            "import { Request, Response } from 'express';\n"
            f"import {{ {res.capitalize()}Model }} from '../models/{res}';\n\n"
            f"export async function get{res.capitalize()}Details(req: Request, res: Response) {{\n"
            f"    const {res}Id = req.params.id;\n"
            f"    const item = await {res.capitalize()}Model.findById({res}Id);\n"
            "    if (!item) return res.status(404).json({ error: 'Not found' });\n"
            "    return res.json(item);\n"
            "}\n"
        )
        
        rep = (
            "import { Request, Response } from 'express';\n"
            f"import {{ {res.capitalize()}Model }} from '../models/{res}';\n\n"
            f"export async function get{res.capitalize()}Details(req: Request, res: Response) {{\n"
            f"    const {res}Id = req.params.id;\n"
            "    const userId = (req as any).user?.id;\n"
            f"    const item = await {res.capitalize()}Model.findOne({{ _id: {res}Id, ownerId: userId }});\n"
            "    if (!item) return res.status(404).json({ error: 'Not found or unauthorized' });\n"
            "    return res.json(item);\n"
            "}\n"
        )
        
        target = f"src/handlers/{res}Handler.ts"
        return PatchTrainingSample(
            sample_id=f"PATCH-IDOR-TS-{idx:04d}",
            language="typescript",
            cwe_id="CWE-639",
            vulnerability_category="broken_object_level_authorization",
            strategy=RepairStrategy.AUTHORIZATION_CHECK,
            vulnerable_code=vuln,
            repaired_code=rep,
            unified_diff=generate_unified_diff(vuln, rep, target),
            diagnostic_message="Missing tenant/owner ownership constraint allows unauthorized cross-account object retrieval.",
            target_file=target,
            start_line=6,
            end_line=7,
            ast_invariants=["Bind query filter to authenticated user principal (ownerId)"]
        )

    def generate_full_dataset(self, num_samples: int = 1500) -> List[PatchTrainingSample]:
        """Generates a balanced multi-language patch synthesis dataset."""
        generators = [
            self._generate_sqli_python,
            self._generate_sqli_javascript,
            self._generate_cmdi_python,
            self._generate_path_traversal_python,
            self._generate_ssrf_python,
            self._generate_deserialization_python,
            self._generate_idor_javascript,
        ]
        
        samples: List[PatchTrainingSample] = []
        for i in range(num_samples):
            gen = generators[i % len(generators)]
            samples.append(gen(i))
            
        random.shuffle(samples)
        return samples
