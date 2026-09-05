# tests/test_performance_engine.py

import tempfile
import unittest
from pathlib import Path

from app.analysis.performance_engine import PerformanceEngine, PerformanceProfile
from app.analysis.workspace_scan import scan_workspace_full, scan_workspace_performance


class PerformanceEngineTests(unittest.TestCase):
    def setUp(self):
        self.engine = PerformanceEngine()

    def test_detect_quadratic_loop_lookup(self):
        code = """
def find_matches(items, targets):
    result = []
    for item in items:
        if item in targets:
            result.append(item)
    return result
"""
        advice = self.engine.analyze_source("test_code.py", code)
        self.assertTrue(any(a.rule_id == "PERF-01-QUADRATIC-LOOKUP" for a in advice))
        quad_advice = [a for a in advice if a.rule_id == "PERF-01-QUADRATIC-LOOKUP"][0]
        self.assertEqual(quad_advice.severity, "high")
        self.assertIn("targets", quad_advice.message)
        self.assertIn("set", quad_advice.suggested_rewrite)

    def test_detect_sync_blocking_in_async(self):
        code = """
import time
import requests

async def handle_request(url):
    time.sleep(1.0)
    resp = requests.get(url)
    return resp.text
"""
        advice = self.engine.analyze_source("async_handler.py", code)
        async_rules = [a for a in advice if a.rule_id == "PERF-02-SYNC-BLOCKING-IN-ASYNC"]
        self.assertGreaterEqual(len(async_rules), 2)
        self.assertTrue(any("time.sleep" in a.message or "sleep" in a.message for a in async_rules))
        self.assertTrue(any("requests.get" in a.message for a in async_rules))

    def test_detect_repeated_regex_compilation_in_loop(self):
        code = """
import re

def parse_logs(lines):
    matches = []
    for line in lines:
        if re.search(r"ERROR:\\s+(\\w+)", line):
            matches.append(line)
    return matches
"""
        advice = self.engine.analyze_source("parser.py", code)
        regex_rules = [a for a in advice if a.rule_id == "PERF-03-REPEATED-REGEX-COMPILATION"]
        self.assertEqual(len(regex_rules), 1)
        self.assertIn("re.compile", regex_rules[0].suggested_rewrite)

    def test_detect_repeated_disk_io_in_loop(self):
        code = """
def process_items(filenames):
    data = []
    for name in filenames:
        with open(name, 'r') as f:
            data.append(f.read())
    return data
"""
        advice = self.engine.analyze_source("io_task.py", code)
        io_rules = [a for a in advice if a.rule_id == "PERF-04-REPEATED-DISK-IO-IN-LOOP"]
        self.assertEqual(len(io_rules), 1)
        self.assertIn("syscall", io_rules[0].message)

    def test_detect_quadratic_string_concat_in_loop(self):
        code = """
def build_output(tokens):
    s = ""
    for t in tokens:
        s += t
    return s
"""
        advice = self.engine.analyze_source("builder.py", code)
        str_rules = [a for a in advice if a.rule_id == "PERF-05-QUADRATIC-STRING-CONCAT"]
        self.assertEqual(len(str_rules), 1)
        self.assertIn("join", str_rules[0].suggested_rewrite)

    def test_clean_code_produces_no_false_positives(self):
        code = """
import asyncio
import re

REGEX = re.compile(r"\\d+")

async def clean_worker(items):
    item_set = set(items)
    await asyncio.sleep(0.1)
    return [x for x in item_set if REGEX.match(str(x))]
"""
        advice = self.engine.analyze_source("clean.py", code)
        self.assertEqual(len(advice), 0)

    def test_performance_profile_delta_calculation(self):
        profile = PerformanceProfile.from_durations(baseline_ms=100.0, patched_ms=60.0, memory_delta_kb=-12.5)
        self.assertTrue(profile.is_faster)
        self.assertEqual(profile.speedup_percentage, 40.0)
        self.assertEqual(profile.memory_delta_kb, -12.5)

    def test_workspace_full_dual_scan(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            # Vulnerable file + performance hotspot
            (root / "mixed.py").write_text(
                """import yaml\ndef load(data):\n    return yaml.load(data)\n\ndef slow(items, targets):\n    res = []\n    for i in items:\n        if i in targets:\n            res.append(i)\n    return res\n""",
                encoding="utf-8"
            )

            res = scan_workspace_full(root)
            self.assertIn("security_findings", res)
            self.assertIn("performance_advice", res)
            self.assertGreaterEqual(len(res["security_findings"]), 1)
            self.assertGreaterEqual(len(res["performance_advice"]), 1)
            self.assertEqual(res["performance_advice"][0].rule_id, "PERF-01-QUADRATIC-LOOKUP")


if __name__ == "__main__":
    unittest.main()
