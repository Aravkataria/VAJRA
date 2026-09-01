# tests/test_syntax_checkers.py

"""
Each checker must catch a real syntax error and pass valid syntax for
its language. JS/TS/Shell checkers shell out to node/tsc/bash -- if
that tool isn't installed in the environment running these tests, the
checker returns None and the test is skipped rather than failed.
"""

import os
import shutil
import pytest

from app.verification.syntax.checkers import (
    check_javascript,
    check_json,
    check_python,
    check_shell,
    check_yaml,
)


def test_python_catches_syntax_error():
    ok, _ = check_python("def f(:\n    pass", "f.py")
    assert not ok


def test_python_accepts_valid_source():
    ok, _ = check_python("def f():\n    pass", "f.py")
    assert ok


def test_json_catches_syntax_error():
    ok, _ = check_json('{"a": }', "f.json")
    assert not ok


def test_json_accepts_valid_source():
    ok, _ = check_json('{"a": 1}', "f.json")
    assert ok


def test_yaml_catches_syntax_error():
    result = check_yaml("a: [1, 2\nb: 3", "f.yaml")
    if result is None:
        pytest.skip("PyYAML not installed")
    ok, _ = result
    assert not ok


def test_yaml_accepts_valid_source():
    result = check_yaml("a: 1\nb: 2", "f.yaml")
    if result is None:
        pytest.skip("PyYAML not installed")
    ok, _ = result
    assert ok


def test_javascript_catches_syntax_error():
    if shutil.which("node") is None:
        pytest.skip("node not installed")
    ok, _ = check_javascript("function f( {\n  return 1\n}", "f.js")
    assert not ok


def test_javascript_accepts_valid_source():
    if shutil.which("node") is None:
        pytest.skip("node not installed")
    ok, _ = check_javascript("function f() {\n  return 1;\n}", "f.js")
    assert ok


def test_shell_catches_syntax_error():
    if os.name == "nt" or shutil.which("bash") is None:
        pytest.skip("bash not installed or on Windows")
    ok, _ = check_shell("if [ 1 -eq 1 ]\n  echo hi", "f.sh")
    assert not ok


def test_shell_accepts_valid_source():
    if os.name == "nt" or shutil.which("bash") is None:
        pytest.skip("bash not installed or on Windows")
    ok, _ = check_shell("if [ 1 -eq 1 ]; then\n  echo hi\nfi", "f.sh")
    assert ok