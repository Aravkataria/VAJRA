# app/verification/security_test/poc_templates.py

import os
import pickle
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

SUPPORTED_DYNAMIC_TYPES = {
    "unsafe-eval",
    "unsafe-exec",
    "command-injection-risk",
    "unsafe-deserialization",
}


@dataclass
class Poc:
    payload: Any
    delivery: str = "any"


class _TouchGadget:
    def __init__(self, marker_path: str):
        self.marker_path = marker_path

    def __reduce__(self):
        return (Path(self.marker_path).touch, ())


def _marker_write_command(marker_path: str) -> str:
    norm = Path(marker_path).as_posix()
    return f'"{sys.executable}" -c "import pathlib; pathlib.Path({norm!r}).touch()"'


def _pickle_payload(marker_path: str) -> bytes:
    return pickle.dumps(_TouchGadget(marker_path))


def build_poc(
    vulnerability_type: str, marker_path: str, call_name: Optional[str] = None
) -> Optional[Poc]:
    norm = Path(marker_path).as_posix()

    if vulnerability_type in ("unsafe-eval", "unsafe-exec"):
        payload = f"__import__('pathlib').Path({norm!r}).touch()"
        return Poc(payload=payload)

    if vulnerability_type == "command-injection-risk":
        payload = _marker_write_command(marker_path)
        return Poc(payload=payload)

    if vulnerability_type == "unsafe-deserialization":
        if call_name in ("pickle.load", "pickle.loads"):
            return Poc(payload=_pickle_payload(marker_path), delivery="bytes-arg-only")

        payload = f'!!python/object/apply:builtins.open ["{norm}", "w"]'
        return Poc(payload=payload)

    return None