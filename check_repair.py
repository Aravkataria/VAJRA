# check_repair.py

import logging
import os
import sys
from pathlib import Path

from app.analysis.deterministic_analyst import DeterministicAnalyst
from app.analysis.python_static import analyze_source
from app.decision.engine import decide
from app.evidence.evidence import Evidence
from app.repair.repairer import build_default_repairer
from app.repair.patch_applier import PatchApplier
from app.verification.verifier import build_default_verifier


def main():
    if os.environ.get("VAJRA_REPAIR_DEBUG", "").lower() in ("1", "true", "yes"):
        logging.basicConfig(level=logging.INFO, format="%(name)s: %(message)s")

    if len(sys.argv) != 3:
        print("Usage: python check_repair.py <workspace_id> <relative_file_path>")
        raise SystemExit(1)

    workspace_id, relative_file = sys.argv[1:]
    workspace_path = Path("workspaces") / workspace_id
    source_path = workspace_path / relative_file

    if not source_path.is_file():
        print(f"File not found: {source_path.resolve()}")
        raise SystemExit(1)

    source = source_path.read_text(encoding="utf-8")
    findings = analyze_source(relative_file, source)
    print(f"Found {len(findings)} finding(s) in {relative_file}:")
    for f in findings:
        print(f"  - line {f.line}: {f.vulnerability_type} ({f.severity})")

    if not findings:
        return

    analyst = DeterministicAnalyst()
    repairer = build_default_repairer()
    verifier = build_default_verifier()
    applier = PatchApplier()

    print("\nRepairer chain:", [type(m).__name__ for m in repairer.models])

    for finding in findings:
        evidence = Evidence.from_finding(finding, repository=workspace_id)
        assessment = analyst.analyze(evidence)
        decision = decide(evidence, assessment)

        print(f"\n--- {finding.vulnerability_type} @ line {finding.line} ---")
        print(f"  confirmed: {assessment.confirmed} (confidence {assessment.confidence:.2f})")
        print(f"  route:     {decision.route}")
        print(f"  reason:    {decision.reason}")

        patch, attempts = repairer.repair_with_trace(decision, workspace_path)
        print("  attempts:")
        for attempt in attempts:
            print(f"    - {attempt.model}: {attempt.status} ({attempt.reason})")

        if patch is None:
            print("  patch:     NO PATCH")
            continue

        print("  patch:     PROPOSED")
        print("  strategy: ", patch.strategy)
        print("  confidence:", patch.confidence)
        print("  diff:\n" + (patch.diff or "<empty>"))

        verification = verifier.verify(patch, workspace_path)
        print(f"  verified:  {verification.verified} ({verification.method})")
        print(f"  reason:    {verification.reason}")
        if verification.remaining_findings:
            print(f"  remaining: {verification.remaining_findings}")

        if verification.verified:
            application = applier.apply(patch, workspace_path)
            print(f"  applied:   {application.applied}")
            print(f"  apply reason: {application.reason}")
        else:
            print("  applied:   SKIPPED")


if __name__ == "__main__":
    main()
