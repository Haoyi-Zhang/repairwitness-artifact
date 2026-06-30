#!/usr/bin/env python3
"""Short offline smoke check for the submitted RepairWitness tree."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent


def run(command: list[str], cwd: Path = ROOT) -> tuple[bool, str]:
    env = {**os.environ, "PYTHONPATH": str(ROOT), "PYTHONDONTWRITEBYTECODE": "1"}
    result = subprocess.run(command, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    return result.returncode == 0, result.stdout


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, default=REPO)
    parser.add_argument("--skip-tests", action="store_true")
    args = parser.parse_args()
    root = args.project_root.resolve()
    artifact = root / "artifact"
    failures: list[str] = []
    outputs: dict[str, str] = {}
    if not args.skip_tests:
        ok, output = run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"], artifact)
        outputs["tests"] = output[-1200:]
        if not ok:
            failures.append("tests")
    ok, output = run([sys.executable, "scripts/validate_results.py"], artifact)
    outputs["result_validation"] = output[-1200:]
    if not ok:
        failures.append("result_validation")
    ok, output = run([sys.executable, "scripts/audit_artifact.py", "--root", str(root)], artifact)
    outputs["audit"] = output[-1200:]
    if not ok:
        failures.append("audit")
    report = {
        "schema_version": 1,
        "kind": "REPAIRWITNESS_SMOKE",
        "status": "PASS" if not failures else "FAIL",
        "failures": failures,
        "outputs": outputs,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    print("REPAIRWITNESS_SMOKE=" + report["status"])
    return 0 if not failures else 2


if __name__ == "__main__":
    raise SystemExit(main())
