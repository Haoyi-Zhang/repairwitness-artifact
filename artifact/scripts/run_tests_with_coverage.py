#!/usr/bin/env python3
"""Run the deterministic tests and refresh branch-aware coverage evidence."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(command: list[str]) -> str:
    env = {**os.environ, "PYTHONPATH": str(ROOT), "PYTHONDONTWRITEBYTECODE": "1"}
    result = subprocess.run(command, cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    print(result.stdout, end="")
    if result.returncode:
        raise SystemExit(result.returncode)
    return result.stdout


def percent(numerator: int | float, denominator: int | float) -> float:
    return (100.0 * float(numerator) / float(denominator)) if denominator else 100.0


def main() -> int:
    coverage_file = ROOT / ".coverage"
    if coverage_file.exists():
        coverage_file.unlink()
    output = run([
        sys.executable,
        "-m",
        "coverage",
        "run",
        "--branch",
        "--source=repairwitness,action_suites",
        "-m",
        "pytest",
        "-q",
        "-p",
        "no:cacheprovider",
    ])
    run([sys.executable, "-m", "coverage", "json", "-o", "verification/coverage.json"])
    report = run([sys.executable, "-m", "coverage", "report"])
    (ROOT / "verification" / "coverage.txt").write_text(report, encoding="utf-8")

    coverage = json.loads((ROOT / "verification" / "coverage.json").read_text(encoding="utf-8"))
    totals = coverage["totals"]
    passed_match = re.search(r"(\d+) passed", output)
    failed_match = re.search(r"(\d+) failed", output)
    covered_branches = int(totals.get("covered_branches", 0))
    num_branches = int(totals.get("num_branches", 0))
    covered_lines = int(totals.get("covered_lines", 0))
    num_statements = int(totals.get("num_statements", 0))
    attestation = {
        "schema_version": 1,
        "kind": "TEST_ATTESTATION",
        "status": "PASS",
        "command": "python -m coverage run --branch --source=repairwitness,action_suites -m pytest -q -p no:cacheprovider",
        "passed": int(passed_match.group(1)) if passed_match else 0,
        "failed": int(failed_match.group(1)) if failed_match else 0,
        "statement_coverage_percent": percent(covered_lines, num_statements),
        "branch_coverage_percent": percent(covered_branches, num_branches),
        "branch_aware_coverage_percent": float(totals.get("percent_covered", 0.0)),
        "covered_branches": covered_branches,
        "num_branches": num_branches,
        "covered_lines": covered_lines,
        "num_statements": num_statements,
    }
    (ROOT / "verification" / "test_attestation.json").write_text(json.dumps(attestation, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if coverage_file.exists():
        coverage_file.unlink()
    print(json.dumps(attestation, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
