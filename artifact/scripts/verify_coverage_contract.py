#!/usr/bin/env python3
"""Reviewer-facing coverage adequacy contract for the code artifact."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CORE_METHOD_FILES = {
    "repairwitness/certification.py",
    "repairwitness/duality.py",
    "repairwitness/interval.py",
    "repairwitness/oracle.py",
    "repairwitness/orlib.py",
    "repairwitness/suite.py",
    "repairwitness/weighted_interval.py",
    "action_suites/semantics.py",
    "action_suites/suite.py",
}
OVERALL_BRANCH_MINIMUM = 70.0
OVERALL_STATEMENT_MINIMUM = 75.0
CORE_BRANCH_MINIMUM = 60.0
CORE_STATEMENT_MINIMUM = 55.0


def load_json(relative: str) -> dict[str, object]:
    path = ROOT / relative
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    findings: list[dict[str, object]] = []
    coverage = load_json("verification/coverage.json")
    tests = load_json("verification/test_attestation.json")
    files = coverage.get("files", {}) if isinstance(coverage.get("files"), dict) else {}
    totals = coverage.get("totals", {}) if isinstance(coverage.get("totals"), dict) else {}

    branch = float(tests.get("branch_coverage_percent") or 0.0)
    statement = float(tests.get("statement_coverage_percent") or 0.0)
    branch_aware = float(tests.get("branch_aware_coverage_percent") or 0.0)
    passed = int(tests.get("passed") or 0)
    failed = int(tests.get("failed") or 0)

    if tests.get("status") != "PASS" or failed != 0 or passed < 70:
        findings.append({"kind": "test_attestation_not_passing", "status": tests.get("status"), "passed": passed, "failed": failed})
    if branch < OVERALL_BRANCH_MINIMUM:
        findings.append({"kind": "branch_coverage_below_contract", "branch_coverage_percent": branch, "minimum": OVERALL_BRANCH_MINIMUM})
    if statement < OVERALL_STATEMENT_MINIMUM:
        findings.append({"kind": "statement_coverage_below_contract", "statement_coverage_percent": statement, "minimum": OVERALL_STATEMENT_MINIMUM})
    if branch_aware < OVERALL_BRANCH_MINIMUM:
        findings.append({"kind": "branch_aware_coverage_below_contract", "branch_aware_coverage_percent": branch_aware, "minimum": OVERALL_BRANCH_MINIMUM})

    core_rows: list[dict[str, object]] = []
    for name in sorted(CORE_METHOD_FILES):
        file_entry = files.get(name)
        if not isinstance(file_entry, dict):
            findings.append({"kind": "core_file_missing_from_coverage", "file": name})
            continue
        summary = file_entry.get("summary", {})
        if not isinstance(summary, dict):
            findings.append({"kind": "core_file_missing_summary", "file": name})
            continue
        file_branch = float(summary.get("percent_branches_covered") or 100.0)
        file_statement = float(summary.get("percent_statements_covered") or 0.0)
        core_rows.append({"file": name, "branch_coverage_percent": file_branch, "statement_coverage_percent": file_statement})
        if file_branch < CORE_BRANCH_MINIMUM:
            findings.append({"kind": "core_file_branch_coverage_low", "file": name, "branch_coverage_percent": file_branch, "minimum": CORE_BRANCH_MINIMUM})
        if file_statement < CORE_STATEMENT_MINIMUM:
            findings.append({"kind": "core_file_statement_coverage_low", "file": name, "statement_coverage_percent": file_statement, "minimum": CORE_STATEMENT_MINIMUM})

    summary = {
        "schema_version": 1,
        "kind": "COVERAGE_CONTRACT",
        "status": "PASS" if not findings else "FAIL",
        "contract": "Coverage is branch-aware and complemented by differential, mutation, independent optimization checkers, redistributable synthetic controls, scalability, and clean-replay validation. The 70% overall branch gate is a release floor, not a sufficiency claim; each core method file must also retain at least 60% branch coverage and 55% statement coverage.",
        "overall_branch_minimum": OVERALL_BRANCH_MINIMUM,
        "overall_statement_minimum": OVERALL_STATEMENT_MINIMUM,
        "core_branch_minimum": CORE_BRANCH_MINIMUM,
        "core_statement_minimum": CORE_STATEMENT_MINIMUM,
        "passed_tests": passed,
        "failed_tests": failed,
        "statement_coverage_percent": statement,
        "branch_coverage_percent": branch,
        "branch_aware_coverage_percent": branch_aware,
        "covered_branches": totals.get("covered_branches"),
        "num_branches": totals.get("num_branches"),
        "core_method_files": core_rows,
        "finding_count": len(findings),
        "findings": findings,
    }
    (ROOT / "verification" / "coverage_contract.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
