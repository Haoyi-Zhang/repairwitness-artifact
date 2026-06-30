#!/usr/bin/env python3
"""Independent validation of bundled empirical and algorithmic result files."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import subprocess
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run_gate(script: str) -> dict[str, object]:
    result = subprocess.run([sys.executable, str(ROOT / "scripts" / script)], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    print(result.stdout, end="")
    if result.returncode:
        return {"status": "FAIL", "errors": [f"{script} returned {result.returncode}"]}
    output_name = {
        "verify_coverage_contract.py": "coverage_contract.json",
        "verify_safetydb_historical_scope.py": "safetydb_historical_scope.json",
        "verify_synthetic_advisory_benchmark.py": "synthetic_advisory_benchmark.json",
        "verify_public_advisory_overlap.py": "public_advisory_overlap.json",
        "verify_adversarial_scalability.py": "adversarial_scalability.json",
        "verify_optimization_impact.py": "optimization_impact.json",
        "verify_baseline_fairness.py": "baseline_fairness.json",
        "verify_temporal_scope.py": "temporal_scope.json",
    }[script]
    return json.loads((ROOT / "verification" / output_name).read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_without_report_sha(value: dict[str, object]) -> bytes:
    payload = dict(value)
    payload.pop("report_sha256", None)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def validate_orlib() -> dict[str, object]:
    folder = ROOT / "benchmarks" / "orlib50"
    report = json.loads((folder / "orlib_report.json").read_text(encoding="utf-8"))
    rows = report["rows"]
    errors: list[str] = []
    if report.get("instance_count") != 50 or len(rows) != 50:
        errors.append("OR-Library report does not contain exactly 50 instances")
    names = [row["name"] for row in rows]
    if len(set(names)) != 50:
        errors.append("OR-Library instance names are not unique")
    for row in rows:
        path = folder / "inputs" / f"{row['name']}.txt"
        if not path.is_file():
            errors.append(f"missing OR-Library input {path.name}")
            continue
        if sha256(path) != row["input_sha256"]:
            errors.append(f"input digest mismatch for {row['name']}")
        optimum = row["known_optimum"]
        for method in ("greedy", "lp_guided", "bounded_milp"):
            result = row[method]
            if result.get("cost") is None:
                continue
            expected = result["cost"] / optimum
            if not math.isclose(expected, result["ratio"], rel_tol=0, abs_tol=1e-12):
                errors.append(f"ratio mismatch for {row['name']} {method}")
    expected_digest = hashlib.sha256(canonical_without_report_sha(report)).hexdigest()
    if report.get("report_sha256") != expected_digest:
        errors.append("OR-Library report digest mismatch")

    csv_rows = list(csv.DictReader((folder / "orlib_results.csv").open(encoding="utf-8")))
    if len(csv_rows) != 50:
        errors.append("OR-Library CSV does not contain 50 rows")

    summary = report["summary"]
    for method in ("greedy", "lp_guided", "bounded_milp"):
        ratios = [float(row[method]["ratio"]) for row in rows if row[method].get("ratio") is not None]
        if len(ratios) != summary[method]["completed"]:
            errors.append(f"completed count mismatch for {method}")
        if not math.isclose(statistics.fmean(ratios), summary[method]["mean_ratio"], abs_tol=1e-12):
            errors.append(f"mean ratio mismatch for {method}")
    return {
        "status": "PASS" if not errors else "FAIL",
        "errors": errors,
        "instances": len(rows),
        "input_bytes": sum((folder / "inputs" / f"{name}.txt").stat().st_size for name in names),
        "report_sha256": report.get("report_sha256"),
    }


def validate_safetydb() -> dict[str, object]:
    path = ROOT / "verification" / "safetydb_external_summary.json"
    report = json.loads(path.read_text(encoding="utf-8"))
    errors: list[str] = []
    inventory = report["inventory"]
    dispositions = inventory["edge_dispositions"]
    if sum(dispositions.values()) != inventory["edges"]:
        errors.append("SafetyDB edge disposition total mismatch")
    solver = report["solver"]
    if solver["groups_executed"] != inventory["groups_with_concrete_divergence"]:
        errors.append("SafetyDB group execution count mismatch")
    if not solver["all_certificates_valid"] or solver["highs_exact_agreement"] != solver["groups_executed"]:
        errors.append("SafetyDB solver agreement is incomplete")
    return {
        "status": "PASS" if not errors else "FAIL",
        "errors": errors,
        "edges": inventory["edges"],
        "divergent_edges": dispositions["RESOLVED_DIVERGENT"],
        "groups": solver["groups_executed"],
    }


def validate_method_reports() -> dict[str, object]:
    method = json.loads((ROOT / "verification" / "method_validation.json").read_text())
    release_method = json.loads((ROOT / "verification" / "method_validation_release.json").read_text())
    mutation = json.loads((ROOT / "verification" / "mutation_validation.json").read_text())
    crosscheck = json.loads((ROOT / "verification" / "mutation_crosscheck.json").read_text())
    scale = json.loads((ROOT / "verification" / "interval_scalability.json").read_text())
    ordered_scale = json.loads((ROOT / "verification" / "ordered_interval_scalability.json").read_text())
    errors: list[str] = []
    if method.get("counterexamples") != 0 or method.get("total_certificates_replayed") != 1900:
        errors.append("method validation summary mismatch")
    if release_method.get("status") != "PASS" or release_method.get("general_weighted_multicover", {}).get("exact_oracle_agreement") != 192:
        errors.append("release method validation report mismatch")
    if mutation.get("detected") != mutation.get("mutations"):
        errors.append("semantic mutation detection is incomplete")
    if crosscheck.get("detected_count") != crosscheck.get("mutation_count") or crosscheck.get("mutation_count") != 35:
        errors.append("35-field mutation cross-check is incomplete")
    if scale.get("status") != "PASS" or scale.get("row_count") != 4:
        errors.append("scalability report is incomplete")
    ordered_rows = ordered_scale.get("rows", []) if isinstance(ordered_scale.get("rows"), list) else []
    if ordered_scale.get("status") != "PASS" or len(ordered_rows) != 3 or max(row.get("release_count", 0) for row in ordered_rows) < 100000:
        errors.append("ordered interval scalability report is incomplete")
    return {
        "status": "PASS" if not errors else "FAIL",
        "errors": errors,
        "certificates_replayed": method.get("total_certificates_replayed"),
        "release_general_exact_agreement": release_method.get("general_weighted_multicover", {}).get("exact_oracle_agreement"),
        "semantic_mutations_detected": mutation.get("detected"),
        "crosscheck_mutations_detected": crosscheck.get("detected_count"),
        "scale_rows": scale.get("row_count"),
        "ordered_scale_rows": len(ordered_rows),
    }


def main() -> None:
    result = {
        "schema_version": 1,
        "orlib50": validate_orlib(),
        "safetydb": validate_safetydb(),
        "method": validate_method_reports(),
        "coverage": run_gate("verify_coverage_contract.py"),
        "safetydb_scope": run_gate("verify_safetydb_historical_scope.py"),
        "synthetic_advisory": run_gate("verify_synthetic_advisory_benchmark.py"),
        "public_advisory_overlap": run_gate("verify_public_advisory_overlap.py"),
        "adversarial_scalability": run_gate("verify_adversarial_scalability.py"),
        "optimization_impact": run_gate("verify_optimization_impact.py"),
        "baseline_fairness": run_gate("verify_baseline_fairness.py"),
        "temporal_scope": run_gate("verify_temporal_scope.py"),
    }
    result["status"] = "PASS" if all(section["status"] == "PASS" for section in result.values() if isinstance(section, dict) and "status" in section) else "FAIL"
    output = ROOT / "verification" / "result_validation.json"
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if result["status"] == "PASS" else 1)


if __name__ == "__main__":
    main()
