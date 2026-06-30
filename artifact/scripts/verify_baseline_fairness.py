#!/usr/bin/env python3
"""Validate comparator and optimization-baseline fairness contracts."""
from __future__ import annotations

import json
import math
import subprocess
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

EXPECTED_COMPARATORS = {
    "RAW": {"uses_release_universe": False, "uses_repair_target": False},
    "STRUCTURAL": {"uses_release_universe": False, "uses_repair_target": True},
    "AFFECTED_SET": {"uses_release_universe": True, "uses_repair_target": False},
    "VERS": {"uses_release_universe": False, "uses_repair_target": False, "external_standard": False},
    "UNIVERS": {"uses_release_universe": True, "uses_repair_target": False},
    "ACTION": {"uses_release_universe": True, "uses_repair_target": True},
}
EXPECTED_DECISIONS = ["EQUIVALENT", "DIVERGENT", "ABSTAIN"]
EXPECTED_METRICS = {
    "coverage",
    "abstention_rate",
    "false_equivalence_count",
    "false_divergence_count",
    "precision_on_decided_divergence",
    "recall_on_action_divergence",
    "first_separation_stage",
}


def load_json(relative: str) -> dict[str, object]:
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def ensure_synthetic_summary() -> dict[str, object]:
    path = ROOT / "verification" / "synthetic_advisory_benchmark.json"
    if not path.exists():
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "verify_synthetic_advisory_benchmark.py")],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        print(result.stdout, end="")
        if result.returncode:
            return {"status": "FAIL", "findings": [{"kind": "synthetic_advisory_gate_failed"}]}
    return load_json("verification/synthetic_advisory_benchmark.json")


def main() -> int:
    findings: list[dict[str, object]] = []
    lock = load_json("config/baseline_lock.json")
    synthetic = ensure_synthetic_summary()
    public_overlap = load_json("verification/public_advisory_overlap.json")
    source = (ROOT / "action_suites" / "baselines.py").read_text(encoding="utf-8")
    tests = (ROOT / "tests" / "test_baselines.py").read_text(encoding="utf-8")
    orlib = load_json("benchmarks/orlib50/orlib_report.json")

    if lock.get("kind") != "BASELINE_LOCK" or lock.get("schema_version") != 2:
        findings.append({"kind": "baseline_lock_schema_changed", "kind_value": lock.get("kind"), "schema_version": lock.get("schema_version")})
    if lock.get("canonical_relation") != "ACTION":
        findings.append({"kind": "canonical_relation_not_action", "canonical_relation": lock.get("canonical_relation")})
    if lock.get("decision_domain") != EXPECTED_DECISIONS:
        findings.append({"kind": "decision_domain_changed", "decision_domain": lock.get("decision_domain")})
    policy = str(lock.get("denominator_policy", "")).lower()
    if "all qualified edges" not in policy or "abstentions" not in policy:
        findings.append({"kind": "denominator_policy_not_conservative", "policy": lock.get("denominator_policy")})

    comparators = lock.get("comparators", [])
    comparator_map = {row.get("id"): row for row in comparators if isinstance(row, dict)}
    if set(comparator_map) != set(EXPECTED_COMPARATORS):
        findings.append({"kind": "comparator_set_changed", "comparators": sorted(comparator_map)})
    for comparator_id, expected in EXPECTED_COMPARATORS.items():
        row = comparator_map.get(comparator_id)
        if not isinstance(row, dict):
            continue
        if not isinstance(row.get("definition"), str) or len(row["definition"]) < 20:
            findings.append({"kind": "comparator_definition_missing", "comparator": comparator_id})
        for field, expected_value in expected.items():
            if row.get(field) != expected_value:
                findings.append({"kind": "comparator_privilege_changed", "comparator": comparator_id, "field": field, "expected": expected_value, "actual": row.get(field)})

    metrics = set(lock.get("metrics", [])) if isinstance(lock.get("metrics"), list) else set()
    if not EXPECTED_METRICS.issubset(metrics):
        findings.append({"kind": "baseline_metrics_incomplete", "missing": sorted(EXPECTED_METRICS - metrics)})
    thresholds = lock.get("thresholds", {})
    if not isinstance(thresholds, dict) or any(value is not None for value in thresholds.values()):
        findings.append({"kind": "posthoc_threshold_detected", "thresholds": thresholds})
    controls = lock.get("negative_controls", [])
    if not isinstance(controls, list) or len(controls) < 4:
        findings.append({"kind": "negative_controls_incomplete", "negative_controls": controls})
    if synthetic.get("status") != "PASS":
        findings.append({"kind": "synthetic_advisory_gate_not_passing", "status": synthetic.get("status")})
    comparator_rows = synthetic.get("comparator_decision_rows", [])
    if not isinstance(comparator_rows, list):
        comparator_rows = []
        findings.append({"kind": "synthetic_comparator_rows_missing"})
    synthetic_comparators = {
        row.get("comparator")
        for row in comparator_rows
        if isinstance(row, dict)
    }
    if synthetic_comparators != set(EXPECTED_COMPARATORS):
        findings.append({"kind": "synthetic_comparator_set_changed", "comparators": sorted(str(item) for item in synthetic_comparators)})
    if int(synthetic.get("negative_control_count") or 0) < 50 or int(synthetic.get("negative_control_false_divergence_count") or 0) != 0:
        findings.append({
            "kind": "synthetic_negative_controls_failed",
            "negative_control_count": synthetic.get("negative_control_count"),
            "false_divergence": synthetic.get("negative_control_false_divergence_count"),
        })
    if public_overlap.get("status") != "PASS" or int(public_overlap.get("affected_set_equal_edges") or 0) != 3 or int(public_overlap.get("action_divergent_edges") or 0) != 3:
        findings.append({
            "kind": "public_overlap_construct_witness_failed",
            "status": public_overlap.get("status"),
            "affected_set_equal_edges": public_overlap.get("affected_set_equal_edges"),
            "action_divergent_edges": public_overlap.get("action_divergent_edges"),
        })

    if "from repairwitness" in source or "import repairwitness" in source:
        findings.append({"kind": "comparator_module_depends_on_optimizer"})
    for test_name in [
        "test_raw_and_normalized_equality_cover_equivalent_and_divergent_cases",
        "test_affected_set_abstains_on_unknown",
        "test_action_relation_distinguishes_missing_unknown_equal_and_divergent",
        "test_universe_affected_equality_handles_executable_and_unknown_ranges",
    ]:
        if test_name not in tests:
            findings.append({"kind": "baseline_test_missing", "test": test_name})

    rows = orlib.get("rows", []) if isinstance(orlib.get("rows"), list) else []
    if int(orlib.get("instance_count") or 0) != 50 or len(rows) != 50:
        findings.append({"kind": "orlib_baseline_instance_count_changed", "instance_count": orlib.get("instance_count"), "row_count": len(rows)})
    ratios: dict[str, list[float]] = {"greedy": [], "lp_guided": [], "bounded_milp": []}
    for row in rows:
        optimum = row.get("known_optimum")
        if isinstance(optimum, bool) or not isinstance(optimum, int) or optimum < 1:
            findings.append({"kind": "orlib_known_optimum_invalid", "name": row.get("name"), "known_optimum": optimum})
            continue
        for method in ratios:
            result = row.get(method, {})
            if not isinstance(result, dict):
                findings.append({"kind": "orlib_method_result_missing", "name": row.get("name"), "method": method})
                continue
            cost = result.get("cost")
            ratio = result.get("ratio")
            if isinstance(cost, int) and not isinstance(cost, bool) and ratio is not None:
                expected = cost / optimum
                if not math.isclose(expected, float(ratio), rel_tol=0, abs_tol=1e-12):
                    findings.append({"kind": "orlib_ratio_not_replayable", "name": row.get("name"), "method": method})
                ratios[method].append(float(ratio))
    if len(ratios["greedy"]) != 50 or len(ratios["lp_guided"]) != 50 or len(ratios["bounded_milp"]) != 50:
        findings.append({"kind": "orlib_method_completion_incomplete", "completed": {key: len(value) for key, value in ratios.items()}})
    if ratios["bounded_milp"] and max(ratios["bounded_milp"]) > 1.02:
        findings.append({"kind": "bounded_milp_quality_not_within_contract", "max_ratio": max(ratios["bounded_milp"])})
    if ratios["greedy"] and ratios["bounded_milp"] and statistics.fmean(ratios["greedy"]) <= statistics.fmean(ratios["bounded_milp"]):
        findings.append({"kind": "greedy_baseline_order_unexpected"})

    summary = {
        "schema_version": 1,
        "kind": "BASELINE_FAIRNESS",
        "status": "PASS" if not findings else "FAIL",
        "contract": "Comparator baselines are locked before outcomes, retain abstentions in the denominator, disclose whether each comparator uses release-universe or repair-target information, report decision/abstention rates on redistributable synthetic controls, and replay a public-overlap construct witness where affected-set equality hides action divergence; OR-Library optimization baselines replay ratios from the same instances and known optima.",
        "comparator_count": len(comparator_map),
        "decision_domain": lock.get("decision_domain"),
        "canonical_relation": lock.get("canonical_relation"),
        "threshold_policy": "NO_POSTHOC_EFFECT_OR_SIGNIFICANCE_THRESHOLDS",
        "synthetic_advisory_status": synthetic.get("status"),
        "synthetic_negative_control_count": synthetic.get("negative_control_count"),
        "synthetic_negative_control_false_divergence_count": synthetic.get("negative_control_false_divergence_count"),
        "public_overlap_affected_set_equal_edges": public_overlap.get("affected_set_equal_edges"),
        "public_overlap_action_divergent_edges": public_overlap.get("action_divergent_edges"),
        "comparator_decision_rows": comparator_rows,
        "orlib_instances": len(rows),
        "orlib_greedy_mean_ratio": statistics.fmean(ratios["greedy"]) if ratios["greedy"] else None,
        "orlib_lp_guided_mean_ratio": statistics.fmean(ratios["lp_guided"]) if ratios["lp_guided"] else None,
        "orlib_bounded_milp_mean_ratio": statistics.fmean(ratios["bounded_milp"]) if ratios["bounded_milp"] else None,
        "finding_count": len(findings),
        "findings": findings,
    }
    (ROOT / "verification" / "baseline_fairness.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
