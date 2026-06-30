#!/usr/bin/env python3
"""Validate practical optimization impact across real and external benchmarks."""
from __future__ import annotations

import json
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_json(relative: str) -> dict[str, object]:
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def main() -> int:
    findings: list[dict[str, object]] = []
    safety = load_json("verification/safetydb_external_summary.json")
    method = load_json("verification/method_validation.json")
    scale = load_json("verification/interval_scalability.json")
    ordered_scale = load_json("verification/ordered_interval_scalability.json")
    adversarial = load_json("verification/adversarial_scalability.json")
    synthetic = load_json("verification/synthetic_advisory_benchmark.json")
    public_overlap = load_json("verification/public_advisory_overlap.json")
    orlib = load_json("benchmarks/orlib50/orlib_report.json")
    solver = safety.get("solver", {}) if isinstance(safety.get("solver"), dict) else {}
    rows = orlib.get("rows", []) if isinstance(orlib.get("rows"), list) else []

    bounded_ratios = [float(row["bounded_milp"]["ratio"]) for row in rows if row.get("bounded_milp", {}).get("ratio") is not None]
    greedy_ratios = [float(row["greedy"]["ratio"]) for row in rows if row.get("greedy", {}).get("ratio") is not None]
    lp_ratios = [float(row["lp_guided"]["ratio"]) for row in rows if row.get("lp_guided", {}).get("ratio") is not None]
    bounded_optima = sum(1 for ratio in bounded_ratios if abs(ratio - 1.0) <= 1e-12)
    median_compression = float(solver.get("median_compression_vs_all_witnesses") or 0.0)

    if int(solver.get("groups_executed") or 0) != 97 or int(solver.get("highs_exact_agreement") or 0) != 97:
        findings.append({"kind": "safetydb_exact_agreement_incomplete", "groups": solver.get("groups_executed"), "highs_exact_agreement": solver.get("highs_exact_agreement")})
    if method.get("counterexamples") != 0 or int(method.get("total_certificates_replayed") or 0) != 1900:
        findings.append({"kind": "controlled_validation_contract_failed", "counterexamples": method.get("counterexamples"), "certificates": method.get("total_certificates_replayed")})
    if scale.get("status") != "PASS" or int(scale.get("max_release_count") or 0) < 100000 or int(scale.get("max_obligation_count") or 0) < 100000:
        findings.append({"kind": "scalability_contract_failed", "status": scale.get("status"), "max_release_count": scale.get("max_release_count"), "max_obligation_count": scale.get("max_obligation_count")})
    ordered_rows = ordered_scale.get("rows", []) if isinstance(ordered_scale.get("rows"), list) else []
    if ordered_scale.get("status") != "PASS" or len(ordered_rows) != 3 or max((int(row.get("release_count") or 0) for row in ordered_rows if isinstance(row, dict)), default=0) < 100000:
        findings.append({"kind": "ordered_scalability_contract_failed", "status": ordered_scale.get("status"), "row_count": len(ordered_rows)})
    if adversarial.get("status") != "PASS" or int(adversarial.get("release_count") or 0) < 10000 or int(adversarial.get("obligation_count") or 0) < 20000:
        findings.append({"kind": "adversarial_scalability_contract_failed", "status": adversarial.get("status"), "release_count": adversarial.get("release_count"), "obligation_count": adversarial.get("obligation_count")})
    if synthetic.get("status") != "PASS" or int(synthetic.get("negative_control_false_divergence_count") or 0) != 0:
        findings.append({"kind": "synthetic_advisory_contract_failed", "status": synthetic.get("status"), "false_divergence": synthetic.get("negative_control_false_divergence_count")})
    if public_overlap.get("status") != "PASS" or int(public_overlap.get("action_divergent_edges") or 0) != 3:
        findings.append({"kind": "public_overlap_contract_failed", "status": public_overlap.get("status"), "action_divergent_edges": public_overlap.get("action_divergent_edges")})
    if int(orlib.get("instance_count") or 0) != 50 or len(bounded_ratios) != 50:
        findings.append({"kind": "orlib_instance_count_changed", "instance_count": orlib.get("instance_count"), "bounded_completed": len(bounded_ratios)})
    if bounded_optima < 49 or max(bounded_ratios or [999.0]) > 1.02:
        findings.append({"kind": "orlib_bounded_milp_quality_regressed", "bounded_optima": bounded_optima, "max_ratio": max(bounded_ratios or [0.0])})
    if greedy_ratios and bounded_ratios and statistics.fmean(greedy_ratios) <= statistics.fmean(bounded_ratios):
        findings.append({"kind": "optimization_baseline_order_unexpected", "greedy_mean_ratio": statistics.fmean(greedy_ratios), "bounded_mean_ratio": statistics.fmean(bounded_ratios)})

    summary = {
        "schema_version": 1,
        "kind": "OPTIMIZATION_IMPACT",
        "status": "PASS" if not findings else "FAIL",
        "contract": "Impact evidence is reported through historical SafetyDB witness compression, public-overlap source-level construct replay, independent optimization agreement, OR-Library quality, mutation rejection, redistributable synthetic action controls, ordered 100k-release scalability, and dense-overlap scalability. The historical compression magnitude is descriptive evidence, not a pass/fail threshold.",
        "safetydb_groups": solver.get("groups_executed"),
        "safetydb_highs_exact_agreement": solver.get("highs_exact_agreement"),
        "median_compression_vs_all_witnesses": median_compression,
        "safetydb_exact_objective_median": solver.get("exact_objective_median"),
        "safetydb_exact_objective_max": solver.get("exact_objective_max"),
        "controlled_certificates_replayed": method.get("total_certificates_replayed"),
        "controlled_counterexamples": method.get("counterexamples"),
        "orlib_instances": orlib.get("instance_count"),
        "orlib_bounded_optima": bounded_optima,
        "orlib_bounded_mean_ratio": statistics.fmean(bounded_ratios) if bounded_ratios else None,
        "orlib_bounded_max_ratio": max(bounded_ratios) if bounded_ratios else None,
        "orlib_greedy_mean_ratio": statistics.fmean(greedy_ratios) if greedy_ratios else None,
        "orlib_lp_guided_mean_ratio": statistics.fmean(lp_ratios) if lp_ratios else None,
        "max_release_count": scale.get("max_release_count"),
        "max_obligation_count": scale.get("max_obligation_count"),
        "max_solve_seconds": (float(scale.get("solve_elapsed_ns", {}).get("max")) / 1_000_000_000.0) if isinstance(scale.get("solve_elapsed_ns"), dict) else None,
        "ordered_scalability_max_solve_seconds": max((float(row.get("solve_seconds") or 0.0) for row in ordered_rows if isinstance(row, dict)), default=None),
        "adversarial_release_count": adversarial.get("release_count"),
        "adversarial_obligation_count": adversarial.get("obligation_count"),
        "adversarial_solve_seconds": adversarial.get("solve_seconds"),
        "synthetic_negative_controls": synthetic.get("negative_control_count"),
        "synthetic_false_divergence_count": synthetic.get("negative_control_false_divergence_count"),
        "public_overlap_action_divergent_edges": public_overlap.get("action_divergent_edges"),
        "public_overlap_affected_set_equal_edges": public_overlap.get("affected_set_equal_edges"),
        "finding_count": len(findings),
        "findings": findings,
    }
    (ROOT / "verification" / "optimization_impact.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
