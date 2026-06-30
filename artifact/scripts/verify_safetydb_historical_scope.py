#!/usr/bin/env python3
"""Validate the historical SafetyDB scope and anti-prevalence boundary."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_json(relative: str) -> dict[str, object]:
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def main() -> int:
    findings: list[dict[str, object]] = []
    readme = (ROOT / "README.md").read_text(encoding="utf-8", errors="ignore").lower()
    protocol = (ROOT / "study_protocol.md").read_text(encoding="utf-8", errors="ignore").lower()
    safety = load_json("verification/safetydb_external_summary.json")
    inventory = safety.get("inventory", {}) if isinstance(safety.get("inventory"), dict) else {}
    solver = safety.get("solver", {}) if isinstance(safety.get("solver"), dict) else {}
    benchmark = str(safety.get("benchmark", "")).lower()

    joined = readme + "\n" + protocol
    for phrase in [
        "historical safetydb",
        "2021.7.17",
        "without claiming current ecosystem prevalence",
        "non-redistributed",
        "redistributable synthetic advisory benchmark",
        "not a live network fetch",
    ]:
        if phrase not in joined:
            findings.append({"kind": "historical_scope_phrase_missing", "phrase": phrase})
    if "historical" not in benchmark or "2021.7.17" not in benchmark:
        findings.append({"kind": "safetydb_benchmark_label_not_historical", "benchmark": safety.get("benchmark")})
    if int(inventory.get("claims_with_cve") or 0) != 1246:
        findings.append({"kind": "safetydb_claim_count_changed", "claims_with_cve": inventory.get("claims_with_cve")})
    dispositions = inventory.get("edge_dispositions", {}) if isinstance(inventory.get("edge_dispositions"), dict) else {}
    if int(dispositions.get("RESOLVED_DIVERGENT") or 0) != 570:
        findings.append({"kind": "safetydb_divergent_edge_count_changed", "resolved_divergent": dispositions.get("RESOLVED_DIVERGENT")})
    if int(solver.get("groups_executed") or 0) != 97 or solver.get("all_certificates_valid") is not True:
        findings.append({"kind": "safetydb_solver_certificate_contract_failed", "groups": solver.get("groups_executed"), "all_certificates_valid": solver.get("all_certificates_valid")})

    summary = {
        "schema_version": 1,
        "kind": "SAFETYDB_HISTORICAL_SCOPE",
        "status": "PASS" if not findings else "FAIL",
        "contract": "SafetyDB evidence is a frozen 2021.7.17 historical PyPI case study with digest-bound summaries and non-redistributed source inputs; it is not a current prevalence, full source-level reproducibility, or live-registry claim. Redistributable synthetic controls cover source-level semantics separately.",
        "benchmark": safety.get("benchmark"),
        "claims_with_cve": inventory.get("claims_with_cve"),
        "edges": inventory.get("edges"),
        "resolved_divergent_edges": dispositions.get("RESOLVED_DIVERGENT"),
        "groups_executed": solver.get("groups_executed"),
        "all_certificates_valid": solver.get("all_certificates_valid"),
        "input_sha256": safety.get("input_sha256"),
        "finding_count": len(findings),
        "findings": findings,
    }
    (ROOT / "verification" / "safetydb_historical_scope.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
