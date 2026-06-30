#!/usr/bin/env python3
"""Replay the redistributable public advisory overlap fixture."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from action_suites.adapters import StructuralClaim, parse_supported_member  # noqa: E402
from action_suites.baselines import affected_set_equality, action_relation  # noqa: E402
from action_suites.canonical import canonical_json_bytes, sha256_bytes, sha256_file  # noqa: E402
from action_suites.model import ReleaseUniverse, witness_releases  # noqa: E402
from action_suites.semantics import action_trace, affected_status  # noqa: E402

BENCH = ROOT / "benchmarks" / "public_advisory_overlap"


def _jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number} is not a JSON object")
            rows.append(value)
    return rows


def _affected_values(claim: StructuralClaim, releases: Iterable[str]) -> dict[str, bool | None]:
    values: dict[str, bool | None] = {}
    for release in releases:
        try:
            values[release] = affected_status(claim, release)
        except (TypeError, ValueError):
            values[release] = None
    return values


def _load_claims_from_records(records: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, object]]:
    parsed: dict[str, dict[str, object]] = {}
    for record in records:
        fixture_path = BENCH / str(record["fixture_path"])
        if sha256_file(fixture_path) != record["sha256"]:
            raise ValueError(f"record digest mismatch: {record['fixture_path']}")
        claims = parse_supported_member(
            str(record["source_id"]),
            str(record["upstream_path"]),
            fixture_path.read_bytes(),
        )
        for claim in claims:
            parsed[claim.claim_id] = claim.to_dict()
    return parsed


def _action_dict(action: object) -> dict[str, object]:
    return action.to_dict()  # type: ignore[no-any-return, attr-defined]


def main() -> int:
    paths = {
        "claims": BENCH / "claims.jsonl",
        "edges": BENCH / "edges.jsonl",
        "records": BENCH / "records.jsonl",
        "release_universes": BENCH / "release_universes.jsonl",
    }
    findings: list[dict[str, object]] = []
    claims_rows = _jsonl(paths["claims"])
    edges_rows = _jsonl(paths["edges"])
    records_rows = _jsonl(paths["records"])
    universe_rows = _jsonl(paths["release_universes"])

    parsed_claims = _load_claims_from_records(records_rows)
    fixture_claims = {str(row["claim_id"]): row for row in claims_rows}
    if set(parsed_claims) != set(fixture_claims):
        findings.append(
            {
                "kind": "parsed_claim_set_mismatch",
                "parsed": sorted(parsed_claims),
                "fixture": sorted(fixture_claims),
            }
        )
    for claim_id, row in fixture_claims.items():
        if parsed_claims.get(claim_id) != row:
            findings.append({"kind": "parsed_claim_mismatch", "claim_id": claim_id})

    universes: dict[str, ReleaseUniverse] = {}
    for row in universe_rows:
        if row.get("status") != "SUCCESS":
            findings.append({"kind": "release_universe_not_success", "package_key": row.get("package_key")})
            continue
        universes[str(row["package_key"])] = ReleaseUniverse(
            package_key=str(row["package_key"]),
            releases=tuple(str(item) for item in row["releases"]),
            source_digest=str(row["response_sha256"]),
        )

    claims = {claim_id: StructuralClaim.from_dict(row) for claim_id, row in fixture_claims.items()}
    witness_counts: list[int] = []
    edge_results: list[dict[str, object]] = []
    for edge in sorted(edges_rows, key=lambda row: str(row["edge_id"])):
        left = claims[str(edge["left_claim_id"])]
        right = claims[str(edge["right_claim_id"])]
        universe = universes[str(edge["package_key"])]
        releases = universe.releases
        left_affected = _affected_values(left, releases)
        right_affected = _affected_values(right, releases)
        affected_decision = affected_set_equality(
            releases, left_affected, right_affected
        ).decision
        left_actions = action_trace(left, universe)
        right_actions = action_trace(right, universe)
        action_decision = action_relation(releases, left_actions, right_actions).decision
        witnesses = sorted(witness_releases(releases, left_actions, right_actions))
        witness_counts.append(len(witnesses))
        expected_release = str(edge["expected_witness_release"])
        if affected_decision != edge["expected_affected_set_decision"]:
            findings.append(
                {
                    "kind": "affected_set_decision_mismatch",
                    "edge_id": edge["edge_id"],
                    "expected": edge["expected_affected_set_decision"],
                    "actual": affected_decision,
                }
            )
        if action_decision != edge["expected_action_decision"]:
            findings.append(
                {
                    "kind": "action_decision_mismatch",
                    "edge_id": edge["edge_id"],
                    "expected": edge["expected_action_decision"],
                    "actual": action_decision,
                }
            )
        if expected_release not in witnesses:
            findings.append(
                {
                    "kind": "expected_witness_missing",
                    "edge_id": edge["edge_id"],
                    "expected_release": expected_release,
                }
            )
        elif (
            _action_dict(left_actions[expected_release]) != edge["expected_left_action"]
            or _action_dict(right_actions[expected_release]) != edge["expected_right_action"]
        ):
            findings.append({"kind": "expected_witness_action_mismatch", "edge_id": edge["edge_id"]})
        edge_results.append(
            {
                "edge_id": edge["edge_id"],
                "package_key": edge["package_key"],
                "affected_set_decision": affected_decision,
                "action_decision": action_decision,
                "witness_count": len(witnesses),
                "first_witness": witnesses[0] if witnesses else None,
            }
        )

    summary = {
        "schema_version": 1,
        "kind": "PUBLIC_ADVISORY_OVERLAP",
        "status": "PASS" if not findings else "FAIL",
        "contract": "A redistributable GHAD/PyPA overlap fixture is replayed from included source records and frozen PyPI release universes. It is a construct witness, not a prevalence estimate: all included edges have identical affected-release sets while repair-action semantics exposes a concrete target/mechanism difference.",
        "fixture_sha256": {name: sha256_file(path) for name, path in paths.items()},
        "claim_count": len(claims_rows),
        "record_count": len(records_rows),
        "edge_count": len(edges_rows),
        "package_count": len(universe_rows),
        "affected_set_equal_edges": sum(1 for row in edge_results if row["affected_set_decision"] == "EQUIVALENT"),
        "action_divergent_edges": sum(1 for row in edge_results if row["action_decision"] == "DIVERGENT"),
        "min_witnesses_per_edge": min(witness_counts) if witness_counts else 0,
        "max_witnesses_per_edge": max(witness_counts) if witness_counts else 0,
        "edge_result_digest": sha256_bytes(canonical_json_bytes(edge_results)),
        "edge_results": edge_results,
        "finding_count": len(findings),
        "findings": findings,
    }
    output = ROOT / "verification" / "public_advisory_overlap.json"
    output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
