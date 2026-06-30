#!/usr/bin/env python3
"""Replay the redistributable synthetic advisory benchmark."""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from action_suites.adapters import StructuralClaim  # noqa: E402
from action_suites.baselines import (  # noqa: E402
    affected_set_equality,
    confusion_counts,
    normalized_structural_equality,
    raw_record_equality,
    universe_affected_equality,
    vers_equality,
)
from action_suites.canonical import canonical_json_bytes, sha256_bytes, sha256_file  # noqa: E402
from action_suites.model import (  # noqa: E402
    Action,
    ReleaseUniverse,
    action_trace_digest,
    witness_releases,
)
from action_suites.semantics import action_trace, affected_status  # noqa: E402
from action_suites.suite import solve_exact, solve_greedy, verify_certificate  # noqa: E402

BENCH = ROOT / "benchmarks" / "synthetic_advisory"


def _version(index: int) -> str:
    return f"1.{index}.0"


def _range(fixed: str | None) -> tuple[dict[str, object], ...]:
    events: list[dict[str, str]] = [{"introduced": "0"}]
    if fixed is not None:
        events.append({"fixed": fixed})
    return ({"type": "ECOSYSTEM", "events": events},)


def _claim(
    *,
    claim_id: str,
    source_id: str,
    record_id: str,
    package: str,
    fixed: str | None,
    target: str | None,
    alternative: str | None = None,
    withdrawn: bool = False,
) -> dict[str, object]:
    return {
        "claim_id": claim_id,
        "source_id": source_id,
        "record_id": record_id,
        "package_ecosystem": "PyPI",
        "package_name": package,
        "aliases": [record_id],
        "withdrawn": withdrawn,
        "ranges": list(_range(fixed)),
        "versions": [],
        "advisory_targets": [] if target is None else [target],
        "alternative_actions": [] if alternative is None else [alternative],
        "source_path": f"synthetic/{source_id}/{record_id}.json",
    }


def _universe(package: str, width: int = 8) -> dict[str, object]:
    releases = [_version(index) for index in range(width)]
    return {
        "package_key": f"pypi::{package}",
        "status": "SUCCESS",
        "response_sha256": sha256_bytes(
            canonical_json_bytes({"package": package, "releases": releases})
        ),
        "releases": releases,
    }


def expected_rows() -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
    claims: list[dict[str, object]] = []
    edges: list[dict[str, object]] = []
    universes: list[dict[str, object]] = []

    def add_pair(
        *,
        index: int,
        package: str,
        left_fixed: str | None,
        right_fixed: str | None,
        left_target: str | None,
        right_target: str | None,
        expected: str,
        control_kind: str,
        left_alternative: str | None = None,
        right_alternative: str | None = None,
    ) -> None:
        left_id = f"claim-{index:03d}-a"
        right_id = f"claim-{index:03d}-b"
        record_id = f"CVE-2099-{index:04d}"
        claims.extend(
            [
                _claim(
                    claim_id=left_id,
                    source_id="SYN-A",
                    record_id=record_id,
                    package=package,
                    fixed=left_fixed,
                    target=left_target,
                    alternative=left_alternative,
                ),
                _claim(
                    claim_id=right_id,
                    source_id="SYN-B",
                    record_id=record_id,
                    package=package,
                    fixed=right_fixed,
                    target=right_target,
                    alternative=right_alternative,
                ),
            ]
        )
        edges.append(
            {
                "edge_id": f"edge-{index:03d}",
                "group_id": f"group-{index // 4:03d}",
                "package_key": f"pypi::{package}",
                "left_claim_id": left_id,
                "right_claim_id": right_id,
                "expected_decision": expected,
                "control_kind": control_kind,
            }
        )

    package_names = {f"synthpkg{i % 12:02d}" for i in range(96)}
    universes.extend(_universe(package) for package in sorted(package_names))

    cursor = 0
    for index in range(36):
        package = f"synthpkg{index % 12:02d}"
        add_pair(
            index=cursor,
            package=package,
            left_fixed=_version(4),
            right_fixed=_version(4),
            left_target=_version(4),
            right_target=_version(4),
            expected="EQUIVALENT",
            control_kind="known_equivalent_upgrade",
        )
        cursor += 1
    for index in range(20):
        package = f"synthpkg{index % 12:02d}"
        add_pair(
            index=cursor,
            package=package,
            left_fixed=_version(1),
            right_fixed=_version(1),
            left_target=_version(1),
            right_target=_version(1),
            expected="EQUIVALENT",
            control_kind="known_no_action_equivalent",
        )
        cursor += 1
    for index in range(24):
        package = f"synthpkg{index % 12:02d}"
        add_pair(
            index=cursor,
            package=package,
            left_fixed=_version(4),
            right_fixed=_version(6),
            left_target=_version(4),
            right_target=_version(6),
            expected="DIVERGENT",
            control_kind="target_shift_divergent",
        )
        cursor += 1
    for index in range(8):
        package = f"synthpkg{index % 12:02d}"
        add_pair(
            index=cursor,
            package=package,
            left_fixed=None,
            right_fixed=None,
            left_target=None,
            right_target=None,
            left_alternative="switch to maintained fork",
            right_alternative="disable vulnerable extension",
            expected="DIVERGENT",
            control_kind="alternative_action_divergent",
        )
        cursor += 1
    for index in range(8):
        package = f"synthpkg{index % 12:02d}"
        add_pair(
            index=cursor,
            package=package,
            left_fixed=_version(4),
            right_fixed=_version(4),
            left_target=_version(4),
            right_target=_version(4),
            expected="ABSTAIN",
            control_kind="unknown_not_witness",
            left_alternative=None,
            right_alternative=None,
        )
        claims[-2]["withdrawn"] = True
        cursor += 1

    return claims, edges, universes


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


def _write_jsonl(path: Path, rows: Iterable[Mapping[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"".join(canonical_json_bytes(row) for row in rows))


def _affected_values(claim: StructuralClaim, releases: Iterable[str]) -> dict[str, bool | None]:
    values: dict[str, bool | None] = {}
    for release in releases:
        try:
            values[release] = affected_status(claim, release)
        except (TypeError, ValueError):
            values[release] = None
    return values


def _decision_rate(counts: Mapping[str, int]) -> float:
    total = sum(counts.values())
    return ((counts.get("EQUIVALENT", 0) + counts.get("DIVERGENT", 0)) / total) if total else 0.0


def _metrics(decisions: Mapping[str, list[str]], canonical: list[str]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for comparator, vector in sorted(decisions.items()):
        counts = Counter(vector)
        confusion = confusion_counts(canonical, vector)
        decided = counts["EQUIVALENT"] + counts["DIVERGENT"]
        rows.append(
            {
                "comparator": comparator,
                "edges": len(vector),
                "equivalent": counts["EQUIVALENT"],
                "divergent": counts["DIVERGENT"],
                "abstained": counts["ABSTAIN"],
                "decided": decided,
                "decision_rate": _decision_rate(counts),
                "false_equivalence_count": confusion["fn"],
                "false_divergence_count": confusion["fp"],
            }
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-fixtures", action="store_true")
    args = parser.parse_args()

    claims_expected, edges_expected, universes_expected = expected_rows()
    paths = {
        "claims": BENCH / "claims.jsonl",
        "edges": BENCH / "edges.jsonl",
        "release_universes": BENCH / "release_universes.jsonl",
    }
    if args.write_fixtures:
        _write_jsonl(paths["claims"], claims_expected)
        _write_jsonl(paths["edges"], edges_expected)
        _write_jsonl(paths["release_universes"], universes_expected)

    claims_rows = _jsonl(paths["claims"])
    edges_rows = _jsonl(paths["edges"])
    universe_rows = _jsonl(paths["release_universes"])
    findings: list[dict[str, object]] = []
    if claims_rows != claims_expected:
        findings.append({"kind": "claim_fixture_changed"})
    if edges_rows != edges_expected:
        findings.append({"kind": "edge_fixture_changed"})
    if universe_rows != universes_expected:
        findings.append({"kind": "release_universe_fixture_changed"})

    claims = {row["claim_id"]: StructuralClaim.from_dict(row) for row in claims_rows}
    universes: dict[str, ReleaseUniverse] = {}
    for row in universe_rows:
        if row.get("status") == "SUCCESS":
            universes[str(row["package_key"])] = ReleaseUniverse(
                str(row["package_key"]),
                tuple(str(item) for item in row["releases"]),
                str(row["response_sha256"]),
            )

    decisions: dict[str, list[str]] = defaultdict(list)
    canonical_vector: list[str] = []
    expected_vector: list[str] = []
    obligations_by_group: dict[str, dict[str, frozenset[str]]] = defaultdict(dict)
    trace_digests: list[str] = []

    for edge in sorted(edges_rows, key=lambda row: str(row["edge_id"])):
        left = claims[str(edge["left_claim_id"])]
        right = claims[str(edge["right_claim_id"])]
        universe = universes[str(edge["package_key"])]
        releases = universe.releases
        left_actions = action_trace(left, universe)
        right_actions = action_trace(right, universe)
        trace_digests.extend([action_trace_digest(left_actions), action_trace_digest(right_actions)])

        action_decision = universe_affected_equality(releases, left, right).decision
        left_affected = _affected_values(left, releases)
        right_affected = _affected_values(right, releases)
        baseline_rows = {
            "RAW": raw_record_equality(canonical_json_bytes(left.to_dict()), canonical_json_bytes(right.to_dict())),
            "STRUCTURAL": normalized_structural_equality(left, right),
            "AFFECTED_SET": affected_set_equality(releases, left_affected, right_affected),
            "VERS": vers_equality(left, right),
            "UNIVERS": universe_affected_equality(releases, left, right),
        }
        witnesses = witness_releases(releases, left_actions, right_actions)
        if witnesses:
            canonical_decision = "DIVERGENT"
            obligations_by_group[str(edge["group_id"])][str(edge["edge_id"])] = witnesses
        elif any(not left_actions[release].concrete or not right_actions[release].concrete for release in releases):
            canonical_decision = "ABSTAIN"
        else:
            canonical_decision = "EQUIVALENT"
        baseline_rows["ACTION"] = type("Decision", (), {"decision": canonical_decision})()
        if action_decision == "DIVERGENT" and canonical_decision != "DIVERGENT":
            findings.append({"kind": "affected_relation_disagrees_with_action_relation", "edge_id": edge["edge_id"]})

        expected = str(edge["expected_decision"])
        if canonical_decision != expected:
            findings.append(
                {
                    "kind": "expected_decision_mismatch",
                    "edge_id": edge["edge_id"],
                    "expected": expected,
                    "actual": canonical_decision,
                }
            )
        expected_vector.append(expected)
        canonical_vector.append(canonical_decision)
        for comparator, decision in baseline_rows.items():
            decisions[comparator].append(decision.decision)

    certificate_rows: list[dict[str, object]] = []
    for group_id, obligations in sorted(obligations_by_group.items()):
        greedy = solve_greedy(obligations)
        exact = solve_exact(obligations)
        for certificate in (greedy, exact):
            passed, errors = verify_certificate(obligations, certificate)
            if not passed:
                findings.append({"kind": "synthetic_certificate_replay_failed", "group_id": group_id, "errors": list(errors)})
            certificate_rows.append({"group_id": group_id, **certificate.to_dict()})

    comparator_rows = _metrics(decisions, canonical_vector)
    expected_counts = Counter(expected_vector)
    canonical_counts = Counter(canonical_vector)
    negative_controls = expected_counts["EQUIVALENT"]
    false_divergence = sum(
        expected == "EQUIVALENT" and actual == "DIVERGENT"
        for expected, actual in zip(expected_vector, canonical_vector, strict=True)
    )
    missed_divergence = sum(
        expected == "DIVERGENT" and actual != "DIVERGENT"
        for expected, actual in zip(expected_vector, canonical_vector, strict=True)
    )
    if negative_controls < 50 or false_divergence:
        findings.append({"kind": "negative_control_contract_failed", "count": negative_controls, "false_divergence": false_divergence})
    if missed_divergence:
        findings.append({"kind": "divergent_control_contract_failed", "missed_divergence": missed_divergence})

    summary = {
        "schema_version": 1,
        "kind": "SYNTHETIC_ADVISORY_BENCHMARK",
        "status": "PASS" if not findings else "FAIL",
        "contract": "Redistributable synthetic claim, edge, and release-universe JSONL fixtures exercise the action semantics, baseline abstentions, known-equivalent negative controls, divergent controls, and suite certificates without contributing to SafetyDB prevalence claims.",
        "fixture_sha256": {name: sha256_file(path) for name, path in paths.items()},
        "claim_count": len(claims_rows),
        "edge_count": len(edges_rows),
        "package_count": len(universe_rows),
        "expected_decision_counts": dict(sorted(expected_counts.items())),
        "canonical_decision_counts": dict(sorted(canonical_counts.items())),
        "negative_control_count": negative_controls,
        "negative_control_false_divergence_count": false_divergence,
        "divergent_control_count": expected_counts["DIVERGENT"],
        "divergent_control_missed_count": missed_divergence,
        "abstention_control_count": expected_counts["ABSTAIN"],
        "groups_with_suites": len(obligations_by_group),
        "certificate_rows": len(certificate_rows),
        "max_exact_explored_nodes": max((row["explored_nodes"] for row in certificate_rows if row["algorithm"] == "KERNELIZED_DETERMINISTIC_BRANCH_AND_BOUND"), default=0),
        "trace_digest_sha256": sha256_bytes(canonical_json_bytes(sorted(trace_digests))),
        "comparator_decision_rows": comparator_rows,
        "finding_count": len(findings),
        "findings": findings,
    }
    output = ROOT / "verification" / "synthetic_advisory_benchmark.json"
    output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
