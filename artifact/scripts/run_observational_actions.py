#!/usr/bin/env python3
"""Run the frozen action relation and suite construction after authorization."""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from action_suites.adapters import StructuralClaim
from action_suites.canonical import atomic_write_bytes, atomic_write_json, canonical_json_bytes, sha256_file
from action_suites.model import ReleaseUniverse, action_trace_digest, classify_edge, witness_releases
from action_suites.runtime_guard import ObservationalRunBlocked, require_authorized
from action_suites.semantics import action_trace
from action_suites.suite import solve_exact, solve_greedy, verify_certificate


def _jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if line.strip():
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError(f"{path}:{line_number} is not a JSON object")
                yield value


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the frozen observational action evaluator.")
    parser.add_argument("--project-root", type=Path, default=ROOT.parent)
    parser.add_argument("--claims", type=Path, required=True)
    parser.add_argument("--edges", type=Path, required=True)
    parser.add_argument("--release-universes", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--exact-node-bound", type=int, default=2_000_000)
    args = parser.parse_args()

    # No observational input is loaded and no output directory is created before
    # the independently recomputed authorization predicate succeeds.
    try:
        require_authorized(args.project_root)
    except ObservationalRunBlocked as exc:
        print(json.dumps({"status": "BLOCKED", "reason": str(exc)}, sort_keys=True))
        return 4

    claims = {row["claim_id"]: StructuralClaim.from_dict(row) for row in _jsonl(args.claims)}
    universes: dict[str, ReleaseUniverse] = {}
    terminal_status: dict[str, str] = {}
    for row in _jsonl(args.release_universes):
        package_key = str(row["package_key"])
        terminal_status[package_key] = str(row["status"])
        if row["status"] == "SUCCESS":
            source_digest = str(row.get("response_sha256") or "")
            universes[package_key] = ReleaseUniverse(
                package_key=package_key,
                releases=tuple(str(item) for item in row.get("releases", [])),
                source_digest=source_digest,
            )

    trace_cache: dict[tuple[str, str], dict[str, object]] = {}
    trace_rows: list[dict[str, object]] = []
    disposition_rows: list[dict[str, object]] = []
    obligations_by_group: dict[str, dict[str, frozenset[str]]] = defaultdict(dict)

    for edge in sorted(_jsonl(args.edges), key=lambda row: str(row["edge_id"])):
        edge_id = str(edge["edge_id"])
        group_id = str(edge["group_id"])
        package_key = str(edge["package_key"])
        left = claims[str(edge["left_claim_id"])]
        right = claims[str(edge["right_claim_id"])]
        universe = universes.get(package_key)
        if universe is None:
            disposition_rows.append({
                "edge_id": edge_id,
                "group_id": group_id,
                "package_key": package_key,
                "disposition": "NON_EXECUTABLE",
                "blocker": f"RELEASE_UNIVERSE_{terminal_status.get(package_key, 'MISSING')}",
                "witnesses": [],
            })
            continue

        traces: list[dict[str, object]] = []
        for claim in (left, right):
            key = (claim.claim_id, universe.digest)
            if key not in trace_cache:
                evaluated = action_trace(claim, universe)
                serial = {release: evaluated[release].to_dict() for release in sorted(evaluated)}
                trace_cache[key] = serial
                trace_rows.append({
                    "claim_id": claim.claim_id,
                    "package_key": package_key,
                    "release_universe_sha256": universe.digest,
                    "action_trace_sha256": action_trace_digest(evaluated),
                    "actions": serial,
                })
            traces.append(trace_cache[key])

        from action_suites.model import Action
        left_actions = {release: Action.from_dict(value) for release, value in traces[0].items()}
        right_actions = {release: Action.from_dict(value) for release, value in traces[1].items()}
        witnesses = witness_releases(universe.releases, left_actions, right_actions)
        disposition = classify_edge(universe.releases, left_actions, right_actions)
        if disposition == "RESOLVED_DIVERGENT":
            obligations_by_group[group_id][edge_id] = witnesses
        disposition_rows.append({
            "edge_id": edge_id,
            "group_id": group_id,
            "package_key": package_key,
            "disposition": disposition,
            "blocker": None,
            "witnesses": sorted(witnesses),
        })

    certificate_rows: list[dict[str, object]] = []
    for group_id, obligations in sorted(obligations_by_group.items()):
        greedy = solve_greedy(obligations)
        exact = solve_exact(obligations, max_nodes=args.exact_node_bound)
        for certificate in (greedy, exact):
            passed, errors = verify_certificate(obligations, certificate)
            if not passed:
                raise AssertionError(f"certificate replay failed for {group_id}: {errors}")
            certificate_rows.append({
                "group_id": group_id,
                **certificate.to_dict(),
                "replay_status": "PASS",
            })

    args.output_dir.mkdir(parents=True, exist_ok=False)
    outputs = {
        "action_traces.jsonl": trace_rows,
        "edge_dispositions.jsonl": disposition_rows,
        "suite_certificates.jsonl": certificate_rows,
    }
    digests: dict[str, str] = {}
    for filename, rows in outputs.items():
        path = args.output_dir / filename
        atomic_write_bytes(path, b"".join(canonical_json_bytes(row) for row in rows))
        digests[filename] = sha256_file(path)
    summary = {
        "status": "COMPLETE",
        "claims_with_traces": len(trace_rows),
        "edges": len(disposition_rows),
        "disposition_counts": {
            label: sum(row["disposition"] == label for row in disposition_rows)
            for label in ("RESOLVED_DIVERGENT", "RESOLVED_EQUIVALENT", "INDETERMINATE", "NON_EXECUTABLE")
        },
        "groups_with_suites": len(obligations_by_group),
        "certificate_rows": len(certificate_rows),
        "output_sha256": digests,
    }
    atomic_write_json(args.output_dir / "observational_summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
