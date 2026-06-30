from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from typing import Iterable

from .adapters import StructuralClaim, parse_supported_member
from .canonical import atomic_write_bytes, atomic_write_json, canonical_json_bytes, sha256_file
from .frame import ClaimGroup, QualifiedEdge, build_groups_and_edges
from .sources import LOCKED_PROJECTION_RULES, SourceSpec, iter_projected_archive_members, syntax_decodable


def _jsonl_bytes(rows: Iterable[dict[str, object]]) -> bytes:
    return b"".join(canonical_json_bytes(row) for row in rows)


def build_structural_frame(
    source_specs: Iterable[SourceSpec],
    archive_dir: Path | str,
    output_dir: Path | str,
) -> dict[str, object]:
    archive_root = Path(archive_dir)
    output_root = Path(output_dir)
    output_root.mkdir(parents=True, exist_ok=True)

    claims: list[StructuralClaim] = []
    recognized_records = 0
    claim_bearing_members = 0
    exclusions: list[dict[str, object]] = []
    source_counts: Counter[str] = Counter()

    for spec in sorted(source_specs, key=lambda row: row.source_id):
        rule = LOCKED_PROJECTION_RULES[spec.source_id]
        archive_path = archive_root / f"{spec.source_id}.tar.gz"
        for relative, content, supported, unsupported_reason in iter_projected_archive_members(archive_path, rule):
            if not syntax_decodable(relative, content):
                exclusions.append({
                    "source_id": spec.source_id,
                    "path": relative,
                    "stage": "syntax_decoded_members",
                    "reason_code": "SYNTAX_DECODE_FAILED",
                    "outcome_blind": True,
                })
                continue
            if not supported:
                exclusions.append({
                    "source_id": spec.source_id,
                    "path": relative,
                    "stage": "frozen_adapter_supported_members",
                    "reason_code": unsupported_reason,
                    "outcome_blind": True,
                })
                continue
            try:
                parsed = parse_supported_member(spec.source_id, relative, content)
                recognized_records += 1
            except Exception as exc:
                exclusions.append({
                    "source_id": spec.source_id,
                    "path": relative,
                    "stage": "recognized_advisory_records",
                    "reason_code": "FROZEN_ADAPTER_REJECTED",
                    "detail": f"{type(exc).__name__}: {exc}"[:500],
                    "outcome_blind": True,
                })
                continue
            if parsed:
                claim_bearing_members += 1
                claims.extend(parsed)
                source_counts[spec.source_id] += len(parsed)
            else:
                exclusions.append({
                    "source_id": spec.source_id,
                    "path": relative,
                    "stage": "claim_bearing_members",
                    "reason_code": "NO_QUALIFYING_AFFECTED_PACKAGE",
                    "outcome_blind": True,
                })

    claims_tuple = tuple(sorted(claims, key=lambda row: row.claim_id))
    if len({row.claim_id for row in claims_tuple}) != len(claims_tuple):
        raise ValueError("duplicate structural claim identifiers")
    groups, edges = build_groups_and_edges(claims_tuple)

    claims_path = output_root / "structural_claims.jsonl"
    groups_path = output_root / "structural_groups.jsonl"
    edges_path = output_root / "qualified_edges.jsonl"
    package_frame_path = output_root / "package_frame.csv"
    atomic_write_bytes(claims_path, _jsonl_bytes(row.to_dict() for row in claims_tuple))
    atomic_write_bytes(groups_path, _jsonl_bytes(row.to_dict() for row in groups))
    atomic_write_bytes(edges_path, _jsonl_bytes(row.to_dict() for row in edges))

    package_rows: dict[str, dict[str, object]] = {}
    group_by_id = {row.group_id: row for row in groups}
    for group in groups:
        current = package_rows.setdefault(group.package_key, {
            "package_key": group.package_key,
            "group_count": 0,
            "edge_count": 0,
            "claim_count": 0,
            "source_count": 0,
            "target_bearing_edge_count": 0,
        })
        current["group_count"] = int(current["group_count"]) + 1
        current["claim_count"] = int(current["claim_count"]) + len(group.claim_ids)
        current["source_count"] = max(int(current["source_count"]), len(group.source_ids))
    for edge in edges:
        current = package_rows[edge.package_key]
        current["edge_count"] = int(current["edge_count"]) + 1
        current["target_bearing_edge_count"] = int(current["target_bearing_edge_count"]) + int(edge.target_bearing)

    fieldnames = [
        "package_key", "group_count", "edge_count", "claim_count", "source_count", "target_bearing_edge_count"
    ]
    package_frame_path.parent.mkdir(parents=True, exist_ok=True)
    with package_frame_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(package_rows[key] for key in sorted(package_rows))

    summary = {
        "schema_version": 1,
        "recognized_advisory_records": recognized_records,
        "claim_bearing_members": claim_bearing_members,
        "normalized_claims": len(claims_tuple),
        "alias_package_groups": len(groups),
        "qualified_edges": len(edges),
        "target_bearing_edges": sum(1 for edge in edges if edge.target_bearing),
        "packages": len(package_rows),
        "source_claim_counts": dict(sorted(source_counts.items())),
        "digests": {
            "structural_claims": sha256_file(claims_path),
            "structural_groups": sha256_file(groups_path),
            "qualified_edges": sha256_file(edges_path),
            "package_frame": sha256_file(package_frame_path),
        },
    }
    atomic_write_json(output_root / "structural_summary.json", summary)
    atomic_write_json(output_root / "structural_exclusions.json", exclusions)
    return summary
