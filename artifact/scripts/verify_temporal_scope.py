#!/usr/bin/env python3
"""Validate temporal-scope claims and current-source boundary evidence."""
from __future__ import annotations

import csv
import json
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_SOURCES = {"C-GHAD", "C-PYPA", "C-GOVULNDB", "C-RUSTSEC", "C-RUBYSEC"}
MIN_ACCESS_DATE = date(2026, 6, 1)


def load_json(relative: str) -> dict[str, object]:
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def main() -> int:
    findings: list[dict[str, object]] = []
    readme = (ROOT / "README.md").read_text(encoding="utf-8", errors="ignore").lower()
    protocol = (ROOT / "study_protocol.md").read_text(encoding="utf-8", errors="ignore").lower()
    reproduction = (ROOT / "reproduction.md").read_text(encoding="utf-8", errors="ignore").lower()
    safety_scope = load_json("verification/safetydb_historical_scope.json")
    resource_lock = load_json("config/resource_lock.json")

    with (ROOT / "source_manifest.csv").open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    by_source = {row["source_id"]: row for row in rows}
    if set(by_source) != EXPECTED_SOURCES:
        findings.append({"kind": "source_manifest_set_changed", "sources": sorted(by_source)})

    access_dates: dict[str, str] = {}
    for source_id, row in by_source.items():
        commit = row.get("version_or_commit", "")
        if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
            findings.append({"kind": "source_not_full_commit", "source_id": source_id, "commit": commit})
        try:
            access = date.fromisoformat(row.get("access_date", ""))
        except ValueError:
            findings.append({"kind": "source_access_date_invalid", "source_id": source_id, "access_date": row.get("access_date")})
            continue
        access_dates[source_id] = access.isoformat()
        if access < MIN_ACCESS_DATE:
            findings.append({"kind": "source_access_date_too_old", "source_id": source_id, "access_date": access.isoformat()})
        if not row.get("license") or not row.get("role") or not row.get("notes"):
            findings.append({"kind": "source_manifest_provenance_incomplete", "source_id": source_id})

    locked_rows = resource_lock.get("advisory_sources", [])
    locked = {row.get("source_id"): row for row in locked_rows if isinstance(row, dict)}
    if set(locked) != EXPECTED_SOURCES:
        findings.append({"kind": "resource_lock_source_set_changed", "sources": sorted(locked)})
    for source_id in EXPECTED_SOURCES:
        manifest_commit = by_source.get(source_id, {}).get("version_or_commit")
        locked_commit = locked.get(source_id, {}).get("commit") if isinstance(locked.get(source_id), dict) else None
        if manifest_commit != locked_commit:
            findings.append({"kind": "source_commit_lock_mismatch", "source_id": source_id, "manifest_commit": manifest_commit, "resource_lock_commit": locked_commit})

    registry_families = resource_lock.get("release_registry_families", [])
    if not isinstance(registry_families, list) or len(registry_families) < 9:
        findings.append({"kind": "registry_family_boundary_incomplete", "count": len(registry_families) if isinstance(registry_families, list) else None})
    if safety_scope.get("status") != "PASS":
        findings.append({"kind": "historical_safetydb_scope_not_passing", "status": safety_scope.get("status")})

    joined = "\n".join([readme, protocol, reproduction])
    for phrase in [
        "historical safetydb",
        "2021.7.17",
        "current ecosystem prevalence",
        "2026-06-22",
        "source_manifest.csv",
        "not a live network fetch",
    ]:
        if phrase not in joined:
            findings.append({"kind": "temporal_scope_phrase_missing", "phrase": phrase})

    summary = {
        "schema_version": 1,
        "kind": "TEMPORAL_SCOPE",
        "status": "PASS" if not findings else "FAIL",
        "contract": "The SafetyDB evidence is a frozen 2021.7.17 historical case study; 2026-06-22 advisory-source commits document current-source boundaries and provenance but are not mixed into a current-prevalence claim.",
        "historical_benchmark": safety_scope.get("benchmark"),
        "historical_scope_status": safety_scope.get("status"),
        "advisory_source_count": len(by_source),
        "advisory_access_dates": dict(sorted(access_dates.items())),
        "registry_family_count": len(registry_families) if isinstance(registry_families, list) else None,
        "finding_count": len(findings),
        "findings": findings,
    }
    (ROOT / "verification" / "temporal_scope.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
