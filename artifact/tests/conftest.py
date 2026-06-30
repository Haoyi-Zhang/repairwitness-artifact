from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Iterable

import pytest

from action_suites.audit import audit_subject_digest
from action_suites.canonical import atomic_write_json, sha256_file, sha256_tree


SOURCE_ROWS = [
    ("C-GHAD", "https://github.com/github/advisory-database", "a" * 40),
    ("C-PYPA", "https://github.com/pypa/advisory-database", "b" * 40),
    ("C-GOVULNDB", "https://github.com/golang/vulndb", "c" * 40),
    ("C-RUSTSEC", "https://github.com/RustSec/advisory-db", "d" * 40),
    ("C-RUBYSEC", "https://github.com/rubysec/ruby-advisory-db", "e" * 40),
]


def write_csv(path: Path, fieldnames: list[str], rows: Iterable[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def build_authorizable_project(root: Path) -> Path:
    artifact = root / "artifact"
    (root / "paper").mkdir(parents=True)
    (artifact / "config").mkdir(parents=True)
    (artifact / "data/recovery").mkdir(parents=True)
    (artifact / "verification").mkdir(parents=True)
    (artifact / "action_suites").mkdir(parents=True)
    (artifact / "action_suites/core.py").write_text("VALUE = 1\n", encoding="utf-8")

    write_csv(
        artifact / "source_manifest.csv",
        ["source_id", "url", "source_type", "version_or_commit", "license", "access_date", "role", "notes"],
        [
            {
                "source_id": source_id,
                "url": url,
                "source_type": "public advisory repository",
                "version_or_commit": commit,
                "license": "test",
                "access_date": "2026-06-22",
                "role": "test",
                "notes": "test",
            }
            for source_id, url, commit in SOURCE_ROWS
        ],
    )
    stage_flow = {
        "stages": [
            {"stage": "projected_members", "count": 10, "status": "VERIFIED", "evidence_sha256": "1" * 64},
            {"stage": "syntax_decoded_members", "count": 10, "status": "VERIFIED", "evidence_sha256": "2" * 64},
            {"stage": "frozen_adapter_supported_members", "count": 9, "status": "VERIFIED", "evidence_sha256": "3" * 64},
            {"stage": "recognized_advisory_records", "count": 9, "status": "VERIFIED", "evidence_sha256": "4" * 64},
            {"stage": "claim_bearing_members", "count": 8, "status": "VERIFIED", "evidence_sha256": "5" * 64},
            {"stage": "normalized_claims", "count": 12, "status": "VERIFIED", "evidence_sha256": "6" * 64},
            {"stage": "alias_package_groups", "count": 3, "status": "VERIFIED", "evidence_sha256": "7" * 64},
            {"stage": "qualified_edges", "count": 4, "status": "VERIFIED", "evidence_sha256": "8" * 64},
            {"stage": "packages_with_terminal_release_universe_rows", "count": 2, "status": "VERIFIED", "evidence_sha256": "9" * 64},
        ],
        "exclusions": [
            {
                "source_id": "C-GOVULNDB",
                "from_stage": "syntax_decoded_members",
                "to_stage": "frozen_adapter_supported_members",
                "count": 1,
                "reason_code": "GO_NATIVE_REPORT_NO_FROZEN_PRIMARY_ADAPTER",
                "outcome_blind": True,
            }
        ],
    }
    atomic_write_json(artifact / "data/recovery/stage_flow.json", stage_flow)
    (artifact / "data/recovery/structural_claims.jsonl").write_text(
        '{"claim_id":"c1"}\n', encoding="utf-8"
    )
    (artifact / "data/recovery/structural_groups.jsonl").write_text(
        '{"group_id":"g1"}\n', encoding="utf-8"
    )
    (artifact / "data/recovery/qualified_edges.jsonl").write_text(
        '{"edge_id":"e1"}\n', encoding="utf-8"
    )
    (artifact / "data/recovery/package_frame.csv").write_text("package_key\npypi::demo\n", encoding="utf-8")
    write_csv(
        artifact / "data/recovery/release_universe_manifest.csv",
        ["package_key", "status"],
        [
            {"package_key": "pypi::demo", "status": "SUCCESS"},
            {"package_key": "npm::demo", "status": "EMPTY"},
        ],
    )
    (artifact / "data/recovery/release_universes.jsonl").write_text(
        '{"package_key":"pypi::demo","status":"SUCCESS","releases":["1.0"]}\n'
        '{"package_key":"npm::demo","status":"EMPTY","releases":[]}\n',
        encoding="utf-8",
    )
    write_csv(
        artifact / "data/recovery/validation_sample_lock.csv",
        ["sample_id"],
        [{"sample_id": "s1"}, {"sample_id": "s2"}],
    )
    atomic_write_json(artifact / "config/baseline_lock.json", {"kind": "BASELINE_LOCK", "version": 1})
    from action_suites.sources import LOCKED_PROJECTION_RULES
    atomic_write_json(
        artifact / "config/resource_lock.json",
        {
            "kind": "RESOURCE_LOCK",
            "version": 1,
            "advisory_sources": [
                {
                    "source_id": source_id,
                    "commit": commit,
                    "include_globs": list(LOCKED_PROJECTION_RULES[source_id].include_globs),
                    "adapter_supported_globs": list(
                        LOCKED_PROJECTION_RULES[source_id].adapter_supported_globs
                    ),
                }
                for source_id, _url, commit in SOURCE_ROWS
            ],
        },
    )
    atomic_write_json(
        artifact / "data/recovery/checkpoint_status_transfer.json",
        {"observational_action_outcomes_computed": False, "current_runtime_contains_full_prior_artifact": False},
    )
    atomic_write_json(
        artifact / "verification/test_attestation.json",
        {
            "kind": "DETERMINISTIC_TESTS",
            "status": "PASS",
            "command": "python -m pytest -q",
            "output_tail": "50 passed",
            "observational_inputs_used": False,
        },
    )
    atomic_write_json(
        artifact / "verification/audit_attestation.json",
        {
            "kind": "ARTIFACT_AUDIT",
            "status": "PASS",
            "repository_audit": "PASS",
            "clean_extraction_replay": "PASS",
            "observational_outputs_absent": True,
            "subject_tree_sha256": "PENDING",
            "errors": [],
        },
    )
    atomic_write_json(
        artifact / "verification/independent_audit_attestation.json",
        {
            "kind": "INDEPENDENT_AUDIT_CLOSURE",
            "status": "PASS",
            "critical_findings": [],
            "major_findings": [],
            "facets": [{"facet": f"A{index}", "decision": "PASS"} for index in range(9)],
        },
    )

    specs = [
        ("source_manifest", "artifact/source_manifest.csv", "file", "source_manifest"),
        ("stage_flow", "artifact/data/recovery/stage_flow.json", "file", "stage_flow"),
        ("structural_claims", "artifact/data/recovery/structural_claims.jsonl", "file", "structural_claims"),
        ("structural_groups", "artifact/data/recovery/structural_groups.jsonl", "file", "structural_groups"),
        ("qualified_edges", "artifact/data/recovery/qualified_edges.jsonl", "file", "qualified_edges"),
        ("package_frame", "artifact/data/recovery/package_frame.csv", "file", "package_frame"),
        ("release_manifest", "artifact/data/recovery/release_universe_manifest.csv", "file", "release_manifest"),
        ("release_universes", "artifact/data/recovery/release_universes.jsonl", "file", "release_universes"),
        ("validation_sample", "artifact/data/recovery/validation_sample_lock.csv", "file", "validation_sample"),
        ("semantic_implementation", "artifact/action_suites", "tree", "semantic_implementation"),
        ("baseline_lock", "artifact/config/baseline_lock.json", "file", "baseline_lock"),
        ("resource_lock", "artifact/config/resource_lock.json", "file", "resource_lock"),
        ("checkpoint_status", "artifact/data/recovery/checkpoint_status_transfer.json", "file", "checkpoint_status"),
    ]
    required_inputs = []
    for name, relative, kind, role in specs:
        path = root / relative
        digest = sha256_tree(path, excluded_names=("__pycache__", ".pytest_cache", ".git")) if kind == "tree" else sha256_file(path)
        required_inputs.append({
            "name": name,
            "path": relative,
            "kind": kind,
            "role": role,
            "expected_sha256": digest,
        })
    protocol = {
        "schema_version": 1,
        "action_kinds": [
            "NO_ACTION", "UPGRADE_TO_ADVISORY_TARGET", "ALTERNATIVE_ACTION",
            "REPAIR_WITHOUT_PUBLIC_TARGET", "UNKNOWN",
        ],
        "unknown_is_concrete_action": False,
        "unknown_can_witness": False,
        "primary_comparison_kind": "CURATION_LINEAGE",
        "observational_outcomes_authorized": False,
        "minimum_divergence_threshold": 0,
        "minimum_compression_threshold": 0,
        "minimum_effect_threshold": 0,
        "significance_gate": 1,
        "result_dependent_stopping": False,
        "research_questions": [{"id": "RQ1"}, {"id": "RQ2"}, {"id": "RQ3"}],
        "validation_sample_rows": 2,
        "required_inputs": required_inputs,
        "observational_output_root": "artifact/data/observational",
        "checkpoint_status_path": "artifact/data/recovery/checkpoint_status_transfer.json",
    }
    atomic_write_json(artifact / "config/protocol_lock.json", protocol)
    audit_path = artifact / "verification/audit_attestation.json"
    audit_value = json.loads(audit_path.read_text(encoding="utf-8"))
    audit_value["subject_tree_sha256"] = audit_subject_digest(root)
    atomic_write_json(audit_path, audit_value)
    return root


@pytest.fixture
def authorizable_project(tmp_path: Path) -> Path:
    return build_authorizable_project(tmp_path / "project")
