#!/usr/bin/env python3
"""Refresh stable release attestation fields from current verification evidence."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ARTIFACT_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = ARTIFACT_ROOT.parent
sys.path.insert(0, str(ARTIFACT_ROOT))

from action_suites.audit import audit_repository, audit_subject_digest  # noqa: E402
from action_suites.canonical import atomic_write_json  # noqa: E402
from repairwitness.package import archive_report  # noqa: E402


def load_json(relative: str) -> dict[str, object]:
    return json.loads((ARTIFACT_ROOT / relative).read_text(encoding="utf-8"))


def load_optional_json(path: Path | None) -> dict[str, object] | None:
    if path is None:
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def reference_page_count(pdf_attestation: dict[str, object]) -> int | None:
    pages = pdf_attestation.get("reference_pages")
    if isinstance(pages, list):
        return len(pages)
    if isinstance(pages, int):
        return pages
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--combined", type=Path)
    parser.add_argument("--code", type=Path)
    parser.add_argument("--clean-replay", type=Path)
    parser.add_argument(
        "--output",
        type=Path,
        default=ARTIFACT_ROOT / "verification" / "release_attestation.json",
    )
    args = parser.parse_args()

    passed, errors = audit_repository(PROJECT_ROOT)
    tests = load_json("verification/test_attestation.json")
    validation = load_json("verification/result_validation.json")
    safety = load_json("verification/safetydb_external_summary.json")
    coverage = load_json("verification/coverage_contract.json")
    optimization = load_json("verification/optimization_impact.json")
    baseline = load_json("verification/baseline_fairness.json")
    temporal = load_json("verification/temporal_scope.json")
    pdf = load_json("verification/pdf_attestation.json")
    synthetic = load_json("verification/synthetic_advisory_benchmark.json")
    adversarial = load_json("verification/adversarial_scalability.json")
    clean_replay = load_optional_json(args.clean_replay)
    archive_reports: dict[str, object] = {}
    if args.combined:
        archive_reports["combined"] = archive_report(args.combined)
    if args.code:
        archive_reports["code"] = archive_report(args.code)
    packaged_scope = bool(args.combined and args.code and args.clean_replay)
    inventory = safety.get("inventory", {}) if isinstance(safety.get("inventory"), dict) else {}
    clean_replay_status = (
        clean_replay.get("status")
        if isinstance(clean_replay, dict)
        else "deferred_to_packaged_reproduction"
    )
    archive_reports_pass = all(
        isinstance(row, dict) and row.get("status") == "PASS"
        for row in archive_reports.values()
    )
    clean_replay_pass = (
        clean_replay_status == "PASS"
        if args.clean_replay is not None
        else clean_replay_status == "deferred_to_packaged_reproduction"
    )
    status_passed = (
        passed
        and validation.get("status") == "PASS"
        and pdf.get("status") == "PASS"
        and archive_reports_pass
        and clean_replay_pass
    )

    report = {
        "schema_version": 1,
        "kind": "RELEASE_ATTESTATION",
        "status": "PASS" if status_passed else "FAIL",
        "attestation_scope": "packaged_release" if packaged_scope else "pre_package_subject_summary",
        "generated_utc": "stable-verification-evidence",
        "validated_subject_tree_sha256": audit_subject_digest(PROJECT_ROOT),
        "combined_top_level": ["artifact", "paper"],
        "anonymous_audit": "PASS" if passed else "FAIL",
        "audit_errors": list(errors),
        "tests_passed": tests.get("passed"),
        "tests_failed": tests.get("failed"),
        "branch_coverage_percent": tests.get("branch_coverage_percent"),
        "statement_coverage_percent": tests.get("statement_coverage_percent"),
        "coverage_contract": coverage.get("status"),
        "safetydb_scope": validation.get("safetydb_scope", {}).get("status") if isinstance(validation.get("safetydb_scope"), dict) else None,
        "synthetic_advisory": synthetic.get("status"),
        "synthetic_negative_controls": synthetic.get("negative_control_count"),
        "synthetic_false_divergence_count": synthetic.get("negative_control_false_divergence_count"),
        "adversarial_scalability": adversarial.get("status"),
        "adversarial_obligations": adversarial.get("obligation_count"),
        "optimization_impact": optimization.get("status"),
        "baseline_fairness": baseline.get("status"),
        "temporal_scope": temporal.get("status"),
        "advisory_source_count": temporal.get("advisory_source_count"),
        "registry_family_count": temporal.get("registry_family_count"),
        "orlib_instances": validation.get("orlib50", {}).get("instances") if isinstance(validation.get("orlib50"), dict) else None,
        "safetydb_edges": inventory.get("edges"),
        "safetydb_claims_with_cve": inventory.get("claims_with_cve"),
        "pdf_reference_attestation": pdf.get("status"),
        "main_pages": pdf.get("main_pages"),
        "main_text_pages": pdf.get("main_text_pages"),
        "reference_pages": reference_page_count(pdf),
        "supplement_pages": pdf.get("supplement_pages"),
        "reference_count": pdf.get("reference_count"),
        "clean_extraction_replay": clean_replay_status,
        "deterministic_archives": "PASS" if archive_reports else "deferred_to_packaged_reproduction",
        "archive_reports": archive_reports,
        "archive_hash_location": "SHA256SUMS distributed beside generated ZIP files; archive hashes are omitted from in-archive subject attestations to avoid circular digests",
    }
    atomic_write_json(args.output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
