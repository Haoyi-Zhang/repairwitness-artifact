from __future__ import annotations

from pathlib import Path
from typing import Mapping

from .audit import audit_subject_digest
from .canonical import canonical_json_bytes, load_json, sha256_bytes, sha256_file


_GATE_MAP: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("PA-01", ("Q-PROTOCOL-INVARIANTS",), "protocol, estimands, and no-threshold policy locked"),
    ("PA-02", ("Q-SOURCE-PINS", "Q-INPUT-source_manifest", "Q-INPUT-resource_lock"), "source commits and projection rules locked"),
    ("PA-03", ("Q-STAGE-FLOW", "Q-INPUT-stage_flow"), "nine-stage candidate flow byte-verified"),
    (
        "PA-04",
        (
            "Q-INPUT-structural_claims",
            "Q-INPUT-structural_groups",
            "Q-INPUT-qualified_edges",
            "Q-INPUT-package_frame",
        ),
        "claims, groups, edges, and package frame jointly locked",
    ),
    ("PA-05", ("Q-RELEASE-TERMINAL", "Q-INPUT-release_manifest", "Q-INPUT-release_universes"), "all package release universes terminal and locked"),
    ("PA-06", ("Q-SAMPLE-CONTINUITY", "Q-INPUT-validation_sample"), "unchanged 96-row validation sample verified"),
    ("PA-07", ("Q-INPUT-semantic_implementation",), "semantic, comparator, and certificate implementation locked"),
    ("PA-08", ("Q-INPUT-baseline_lock",), "baseline definitions and metrics locked"),
    ("PA-09", ("Q-NO-OBSERVATIONAL-OUTCOMES", "Q-INPUT-checkpoint_status"), "outcome-blind pre-analysis state verified"),
)


def _kind_specific_attestation_errors(
    root: Path, value: Mapping[str, object], expected_kind: str
) -> list[str]:
    errors: list[str] = []
    if value.get("status") != "PASS":
        errors.append("status is not PASS")
    if value.get("kind") != expected_kind:
        errors.append("kind mismatch")

    if expected_kind == "DETERMINISTIC_TESTS":
        if value.get("observational_inputs_used") is not False:
            errors.append("tests did not attest outcome-blind execution")
        command = value.get("command")
        if not isinstance(command, str) or "pytest" not in command:
            errors.append("pytest command is not recorded")
        output_tail = value.get("output_tail")
        if not isinstance(output_tail, str) or "passed" not in output_tail:
            errors.append("passing test summary is not recorded")
    elif expected_kind == "ARTIFACT_AUDIT":
        if value.get("repository_audit") != "PASS":
            errors.append("repository audit is not PASS")
        if value.get("clean_extraction_replay") != "PASS":
            errors.append("clean extraction replay is not PASS")
        if value.get("observational_outputs_absent") is not True:
            errors.append("absence of observational outputs is not attested")
        if value.get("errors") != []:
            errors.append("audit errors are nonempty or missing")
        recorded_subject = value.get("subject_tree_sha256")
        current_subject = audit_subject_digest(root)
        if recorded_subject != current_subject:
            errors.append("clean-replay subject digest mismatch")
    elif expected_kind == "INDEPENDENT_AUDIT_CLOSURE":
        if value.get("critical_findings") != []:
            errors.append("critical audit findings remain")
        if value.get("major_findings") != []:
            errors.append("major audit findings remain")
        facets = value.get("facets")
        if not isinstance(facets, list) or len(facets) < 9:
            errors.append("fewer than nine audit facets are attested")
    return errors


def _attestation_status(
    root: Path, relative_path: str, expected_kind: str
) -> tuple[bool, str | None, str]:
    path = root / relative_path
    if not path.exists():
        return False, None, f"missing {relative_path}"
    try:
        value = load_json(path)
    except Exception as exc:
        return False, None, f"invalid attestation: {exc}"
    if not isinstance(value, Mapping):
        return False, sha256_file(path), "attestation must be a JSON object"
    errors = _kind_specific_attestation_errors(root, value, expected_kind)
    passed = not errors
    detail = "attestation contract verified" if passed else "; ".join(errors)
    return passed, sha256_file(path), detail


def build_gate_status(root: Path | str, qualification: Mapping[str, object]) -> dict[str, object]:
    root_path = Path(root).resolve()
    checks = {
        row["check_id"]: row["status"] == "PASS"
        for row in qualification["checks"]  # type: ignore[index]
    }
    gates: list[dict[str, object]] = []
    for gate_id, required_checks, description in _GATE_MAP:
        missing_or_failed = [check for check in required_checks if not checks.get(check, False)]
        gates.append(
            {
                "gate_id": gate_id,
                "status": "PASS" if not missing_or_failed else "FAIL",
                "description": description,
                "evidence": list(required_checks),
                "detail": (
                    "all qualification predicates passed"
                    if not missing_or_failed
                    else f"failed predicates: {missing_or_failed}"
                ),
            }
        )

    attestation_specs = (
        ("PA-10", "artifact/verification/test_attestation.json", "DETERMINISTIC_TESTS", "deterministic and tamper tests pass"),
        ("PA-11", "artifact/verification/audit_attestation.json", "ARTIFACT_AUDIT", "artifact audit and clean extraction replay pass"),
        ("PA-12", "artifact/verification/independent_audit_attestation.json", "INDEPENDENT_AUDIT_CLOSURE", "independent implementation audit has no critical or major blockers"),
    )
    external_digests: dict[str, str | None] = {}
    for gate_id, path, kind, description in attestation_specs:
        passed, digest, detail = _attestation_status(root_path, path, kind)
        external_digests[gate_id] = digest
        gates.append(
            {
                "gate_id": gate_id,
                "status": "PASS" if passed else "FAIL",
                "description": description,
                "evidence": [path],
                "detail": detail,
            }
        )

    payload: dict[str, object] = {
        "schema_version": 2,
        "qualification_sha256": qualification["qualification_sha256"],
        "gates": gates,
        "external_evidence_sha256": external_digests,
        "all_pass": all(row["status"] == "PASS" for row in gates),
    }
    payload["gate_status_sha256"] = sha256_bytes(canonical_json_bytes(payload))
    return payload
