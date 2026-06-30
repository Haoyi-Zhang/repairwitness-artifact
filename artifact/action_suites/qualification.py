from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .canonical import (
    canonical_json_bytes,
    load_json,
    sha256_bytes,
    sha256_file,
    sha256_tree,
)
from .flow import Exclusion, Stage, StageCount, validate_stage_flow
from .sources import LOCKED_PROJECTION_RULES, load_source_manifest


@dataclass(frozen=True)
class Check:
    check_id: str
    passed: bool
    detail: str

    def to_dict(self) -> dict[str, object]:
        return {
            "check_id": self.check_id,
            "status": "PASS" if self.passed else "FAIL",
            "detail": self.detail,
        }


def _digest_path(root: Path, specification: Mapping[str, Any]) -> str:
    path = root / str(specification["path"])
    kind = specification.get("kind", "file")
    if kind == "file":
        return sha256_file(path)
    if kind == "tree":
        return sha256_tree(
            path,
            excluded_names=("__pycache__", ".pytest_cache", ".git"),
        )
    raise ValueError(f"unsupported digest kind: {kind}")


def _check_protocol_invariants(lock: Mapping[str, Any]) -> Check:
    expected_actions = [
        "NO_ACTION",
        "UPGRADE_TO_ADVISORY_TARGET",
        "ALTERNATIVE_ACTION",
        "REPAIR_WITHOUT_PUBLIC_TARGET",
        "UNKNOWN",
    ]
    errors: list[str] = []
    if lock.get("action_kinds") != expected_actions:
        errors.append("action domain changed")
    if lock.get("unknown_is_concrete_action") is not False:
        errors.append("UNKNOWN must remain non-concrete")
    if lock.get("unknown_can_witness") is not False:
        errors.append("UNKNOWN must not witness an edge")
    if lock.get("primary_comparison_kind") != "CURATION_LINEAGE":
        errors.append("primary edges must remain curation-lineage comparisons")
    if lock.get("observational_outcomes_authorized") is not False:
        errors.append("protocol lock must start with outcomes unauthorized")
    if lock.get("minimum_divergence_threshold") != 0:
        errors.append("minimum divergence threshold must be 0")
    if lock.get("minimum_compression_threshold") != 0:
        errors.append("minimum compression threshold must be 0")
    if lock.get("minimum_effect_threshold") != 0:
        errors.append("minimum effect threshold must be 0")
    if lock.get("significance_gate") != 1:
        errors.append("significance gate must be 1")
    if lock.get("result_dependent_stopping") is not False:
        errors.append("result-dependent stopping must remain disabled")
    rqs = lock.get("research_questions")
    if not isinstance(rqs, list) or [row.get("id") for row in rqs] != [
        "RQ1",
        "RQ2",
        "RQ3",
    ]:
        errors.append("research-question identities changed")
    return Check(
        "Q-PROTOCOL-INVARIANTS",
        not errors,
        "locked invariants verified" if not errors else "; ".join(errors),
    )


def _check_sources(root: Path, lock: Mapping[str, Any]) -> Check:
    try:
        manifest_spec = next(
            item
            for item in lock["required_inputs"]
            if item.get("role") == "source_manifest"
        )
        specs = load_source_manifest(root / manifest_spec["path"])
        resource_spec = next(
            item
            for item in lock["required_inputs"]
            if item.get("role") == "resource_lock"
        )
        resource_lock = load_json(root / resource_spec["path"])
        locked_sources = {
            str(row["source_id"]): row for row in resource_lock["advisory_sources"]
        }
        if set(locked_sources) != set(LOCKED_PROJECTION_RULES):
            raise ValueError("resource lock source set differs from code projection set")
        for spec in specs:
            locked = locked_sources[spec.source_id]
            if spec.commit != locked.get("commit"):
                raise ValueError(f"commit mismatch for {spec.source_id}")
            rule = LOCKED_PROJECTION_RULES[spec.source_id]
            if list(rule.include_globs) != locked.get("include_globs"):
                raise ValueError(f"projection allowlist mismatch for {spec.source_id}")
            if list(rule.adapter_supported_globs) != locked.get(
                "adapter_supported_globs"
            ):
                raise ValueError(f"adapter allowlist mismatch for {spec.source_id}")
    except Exception as exc:  # intentionally fail closed
        return Check("Q-SOURCE-PINS", False, f"source/resource lock invalid: {exc}")
    return Check(
        "Q-SOURCE-PINS",
        len(specs) == 5,
        f"{len(specs)} full-commit sources and projection rules locked",
    )


def _check_stage_flow(root: Path, lock: Mapping[str, Any]) -> Check:
    try:
        flow_spec = next(
            item
            for item in lock["required_inputs"]
            if item.get("role") == "stage_flow"
        )
        payload = load_json(root / flow_spec["path"])
        counts = tuple(
            StageCount(
                stage=Stage(row["stage"]),
                count=row.get("count"),
                status=row["status"],
                evidence_sha256=row.get("evidence_sha256"),
            )
            for row in payload["stages"]
        )
        exclusions = tuple(
            Exclusion(
                source_id=row["source_id"],
                from_stage=Stage(row["from_stage"]),
                to_stage=Stage(row["to_stage"]),
                count=int(row["count"]),
                reason_code=row["reason_code"],
                outcome_blind=bool(row["outcome_blind"]),
            )
            for row in payload.get("exclusions", [])
        )
        passed, errors = validate_stage_flow(counts, exclusions)
    except Exception as exc:
        return Check("Q-STAGE-FLOW", False, f"stage ledger invalid: {exc}")
    return Check(
        "Q-STAGE-FLOW",
        passed,
        "all nine stages byte-verified" if passed else "; ".join(errors),
    )


def _check_release_manifest(root: Path, lock: Mapping[str, Any]) -> Check:
    try:
        spec = next(
            item
            for item in lock["required_inputs"]
            if item.get("role") == "release_manifest"
        )
        path = root / spec["path"]
        with path.open("r", encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
    except Exception as exc:
        return Check(
            "Q-RELEASE-TERMINAL",
            False,
            f"release manifest unavailable ({type(exc).__name__})",
        )
    if not rows:
        return Check("Q-RELEASE-TERMINAL", False, "release manifest is empty")
    allowed = {"SUCCESS", "EMPTY", "FAILED"}
    invalid = [row for row in rows if row.get("status") not in allowed]
    package_keys = [row.get("package_key", "") for row in rows]
    duplicate = len(package_keys) != len(set(package_keys))
    passed = not invalid and not duplicate and all(package_keys)
    return Check(
        "Q-RELEASE-TERMINAL",
        passed,
        (
            f"{len(rows)} terminal package rows verified"
            if passed
            else "invalid, duplicate, or missing terminal package rows"
        ),
    )


def _check_sample(root: Path, lock: Mapping[str, Any]) -> Check:
    try:
        spec = next(
            item
            for item in lock["required_inputs"]
            if item.get("role") == "validation_sample"
        )
        with (root / spec["path"]).open("r", encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
    except Exception as exc:
        return Check(
            "Q-SAMPLE-CONTINUITY",
            False,
            f"sample unavailable ({type(exc).__name__})",
        )
    expected_rows = int(lock.get("validation_sample_rows", 96))
    passed = len(rows) == expected_rows
    return Check(
        "Q-SAMPLE-CONTINUITY",
        passed,
        f"sample rows={len(rows)}, expected={expected_rows}",
    )


def _check_no_observational_outputs(root: Path, lock: Mapping[str, Any]) -> Check:
    forbidden_root = root / str(
        lock.get("observational_output_root", "artifact/data/observational")
    )
    files = [] if not forbidden_root.exists() else [
        path for path in forbidden_root.rglob("*") if path.is_file()
    ]
    checkpoint_path = root / str(
        lock.get(
            "checkpoint_status_path",
            "artifact/data/recovery/checkpoint_status_transfer.json",
        )
    )
    checkpoint_ok = False
    try:
        checkpoint = load_json(checkpoint_path)
        checkpoint_ok = (
            checkpoint.get("observational_action_outcomes_computed") is False
            and checkpoint.get("current_runtime_contains_full_prior_artifact") is False
        )
    except Exception:
        checkpoint_ok = False
    passed = not files and checkpoint_ok
    return Check(
        "Q-NO-OBSERVATIONAL-OUTCOMES",
        passed,
        "no observational outcome bytes present and recovery boundary is explicit"
        if passed
        else f"found {len(files)} outcome files or inconsistent checkpoint state",
    )


def qualify(root: Path | str) -> dict[str, object]:
    """Perform static qualification without reading any authorization state."""

    root_path = Path(root).resolve()
    lock_path = root_path / "artifact/config/protocol_lock.json"
    lock = load_json(lock_path)
    checks: list[Check] = [_check_protocol_invariants(lock), _check_sources(root_path, lock)]
    input_digests: dict[str, str | None] = {}

    for specification in lock.get("required_inputs", []):
        name = str(specification["name"])
        path = root_path / str(specification["path"])
        if not path.exists():
            input_digests[name] = None
            checks.append(Check(f"Q-INPUT-{name}", False, f"missing {specification['path']}"))
            continue
        try:
            actual = _digest_path(root_path, specification)
        except Exception as exc:
            input_digests[name] = None
            checks.append(Check(f"Q-INPUT-{name}", False, f"digest failed: {exc}"))
            continue
        input_digests[name] = actual
        expected = specification.get("expected_sha256")
        if expected is None:
            checks.append(
                Check(
                    f"Q-INPUT-{name}",
                    False,
                    "input exists but its digest is not prospectively locked",
                )
            )
        else:
            checks.append(
                Check(
                    f"Q-INPUT-{name}",
                    actual == expected,
                    "digest matched" if actual == expected else "digest mismatch",
                )
            )

    checks.extend(
        [
            _check_stage_flow(root_path, lock),
            _check_release_manifest(root_path, lock),
            _check_sample(root_path, lock),
            _check_no_observational_outputs(root_path, lock),
        ]
    )
    payload: dict[str, object] = {
        "schema_version": 2,
        "qualification_kind": "STATIC_NON_RECURSIVE",
        "protocol_lock_sha256": sha256_file(lock_path),
        "checks": [check.to_dict() for check in checks],
        "input_digests": input_digests,
        "qualified": all(check.passed for check in checks),
        "authorization_state_read": False,
    }
    payload["qualification_sha256"] = sha256_bytes(canonical_json_bytes(payload))
    return payload
