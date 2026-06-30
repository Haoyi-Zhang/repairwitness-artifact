from __future__ import annotations

from pathlib import Path
from typing import Mapping

from .canonical import atomic_write_json, canonical_json_bytes, sha256_bytes


class AuthorizationRefused(RuntimeError):
    pass


def _self_digest(value: Mapping[str, object], field: str) -> str:
    payload = dict(value)
    payload.pop(field, None)
    return sha256_bytes(canonical_json_bytes(payload))


def construct_authorization(
    qualification: Mapping[str, object],
    gate_status: Mapping[str, object],
) -> dict[str, object]:
    if qualification.get("qualification_sha256") != _self_digest(
        qualification, "qualification_sha256"
    ):
        raise AuthorizationRefused("static qualification self-digest is invalid")
    if gate_status.get("gate_status_sha256") != _self_digest(
        gate_status, "gate_status_sha256"
    ):
        raise AuthorizationRefused("gate-status self-digest is invalid")
    if gate_status.get("qualification_sha256") != qualification.get(
        "qualification_sha256"
    ):
        raise AuthorizationRefused("gate status is not bound to this qualification")
    if qualification.get("qualified") is not True:
        raise AuthorizationRefused("static qualification is not PASS")
    if gate_status.get("all_pass") is not True:
        raise AuthorizationRefused("one or more PA gates are not PASS")
    expected_ids = {f"PA-{index:02d}" for index in range(1, 13)}
    gates = gate_status.get("gates")
    if not isinstance(gates, list):
        raise AuthorizationRefused("gate rows are unavailable")
    observed_ids = {str(row.get("gate_id")) for row in gates if isinstance(row, Mapping)}
    if observed_ids != expected_ids or any(
        not isinstance(row, Mapping) or row.get("status") != "PASS" for row in gates
    ):
        raise AuthorizationRefused("PA-01 through PA-12 are not uniquely PASS")

    payload: dict[str, object] = {
        "schema_version": 1,
        "authorization_kind": "OBSERVATIONAL_ACTION_EVALUATION",
        "authorized": True,
        "qualification_sha256": qualification["qualification_sha256"],
        "gate_status_sha256": gate_status["gate_status_sha256"],
        "locked_input_digests": qualification["input_digests"],
        "predicate": "static_qualified && all_PA_01_through_PA_12_pass",
    }
    payload["analysis_gate_sha256"] = sha256_bytes(canonical_json_bytes(payload))
    return payload


def write_authorization(
    path: Path | str,
    qualification: Mapping[str, object],
    gate_status: Mapping[str, object],
) -> dict[str, object]:
    payload = construct_authorization(qualification, gate_status)
    atomic_write_json(path, payload)
    return payload
