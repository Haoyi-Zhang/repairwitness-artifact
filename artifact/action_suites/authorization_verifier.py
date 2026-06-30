from __future__ import annotations

from pathlib import Path

from .canonical import canonical_json_bytes, load_json, sha256_bytes
from .gates import build_gate_status
from .qualification import qualify


def _self_digest(value: dict[str, object], field: str) -> str:
    payload = dict(value)
    payload.pop(field, None)
    return sha256_bytes(canonical_json_bytes(payload))


def verify_authorization(root: Path | str) -> tuple[bool, tuple[str, ...]]:
    """Independently recompute qualification, gates, and authorization predicate.

    Every parse, digest, or recomputation failure is converted into a negative
    authorization result. The verifier never propagates malformed-state exceptions
    into a caller that might otherwise continue an observational run.
    """

    root_path = Path(root).resolve()
    errors: list[str] = []
    qualification_path = root_path / "artifact/verification/static_qualification.json"
    gate_path = root_path / "artifact/verification/gate_status.json"
    authorization_path = root_path / "artifact/verification/analysis_gate.json"
    for path in (qualification_path, gate_path, authorization_path):
        if not path.exists():
            errors.append(f"missing {path.relative_to(root_path).as_posix()}")
    if errors:
        return False, tuple(errors)

    try:
        stored_qualification = load_json(qualification_path)
    except Exception as exc:
        return False, (f"stored qualification is unreadable: {type(exc).__name__}: {exc}",)
    try:
        recomputed_qualification = qualify(root_path)
    except Exception as exc:
        return False, (f"independent qualification failed: {type(exc).__name__}: {exc}",)
    if stored_qualification != recomputed_qualification:
        errors.append("stored static qualification differs from independent recomputation")
    if recomputed_qualification.get("qualified") is not True:
        errors.append("static qualification is not PASS")
    if recomputed_qualification.get("qualification_sha256") != _self_digest(
        recomputed_qualification, "qualification_sha256"
    ):
        errors.append("qualification self-digest is invalid")

    try:
        stored_gates = load_json(gate_path)
        recomputed_gates = build_gate_status(root_path, recomputed_qualification)
    except Exception as exc:
        return False, tuple(errors + [f"independent gate construction failed: {type(exc).__name__}: {exc}"])
    if stored_gates != recomputed_gates:
        errors.append("stored gate status differs from independent recomputation")
    if recomputed_gates.get("all_pass") is not True:
        errors.append("one or more PA gates are not PASS")
    if recomputed_gates.get("gate_status_sha256") != _self_digest(
        recomputed_gates, "gate_status_sha256"
    ):
        errors.append("gate-status self-digest is invalid")

    try:
        authorization = load_json(authorization_path)
    except Exception as exc:
        return False, tuple(errors + [f"analysis gate is unreadable: {type(exc).__name__}: {exc}"])
    if authorization.get("analysis_gate_sha256") != _self_digest(
        authorization, "analysis_gate_sha256"
    ):
        errors.append("analysis-gate self-digest is invalid")
    if authorization.get("authorization_kind") != "OBSERVATIONAL_ACTION_EVALUATION":
        errors.append("authorization kind is invalid")
    if authorization.get("predicate") != "static_qualified && all_PA_01_through_PA_12_pass":
        errors.append("authorization predicate is invalid")
    if authorization.get("authorized") is not True:
        errors.append("authorization flag is not true")
    if authorization.get("qualification_sha256") != recomputed_qualification.get(
        "qualification_sha256"
    ):
        errors.append("analysis gate is not bound to current qualification")
    if authorization.get("gate_status_sha256") != recomputed_gates.get(
        "gate_status_sha256"
    ):
        errors.append("analysis gate is not bound to current gate status")
    if authorization.get("locked_input_digests") != recomputed_qualification.get(
        "input_digests"
    ):
        errors.append("analysis gate is not bound to current input digests")
    return not errors, tuple(errors)
