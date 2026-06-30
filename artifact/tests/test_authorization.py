from __future__ import annotations

import json
from pathlib import Path

import pytest

from action_suites.authorization_verifier import verify_authorization
from action_suites.authorization_writer import AuthorizationRefused, write_authorization
from action_suites.canonical import atomic_write_json
from action_suites.gates import build_gate_status
from action_suites.qualification import qualify
from action_suites.runtime_guard import ObservationalRunBlocked, require_authorized


def authorize(root: Path) -> None:
    qualification = qualify(root)
    assert qualification["qualified"] is True
    atomic_write_json(root / "artifact/verification/static_qualification.json", qualification)
    gates = build_gate_status(root, qualification)
    assert gates["all_pass"] is True
    atomic_write_json(root / "artifact/verification/gate_status.json", gates)
    write_authorization(root / "artifact/verification/analysis_gate.json", qualification, gates)


def test_static_qualification_does_not_read_authorization(authorizable_project: Path) -> None:
    atomic_write_json(
        authorizable_project / "artifact/verification/analysis_gate.json",
        {"authorized": False, "garbage": True},
    )
    result = qualify(authorizable_project)
    assert result["qualified"] is True
    assert result["authorization_state_read"] is False


def test_complete_acyclic_chain_authorizes(authorizable_project: Path) -> None:
    authorize(authorizable_project)
    passed, errors = verify_authorization(authorizable_project)
    assert passed, errors
    require_authorized(authorizable_project)


@pytest.mark.parametrize(
    "relative",
    [
        "artifact/config/protocol_lock.json",
        "artifact/source_manifest.csv",
        "artifact/data/recovery/stage_flow.json",
        "artifact/data/recovery/structural_claims.jsonl",
        "artifact/data/recovery/structural_groups.jsonl",
        "artifact/data/recovery/qualified_edges.jsonl",
        "artifact/data/recovery/package_frame.csv",
        "artifact/data/recovery/release_universe_manifest.csv",
        "artifact/data/recovery/release_universes.jsonl",
        "artifact/data/recovery/validation_sample_lock.csv",
        "artifact/action_suites/core.py",
        "artifact/config/baseline_lock.json",
        "artifact/config/resource_lock.json",
        "artifact/data/recovery/checkpoint_status_transfer.json",
    ],
)
def test_input_tampering_fails_closed(authorizable_project: Path, relative: str) -> None:
    authorize(authorizable_project)
    path = authorizable_project / relative
    path.write_bytes(path.read_bytes() + b"\nTAMPER")
    passed, errors = verify_authorization(authorizable_project)
    assert not passed
    assert errors
    with pytest.raises(ObservationalRunBlocked):
        require_authorized(authorizable_project)


def test_gate_status_tampering_fails_closed(authorizable_project: Path) -> None:
    authorize(authorizable_project)
    path = authorizable_project / "artifact/verification/gate_status.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    value["gates"][0]["status"] = "FAIL"
    atomic_write_json(path, value)
    assert not verify_authorization(authorizable_project)[0]


def test_authorization_payload_tampering_fails_closed(authorizable_project: Path) -> None:
    authorize(authorizable_project)
    path = authorizable_project / "artifact/verification/analysis_gate.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    value["authorized"] = False
    atomic_write_json(path, value)
    assert not verify_authorization(authorizable_project)[0]


def test_writer_refuses_failed_gate(authorizable_project: Path) -> None:
    qualification = qualify(authorizable_project)
    gates = build_gate_status(authorizable_project, qualification)
    gates["all_pass"] = False
    with pytest.raises(AuthorizationRefused):
        write_authorization(authorizable_project / "gate.json", qualification, gates)


def test_observational_runner_guards_before_reading_inputs_or_creating_output(
    authorizable_project: Path,
) -> None:
    import os
    import subprocess
    import sys

    script = Path(__file__).resolve().parents[1] / "scripts/run_observational_actions.py"
    output = authorizable_project / "must_not_exist"
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--project-root",
            str(authorizable_project),
            "--claims",
            str(authorizable_project / "missing-claims.jsonl"),
            "--edges",
            str(authorizable_project / "missing-edges.jsonl"),
            "--release-universes",
            str(authorizable_project / "missing-releases.jsonl"),
            "--output-dir",
            str(output),
        ],
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert completed.returncode == 4
    assert '"status": "BLOCKED"' in completed.stdout
    assert not output.exists()


def test_external_attestations_require_kind_specific_evidence(
    authorizable_project: Path,
) -> None:
    qualification = qualify(authorizable_project)
    cases = (
        (
            "artifact/verification/test_attestation.json",
            "PA-10",
            lambda value: value.__setitem__("observational_inputs_used", True),
        ),
        (
            "artifact/verification/audit_attestation.json",
            "PA-11",
            lambda value: value.pop("clean_extraction_replay"),
        ),
        (
            "artifact/verification/audit_attestation.json",
            "PA-11",
            lambda value: value.__setitem__("subject_tree_sha256", "0" * 64),
        ),
        (
            "artifact/verification/independent_audit_attestation.json",
            "PA-12",
            lambda value: value.__setitem__("major_findings", ["unresolved"]),
        ),
    )
    for relative, gate_id, mutate in cases:
        path = authorizable_project / relative
        original = json.loads(path.read_text(encoding="utf-8"))
        tampered = json.loads(path.read_text(encoding="utf-8"))
        mutate(tampered)
        atomic_write_json(path, tampered)
        gates = build_gate_status(authorizable_project, qualification)
        row = next(item for item in gates["gates"] if item["gate_id"] == gate_id)
        assert row["status"] == "FAIL"
        atomic_write_json(path, original)
