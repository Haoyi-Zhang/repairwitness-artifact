from __future__ import annotations

import json
import stat
import tarfile
import zipfile
from dataclasses import replace
from io import BytesIO
from pathlib import Path

import pytest

from action_suites.sources import (
    ProjectionRule,
    SourceSpec,
    _safe_member_name,
    decode_member,
    iter_projected_archive_members,
    syntax_decodable,
)
from repairwitness.certification import (
    CertifiedSuiteBundle,
    OracleAttestation,
    solve_certified,
    verify_certified_bundle,
)
from repairwitness.audit import (
    audit_repository as rw_audit_repository,
    audit_subject_digest as rw_audit_subject_digest,
    iter_audit_subject_files as rw_iter_audit_subject_files,
    iter_publishable_files as rw_iter_publishable_files,
)
from repairwitness.canonical import (
    CanonicalizationError,
    atomic_write_json,
    canonical_json_bytes,
    length_prefixed_path_content_digest,
    load_json,
    sha256_tree,
)
from repairwitness.interval import (
    IntervalStep,
    recognition_from_bounds,
    recognize_intervals,
    solve_interval_multicover,
    verify_interval_certificate,
)
from repairwitness.oracle import (
    solve_exhaustive_oracle,
    solve_independent_oracle,
    solve_milp_oracle,
)
from repairwitness.orlib import (
    OrlibFormatError,
    OrlibInstance,
    OrlibManifestEntry,
    load_orlib_manifest,
    parse_orlib_scp,
)
from repairwitness.package import (
    ReleaseArchiveError,
    ReleaseManifest,
    ReleaseMember,
    archive_report,
    create_deterministic_zip,
    verify_release_zip,
)
from repairwitness.suite import (
    ComponentProof,
    InfeasibleSuiteProblem,
    KernelStats,
    SuiteCertificate,
    _integer_value,
    _sequence_field,
    obligation_digest,
    solve_exact,
    verify_certificate,
)
from action_suites.model import (
    Action,
    ActionKind,
    BlockerCode,
    Edge,
    ReleaseUniverse,
    action_trace_digest,
    classify_edge,
    witness_releases,
)


def test_suite_deserializers_and_normalizers_reject_noncanonical_inputs() -> None:
    assert _sequence_field(["a"], "field") == ["a"]
    with pytest.raises(ValueError, match="JSON array"):
        _sequence_field("abc", "field")
    assert _integer_value("7", "field") == 7
    with pytest.raises(ValueError, match="not a Boolean"):
        _integer_value(True, "field")
    with pytest.raises(ValueError, match="must be an integer"):
        _integer_value("nan", "field")

    legacy = KernelStats.from_dict(
        {
            "forced_releases": ["r2"],
            "forced_cost": "4",
            "forced_covered_edges": "3",
            "components": "2",
        }
    )
    assert legacy.forced_releases == ("r2",)
    assert legacy.components == 2
    assert KernelStats.from_dict(None).state_space_upper_bound == 1
    with pytest.raises(ValueError, match="kernel.forced_releases"):
        KernelStats.from_dict({"forced_releases": "r2"})

    proof = {
        "edge_ids": ["e"],
        "selected_releases": ["r"],
        "lower_bound": 1,
        "upper_bound": 1,
        "explored_nodes": 3,
        "node_budget": None,
        "exact": True,
        "proof_kind": "DYNAMIC_PROGRAMMING_EXHAUSTIVE",
    }
    assert ComponentProof.from_dict(proof).selected_releases == ("r",)
    with pytest.raises(ValueError, match="component.exact"):
        ComponentProof.from_dict({**proof, "exact": "yes"})

    with pytest.raises(ValueError, match="at least one"):
        solve_exact({})
    with pytest.raises(ValueError, match="edge identifiers"):
        solve_exact({"": {"r"}})
    with pytest.raises(ValueError, match="no concrete witness"):
        solve_exact({"e": set()})
    with pytest.raises(ValueError, match="unknown edges"):
        solve_exact({"e": {"r"}}, demands={"other": 1})
    with pytest.raises(ValueError, match="non-positive demand"):
        solve_exact({"e": {"r"}}, demands={"e": 0})
    with pytest.raises(InfeasibleSuiteProblem):
        solve_exact({"e": {"r"}}, demands={"e": 2})
    with pytest.raises(ValueError, match="unknown releases"):
        solve_exact({"e": {"r"}}, costs={"other": 1})
    with pytest.raises(ValueError, match="non-positive execution cost"):
        solve_exact({"e": {"r"}}, costs={"r": 0})


def test_suite_certificate_round_trips_and_tamper_errors_are_specific() -> None:
    obligations = {"e0": {"a", "b"}, "e1": {"b", "c"}}
    certificate = solve_exact(obligations)
    legacy = certificate.to_dict()
    legacy.pop("edge_witnesses")
    restored = SuiteCertificate.from_dict(legacy)
    assert restored.edge_witnesses == certificate.edge_witnesses
    assert verify_certificate(obligations, restored)[0]

    with pytest.raises(ValueError, match="component_proofs rows"):
        SuiteCertificate.from_dict({**certificate.to_dict(), "component_proofs": [[]]})

    bad_header = replace(
        certificate,
        solver_version="0.0",
        selected_releases=("b", "b", "z"),
        upper_bound=999,
    )
    passed, errors = verify_certificate(obligations, bad_header, verify_optimality=False)
    assert not passed
    assert any("unsupported solver version" in error for error in errors)
    assert any("duplicates" in error or "duplicate" in error for error in errors)
    assert any("unknown values" in error for error in errors)
    assert any("upper bound" in error for error in errors)

    bad_witnesses = replace(certificate, edge_witnesses=(("e0", ("a",)), ("e0", ("a",))))
    passed, errors = verify_certificate(obligations, bad_witnesses, verify_optimality=False)
    assert not passed
    assert any("duplicate edge identifiers" in error for error in errors)
    assert any("witness assignments do not match" in error for error in errors)

    bad_component = replace(
        certificate,
        component_proofs=(replace(certificate.component_proofs[0], proof_kind="UNKNOWN"),),
    )
    passed, errors = verify_certificate(obligations, bad_component, verify_optimality=False)
    assert not passed
    assert any("proof replay failed" in error for error in errors)


def test_certified_bundle_rejects_bad_metadata_and_oracle_attestations() -> None:
    obligations = {"e0": {"a", "b"}, "e1": {"b"}}
    bundle = solve_certified(obligations, independent_oracle=True)
    assert verify_certified_bundle(obligations, bundle, profile="strict")[0]

    oracle_payload = {
        "problem_sha256": obligation_digest(obligations),
        "backend": "EXHAUSTIVE",
        "selected_releases": ["b"],
        "optimal_cost": 1,
        "explored_units": 2,
    }
    with pytest.raises(ValueError, match="selected_releases"):
        OracleAttestation.from_dict({**oracle_payload, "selected_releases": [1]})
    with pytest.raises(ValueError, match="optimal_cost"):
        OracleAttestation.from_dict({**oracle_payload, "optimal_cost": -1})
    with pytest.raises(ValueError, match="problem_sha256"):
        OracleAttestation.from_dict({**oracle_payload, "problem_sha256": "bad"})
    with pytest.raises(ValueError, match="backend"):
        OracleAttestation.from_dict({**oracle_payload, "backend": ""})

    with pytest.raises(ValueError, match="suite must"):
        CertifiedSuiteBundle.from_dict({**bundle.to_dict(), "suite": []})
    with pytest.raises(ValueError, match="dual must"):
        CertifiedSuiteBundle.from_dict({**bundle.to_dict(), "dual": []})
    with pytest.raises(ValueError, match="oracle must"):
        CertifiedSuiteBundle.from_dict({**bundle.to_dict(), "oracle": []})
    with pytest.raises(ValueError, match="proof_channels"):
        CertifiedSuiteBundle.from_dict({**bundle.to_dict(), "proof_channels": [0]})
    with pytest.raises(ValueError, match="optimality_gap"):
        CertifiedSuiteBundle.from_dict({**bundle.to_dict(), "optimality_gap": 99})
    with pytest.raises(ValueError, match="unknown verification profile"):
        verify_certified_bundle(obligations, bundle, profile="loose")  # type: ignore[arg-type]

    wrong_channels = replace(bundle, proof_channels=("PRIMARY_SEARCH_REPLAY",))
    passed, errors = verify_certified_bundle(obligations, wrong_channels)
    assert not passed
    assert any("proof channel list" in error for error in errors)

    bad_oracle = OracleAttestation(
        problem_sha256=obligation_digest(obligations),
        backend="UNSUPPORTED",
        selected_releases=("missing",),
        optimal_cost=1,
        explored_units=1,
    )
    with_bad_oracle = replace(bundle, oracle=bad_oracle)
    passed, errors = verify_certified_bundle(obligations, with_bad_oracle)
    assert not passed
    assert any("unsupported oracle backend" in error for error in errors)
    assert any("unknown releases" in error for error in errors)


def test_interval_recognition_and_trace_guards_cover_negative_paths() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        recognition_from_bounds([], {})
    with pytest.raises(ValueError, match="duplicates"):
        recognition_from_bounds(["a", "a"], {})
    with pytest.raises(ValueError, match="two or three"):
        recognition_from_bounds(["a"], {"e": (0,)})  # type: ignore[dict-item]
    with pytest.raises(ValueError, match="must contain integers"):
        recognition_from_bounds(["a"], {"e": (0, True)})
    with pytest.raises(ValueError, match="outside release_order"):
        recognition_from_bounds(["a"], {"e": (1, 1)})
    with pytest.raises(ValueError, match="exceeds its interval width"):
        recognition_from_bounds(["a"], {"e": (0, 0, 2)})
    with pytest.raises(ValueError, match="contains unknown releases"):
        recognize_intervals(["a"], {"e": {"b"}})
    with pytest.raises(ValueError, match="not contiguous"):
        recognize_intervals(["a", "b", "c"], {"e": {"a", "c"}})
    with pytest.raises(ValueError, match="unknown obligations"):
        recognize_intervals(["a"], {"e": {"a"}}, demands={"extra": 1})

    cert = solve_interval_multicover(("a", "b", "c"), {"e0": (0, 1), "e1": (1, 2)})
    wrong_kind = replace(cert, proof_kind="WRONG")
    passed, errors = verify_interval_certificate(("a", "b", "c"), {"e0": (0, 1), "e1": (1, 2)}, wrong_kind)
    assert not passed
    assert "unexpected interval proof kind" in errors

    wrong_step = replace(
        cert,
        steps=(replace(cert.steps[0], edge_id="other"), cert.steps[1]),
    )
    passed, errors = verify_interval_certificate(("a", "b", "c"), {"e0": (0, 1), "e1": (1, 2)}, wrong_step)
    assert not passed
    assert any("step edge mismatch" in error for error in errors)

    impossible_trace = replace(
        cert,
        steps=(IntervalStep("e0", 0, (0, 1)), cert.steps[1]),
    )
    passed, errors = verify_interval_certificate(("a", "b", "c"), {"e0": (0, 1), "e1": (1, 2)}, impossible_trace)
    assert not passed
    assert any("insert count mismatch" in error or "insertion mismatch" in error for error in errors)


def test_oracle_boundaries_select_backends_and_reject_invalid_models() -> None:
    assert solve_exhaustive_oracle({}).selected_releases == ()
    with pytest.raises(ValueError, match="at most 1 releases"):
        solve_exhaustive_oracle({"e": {"a", "b"}}, release_limit=1)
    with pytest.raises(ValueError, match="positive integer"):
        solve_exhaustive_oracle({"e": {"a"}}, demands={"e": True})
    with pytest.raises(ValueError, match="unknown releases"):
        solve_exhaustive_oracle({"e": {"a"}}, costs={"missing": 1})

    result = solve_independent_oracle({"e": {"a", "b"}}, exhaustive_release_limit=2)
    assert result.backend == "EXHAUSTIVE"

    empty_milp = solve_milp_oracle({})
    assert empty_milp.backend == "SCIPY_HIGHS_MILP"
    assert empty_milp.optimal_cost == 0


def test_orlib_parser_manifest_and_instance_guards_are_fail_closed(tmp_path: Path) -> None:
    valid_sha = "0" * 64
    assert OrlibInstance("i", 1, 1, (1,), ((1,),), valid_sha).digest
    for kwargs in [
        {"name": "", "row_count": 1, "column_count": 1, "costs": (1,), "row_columns": ((1,),), "source_sha256": valid_sha},
        {"name": "i", "row_count": 0, "column_count": 1, "costs": (1,), "row_columns": ((1,),), "source_sha256": valid_sha},
        {"name": "i", "row_count": 1, "column_count": 1, "costs": (0,), "row_columns": ((1,),), "source_sha256": valid_sha},
        {"name": "i", "row_count": 1, "column_count": 1, "costs": (1,), "row_columns": ((2,),), "source_sha256": valid_sha},
        {"name": "i", "row_count": 1, "column_count": 1, "costs": (1,), "row_columns": ((1,),), "source_sha256": "bad"},
    ]:
        with pytest.raises(ValueError):
            OrlibInstance(**kwargs)

    bad_inputs = [
        b"\xff",
        b"1",
        b"1 1 0 1 1",
        b"1 1 1 0",
        b"1 2 1 1 2 1 1",
        b"1 2 1 1 2 1 1 1",
        b"1 2 1 1 3 1 1 2",
    ]
    for content in bad_inputs:
        with pytest.raises(OrlibFormatError):
            parse_orlib_scp(content, name="bad", max_incidences=1)

    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps({"instances": [{"name": "b", "url": "u", "best_known_cost": 1}, {"name": "a", "url": "u", "best_known_cost": 1}]}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unique and sorted"):
        load_orlib_manifest(manifest)
    with pytest.raises(ValueError, match="positive"):
        OrlibManifestEntry.from_dict({"name": "x", "url": "u", "best_known_cost": 0})


def test_release_archive_manifest_and_metadata_guards(tmp_path: Path) -> None:
    with pytest.raises(ReleaseArchiveError, match="member fields"):
        ReleaseMember.from_dict({"path": "x"})
    with pytest.raises(ReleaseArchiveError, match="unsafe archive path"):
        ReleaseMember.from_dict({"path": "../x", "sha256": "0" * 64, "size": 1, "mode": "0644"})
    with pytest.raises(ReleaseArchiveError, match="mode"):
        ReleaseMember.from_dict({"path": "x", "sha256": "0" * 64, "size": 1, "mode": "0777"})
    with pytest.raises(ReleaseArchiveError, match="schema_version"):
        ReleaseManifest.from_dict(
            {
                "schema_version": 2,
                "project": "RepairWitness",
                "version": "1",
                "root_prefix": "RepairWitness/",
                "member_count": 0,
                "members": [],
                "subject_sha256": "0" * 64,
                "timestamp_policy": "ZIP_DOS_2020-01-01T00:00:00",
                "permission_policy": "0644_FILES_0755_SCRIPTS",
            }
        )

    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        info = zipfile.ZipInfo("RepairWitness/RELEASE_MANIFEST.json", (2024, 1, 1, 0, 0, 0))
        info.external_attr = (stat.S_IFREG | 0o644) << 16
        handle.writestr(info, b"{}")
        handle.writestr("RepairWitness/dir/", b"")
    passed, errors, manifest = verify_release_zip(archive)
    assert not passed
    assert manifest is None
    assert any("non-deterministic timestamp" in error for error in errors)
    assert any("unexpected directory" in error for error in errors)

    root = tmp_path / "root"
    (root / "paper").mkdir(parents=True)
    (root / "artifact").mkdir()
    (root / "paper" / "main.tex").write_text("x", encoding="utf-8")
    output = tmp_path / "ok.zip"
    manifest = create_deterministic_zip(root, output, files=[root / "paper" / "main.tex"])
    report = archive_report(output)
    assert report["status"] == "PASS"
    assert report["member_count"] == len(manifest.members)


def test_source_projection_guards_and_decoders(tmp_path: Path) -> None:
    spec = SourceSpec("S", "https://github.com/owner/repo", "git", "0" * 40, "MIT", "role")
    assert spec.owner_repo == "owner/repo"
    assert spec.archive_url.endswith("/archive/" + "0" * 40 + ".tar.gz")
    with pytest.raises(ValueError, match="unsupported source URL"):
        SourceSpec("S", "https://example.com/repo", "git", "0" * 40, "MIT", "role").owner_repo

    assert _safe_member_name("repo/path/file.json") == "path/file.json"
    with pytest.raises(ValueError, match="unsafe archive member"):
        _safe_member_name("repo/../evil.json")
    with pytest.raises(ValueError, match="repository root"):
        _safe_member_name("lonely.json")

    rule = ProjectionRule(
        "S",
        include_globs=("data/*.json", "reports/*.yaml"),
        adapter_supported_globs=("data/*.json",),
        unsupported_reason_by_glob=(("reports/*.yaml", "REPORT_ONLY"),),
    )
    archive = tmp_path / "src.tar.gz"
    with tarfile.open(archive, "w:gz") as handle:
        for name, content in [
            ("repo/data/a.json", b'{"x": 1}'),
            ("repo/reports/a.yaml", b"x: 1\n"),
            ("repo/ignored.txt", b"x"),
        ]:
            info = tarfile.TarInfo(name)
            info.size = len(content)
            handle.addfile(info, BytesIO(content))
    rows = list(iter_projected_archive_members(archive, rule))
    assert [(row[0], row[2], row[3]) for row in rows] == [
        ("data/a.json", True, None),
        ("reports/a.yaml", False, "REPORT_ONLY"),
    ]

    bad_archive = tmp_path / "bad.tar.gz"
    with tarfile.open(bad_archive, "w:gz") as handle:
        content = b"{}"
        info = tarfile.TarInfo("repo/../evil.json")
        info.size = len(content)
        handle.addfile(info, BytesIO(content))
    with pytest.raises(ValueError, match="unsafe archive member"):
        list(iter_projected_archive_members(bad_archive, rule))

    assert decode_member("x.json", b'{"a": 1}') == {"a": 1}
    assert decode_member("x.yaml", b"a: 1\n") == {"a": 1}
    with pytest.raises(ValueError, match="no generic decoder"):
        decode_member("x.txt", b"x")
    assert syntax_decodable("x.md", b"```toml\n[advisory]\nid='RUSTSEC-1'\n```\n")
    assert not syntax_decodable("x.md", b"[advisory]\nid='RUSTSEC-1'\n")


def _minimal_release_tree(root: Path) -> None:
    files = {
        "paper/main.tex": "\\documentclass{article}\n",
        "paper/supplement.tex": "\\documentclass{article}\n",
        "paper/references.bib": "",
        "artifact/README.md": "# Artifact\n",
        "artifact/reproduction.md": "# Reproduction\n",
        "artifact/study_protocol.md": "# Protocol\n",
        "artifact/source_manifest.csv": "source_id,url\n",
        "artifact/verification/local_reproduction.json": '{"status":"PASS"}\n',
        "artifact/verification/clean_replay.json": '{"status":"PASS"}\n',
        "artifact/verification/frozen.json": '{"status":"PASS"}\n',
    }
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def test_repairwitness_audit_rejects_dirty_trees_and_filters_run_outputs(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _minimal_release_tree(root)
    passed, errors = rw_audit_repository(root)
    assert passed, errors

    published = {path.relative_to(root).as_posix() for path in rw_iter_publishable_files(root)}
    assert "artifact/verification/local_reproduction.json" not in published
    assert "artifact/verification/clean_replay.json" not in published
    assert "artifact/verification/frozen.json" in published
    subject = {path.relative_to(root).as_posix() for path in rw_iter_audit_subject_files(root)}
    assert "artifact/verification/frozen.json" not in subject
    assert rw_audit_subject_digest(root) == rw_audit_subject_digest(root)

    (root / "README.md").write_text("extra", encoding="utf-8")
    passed, errors = rw_audit_repository(root)
    assert not passed
    assert any("top-level entries" in error for error in errors)
    (root / "README.md").unlink()

    (root / "artifact" / "__pycache__").mkdir()
    (root / "artifact" / "__pycache__" / "x.pyc").write_bytes(b"\0")
    passed, errors = rw_audit_repository(root)
    assert not passed
    assert any("forbidden directory" in error for error in errors)
    assert any("forbidden generated file" in error for error in errors)
    (root / "artifact" / "__pycache__" / "x.pyc").unlink()
    (root / "artifact" / "__pycache__").rmdir()

    (root / "paper" / "notes.txt").write_text("draft", encoding="utf-8")
    temporary_path_literal = "temporary path /" + "tmp" + "/private\n"
    (root / "artifact" / "leak.md").write_text(temporary_path_literal, encoding="utf-8")
    (root / "artifact" / "bad.json").write_bytes(b"\xff")
    passed, errors = rw_audit_repository(root)
    assert not passed
    assert any("unexpected paper file" in error for error in errors)
    assert any("temporary absolute path" in error for error in errors)
    assert any("declared text file is not UTF-8" in error for error in errors)


def test_canonical_digest_and_atomic_write_boundaries(tmp_path: Path) -> None:
    assert canonical_json_bytes({"b": 2, "a": 1}) == b'{"a":1,"b":2}\n'
    with pytest.raises(CanonicalizationError):
        canonical_json_bytes({"bad": float("nan")})
    with pytest.raises(CanonicalizationError, match="duplicate canonical path"):
        length_prefixed_path_content_digest([("x", b"1"), ("x", b"2")])

    root = tmp_path / "tree"
    (root / "keep").mkdir(parents=True)
    (root / "skip").mkdir()
    (root / "keep" / "a.txt").write_text("a", encoding="utf-8")
    (root / "skip" / "b.txt").write_text("b", encoding="utf-8")
    assert sha256_tree(root, excluded_names=("skip",)) == length_prefixed_path_content_digest([("keep/a.txt", b"a")])

    output = tmp_path / "nested" / "value.json"
    atomic_write_json(output, {"ok": True})
    assert load_json(output) == {"ok": True}
    assert not list(output.parent.glob(".value.json.*"))


def test_action_model_invariants_and_classification_edges() -> None:
    with pytest.raises(ValueError, match="requires at least one"):
        Action(ActionKind.UPGRADE_TO_ADVISORY_TARGET)
    with pytest.raises(ValueError, match="cannot carry upgrade targets"):
        Action(ActionKind.NO_ACTION, targets=("2.0",))
    with pytest.raises(ValueError, match="requires a mechanism"):
        Action(ActionKind.ALTERNATIVE_ACTION)
    with pytest.raises(ValueError, match="cannot carry an alternative"):
        Action(ActionKind.NO_ACTION, mechanism="manual")
    with pytest.raises(ValueError, match="UNKNOWN requires"):
        Action(ActionKind.UNKNOWN)
    with pytest.raises(ValueError, match="concrete action"):
        Action(ActionKind.NO_ACTION, blocker=BlockerCode.INDETERMINATE)

    upgrade = Action(ActionKind.UPGRADE_TO_ADVISORY_TARGET, targets=("2.0", "2.0", "1.0"))
    assert upgrade.targets == ("1.0", "2.0")
    restored = Action.from_dict(upgrade.to_dict())
    assert restored == upgrade
    unknown = Action(ActionKind.UNKNOWN, blocker=BlockerCode.UNSUPPORTED_RANGE)
    no_action = Action(ActionKind.NO_ACTION)
    releases = ("1.0", "2.0")

    with pytest.raises(ValueError, match="duplicate release"):
        ReleaseUniverse("pkg", ("1.0", "1.0"), "0" * 64)
    with pytest.raises(ValueError, match="requires a package"):
        ReleaseUniverse("", ("1.0",), "0" * 64)
    with pytest.raises(ValueError, match="SHA-256"):
        ReleaseUniverse("pkg", ("1.0",), "bad")
    assert ReleaseUniverse("pkg", releases, "0" * 64).digest
    with pytest.raises(ValueError, match="non-empty"):
        Edge("", "left", "right")
    with pytest.raises(ValueError, match="distinct"):
        Edge("e", "same", "same")

    with pytest.raises(ValueError, match="missing_left"):
        witness_releases(releases, {"1.0": no_action}, {"1.0": no_action, "2.0": no_action})
    assert witness_releases(releases, {"1.0": no_action, "2.0": upgrade}, {"1.0": no_action, "2.0": no_action}) == frozenset({"2.0"})
    assert classify_edge(releases, {"1.0": unknown, "2.0": unknown}, {"1.0": unknown, "2.0": unknown}) == "INDETERMINATE"
    assert classify_edge(releases, {"1.0": no_action, "2.0": unknown}, {"1.0": no_action, "2.0": unknown}) == "INDETERMINATE"
    assert classify_edge(releases, {"1.0": no_action, "2.0": no_action}, {"1.0": no_action, "2.0": no_action}) == "RESOLVED_EQUIVALENT"
    assert classify_edge(releases, {"1.0": no_action, "2.0": no_action}, {"1.0": no_action, "2.0": upgrade}) == "RESOLVED_DIVERGENT"
    assert action_trace_digest({"2.0": upgrade, "1.0": no_action}) == action_trace_digest({"1.0": no_action, "2.0": upgrade})
