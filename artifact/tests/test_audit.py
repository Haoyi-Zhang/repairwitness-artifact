from __future__ import annotations

from pathlib import Path

import pytest

from action_suites.audit import audit_repository, iter_publishable_files
from action_suites.package import create_deterministic_zip


def test_audit_scopes_forbidden_directory_names_to_project_relative_paths(
    tmp_path: Path,
) -> None:
    root = tmp_path / "tmp" / "project"
    required = {
        "paper/main.tex": r"\\documentclass{article}\n",
        "paper/supplement.tex": r"\\documentclass{article}\n",
        "paper/references.bib": "",
        "artifact/README.md": "# Artifact\n",
        "artifact/reproduction.md": "# Reproduction\n",
        "artifact/study_protocol.md": "# Protocol\n",
        "artifact/source_manifest.csv": "resource,commit\n",
    }
    for relative, content in required.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    (root / "artifact" / "verification").mkdir()
    (root / "artifact" / "verification" / "local_reproduction.json").write_text(
        '{"status":"PASS"}\n',
        encoding="utf-8",
    )
    (root / "artifact" / "verification" / "clean_replay.json").write_text(
        '{"status":"PASS"}\n',
        encoding="utf-8",
    )

    passed, errors = audit_repository(root)
    assert passed, errors

    published = {path.relative_to(root).as_posix() for path in iter_publishable_files(root)}
    assert published == set(required)

    with pytest.raises(ValueError, match="outside the audited project tree"):
        create_deterministic_zip(root, root / "artifact" / "RepairWitness.zip")
