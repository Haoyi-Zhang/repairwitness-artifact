from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

import pytest

from repairwitness.package import (
    ReleaseArchiveError,
    create_deterministic_zip,
    safe_extract_release,
    verify_release_zip,
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_deterministic_release_archive(tmp_path: Path) -> None:
    root = tmp_path / "root"
    (root / "artifact").mkdir(parents=True)
    (root / "paper").mkdir()
    (root / "artifact" / "verification").mkdir()
    (root / "artifact" / "README.md").write_text("artifact\n", encoding="utf-8")
    (root / "artifact" / "verification" / "local_reproduction.json").write_text(
        '{"status":"PASS"}\n',
        encoding="utf-8",
    )
    (root / "artifact" / "verification" / "clean_replay.json").write_text(
        '{"status":"PASS"}\n',
        encoding="utf-8",
    )
    (root / "paper" / "main.tex").write_text("paper\n", encoding="utf-8")
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"
    create_deterministic_zip(root, first, version="test")
    create_deterministic_zip(root, second, version="test")
    assert digest(first) == digest(second)
    valid, errors, manifest = verify_release_zip(first)
    assert valid, errors
    assert manifest is not None
    member_paths = {member.path for member in manifest.members}
    assert "artifact/verification/local_reproduction.json" not in member_paths
    assert "artifact/verification/clean_replay.json" not in member_paths
    with zipfile.ZipFile(first) as archive:
        archive_names = set(archive.namelist())
    assert "RepairWitness/artifact/verification/local_reproduction.json" not in archive_names
    assert "RepairWitness/artifact/verification/clean_replay.json" not in archive_names
    destination = tmp_path / "extract"
    safe_extract_release(first, destination)
    assert (destination / "RepairWitness" / "paper" / "main.tex").read_text() == "paper\n"

    with pytest.raises(ReleaseArchiveError, match="outside the audited project tree"):
        create_deterministic_zip(root, root / "artifact" / "nested.zip", version="test")
