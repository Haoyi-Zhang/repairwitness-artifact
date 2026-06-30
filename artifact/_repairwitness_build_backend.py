"""Minimal in-tree wheel builder for offline artifact installation."""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import importlib.util
import re
import zipfile
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parent
TAG = "py3-none-any"
FIXED_TIMESTAMP = (2020, 1, 1, 0, 0, 0)


def _toml_loads(text: str):
    module_path = ROOT / "action_suites" / "tomlcompat.py"
    spec = importlib.util.spec_from_file_location("_repairwitness_tomlcompat", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load in-tree TOML helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.loads(text)


def _project() -> dict[str, object]:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        data = _toml_loads(handle.read().decode("utf-8"))
    project = data.get("project")
    if not isinstance(project, dict):
        raise ValueError("pyproject.toml lacks a [project] table")
    return project


def _distribution(value: str) -> str:
    return re.sub(r"[-_.]+", "_", value)


def _dist_info_name() -> str:
    project = _project()
    return f"{_distribution(str(project['name']))}-{str(project['version'])}.dist-info"


def _wheel_name() -> str:
    project = _project()
    return f"{_distribution(str(project['name']))}-{str(project['version'])}-{TAG}.whl"


def _metadata() -> bytes:
    project = _project()
    lines = [
        "Metadata-Version: 2.3",
        f"Name: {project['name']}",
        f"Version: {project['version']}",
        f"Summary: {project.get('description', '')}",
        f"Requires-Python: {project['requires-python']}",
        "Description-Content-Type: text/markdown",
        "License-File: LICENSE.txt",
    ]
    dependencies = project.get("dependencies", [])
    if not isinstance(dependencies, list):
        raise ValueError("project.dependencies must be a list")
    lines.extend(f"Requires-Dist: {dependency}" for dependency in dependencies)
    readme = ROOT / str(project.get("readme", "README.md"))
    return ("\n".join(lines) + "\n\n" + readme.read_text(encoding="utf-8")).encode("utf-8")


def _wheel() -> bytes:
    return (
        "Wheel-Version: 1.0\n"
        "Generator: repairwitness-local-build-backend\n"
        "Root-Is-Purelib: true\n"
        f"Tag: {TAG}\n"
    ).encode("utf-8")


def _digest(content: bytes) -> str:
    raw = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).decode("ascii")
    return "sha256=" + raw.rstrip("=")


def _write_member(archive: zipfile.ZipFile, name: str, content: bytes) -> None:
    info = zipfile.ZipInfo(name, FIXED_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    archive.writestr(info, content, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def _package_files() -> Iterable[tuple[str, bytes]]:
    for package in ("action_suites", "repairwitness"):
        for path in sorted((ROOT / package).rglob("*.py")):
            yield path.relative_to(ROOT).as_posix(), path.read_bytes()


def _dist_info_files() -> Iterable[tuple[str, bytes]]:
    dist_info = _dist_info_name()
    yield f"{dist_info}/METADATA", _metadata()
    yield f"{dist_info}/WHEEL", _wheel()
    yield f"{dist_info}/LICENSE.txt", (ROOT / "LICENSE.txt").read_bytes()


def _record(rows: list[tuple[str, bytes]]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    for name, content in rows:
        writer.writerow([name, _digest(content), str(len(content))])
    writer.writerow([f"{_dist_info_name()}/RECORD", "", ""])
    return stream.getvalue().encode("utf-8")


def get_requires_for_build_wheel(config_settings: object | None = None) -> list[str]:
    return []


def prepare_metadata_for_build_wheel(
    metadata_directory: str,
    config_settings: object | None = None,
) -> str:
    dist_info = _dist_info_name()
    target = Path(metadata_directory) / dist_info
    target.mkdir(parents=True, exist_ok=True)
    (target / "METADATA").write_bytes(_metadata())
    (target / "WHEEL").write_bytes(_wheel())
    (target / "LICENSE.txt").write_bytes((ROOT / "LICENSE.txt").read_bytes())
    (target / "RECORD").write_text("", encoding="utf-8")
    return dist_info


def build_wheel(
    wheel_directory: str,
    config_settings: object | None = None,
    metadata_directory: str | None = None,
) -> str:
    wheel_name = _wheel_name()
    output = Path(wheel_directory) / wheel_name
    rows = sorted([*_package_files(), *_dist_info_files()], key=lambda row: row[0])
    rows.append((f"{_dist_info_name()}/RECORD", _record(rows)))
    with zipfile.ZipFile(output, "w") as archive:
        for name, content in rows:
            _write_member(archive, name, content)
    return wheel_name
