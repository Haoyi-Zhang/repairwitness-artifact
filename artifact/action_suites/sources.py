from __future__ import annotations

import csv
import fnmatch
import io
import json
import shutil
import tarfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Mapping, Sequence

import yaml

from .canonical import (
    atomic_write_bytes,
    atomic_write_json,
    length_prefixed_path_content_digest,
    sha256_file,
)
from .tomlcompat import TomlCompatError, loads as toml_loads


@dataclass(frozen=True)
class SourceSpec:
    source_id: str
    url: str
    source_type: str
    commit: str
    license: str
    role: str

    @property
    def owner_repo(self) -> str:
        prefix = "https://github.com/"
        if not self.url.startswith(prefix):
            raise ValueError(f"unsupported source URL: {self.url}")
        return self.url.removeprefix(prefix).strip("/")

    @property
    def archive_url(self) -> str:
        return f"https://github.com/{self.owner_repo}/archive/{self.commit}.tar.gz"


@dataclass(frozen=True)
class ProjectionRule:
    source_id: str
    include_globs: tuple[str, ...]
    adapter_supported_globs: tuple[str, ...]
    unsupported_reason_by_glob: tuple[tuple[str, str], ...] = ()

    def includes(self, path: str) -> bool:
        return any(fnmatch.fnmatchcase(path, pattern) for pattern in self.include_globs)

    def adapter_supported(self, path: str) -> bool:
        return any(
            fnmatch.fnmatchcase(path, pattern)
            for pattern in self.adapter_supported_globs
        )

    def unsupported_reason(self, path: str) -> str | None:
        for pattern, reason in self.unsupported_reason_by_glob:
            if fnmatch.fnmatchcase(path, pattern):
                return reason
        return None


LOCKED_PROJECTION_RULES: Mapping[str, ProjectionRule] = {
    "C-GHAD": ProjectionRule(
        source_id="C-GHAD",
        include_globs=("advisories/github-reviewed/**/*.json",),
        adapter_supported_globs=("advisories/github-reviewed/**/*.json",),
    ),
    "C-PYPA": ProjectionRule(
        source_id="C-PYPA",
        include_globs=("vulns/**/*.yaml", "vulns/**/*.yml"),
        adapter_supported_globs=("vulns/**/*.yaml", "vulns/**/*.yml"),
    ),
    "C-GOVULNDB": ProjectionRule(
        source_id="C-GOVULNDB",
        include_globs=("data/osv/*.json", "data/osv/**/*.json", "data/reports/*.yaml", "data/reports/**/*.yaml"),
        adapter_supported_globs=("data/osv/*.json", "data/osv/**/*.json"),
        unsupported_reason_by_glob=(
            ("data/reports/*.yaml", "GO_NATIVE_REPORT_NO_FROZEN_PRIMARY_ADAPTER"),
            ("data/reports/**/*.yaml", "GO_NATIVE_REPORT_NO_FROZEN_PRIMARY_ADAPTER"),
        ),
    ),
    "C-RUSTSEC": ProjectionRule(
        source_id="C-RUSTSEC",
        include_globs=("crates/**/*.md",),
        adapter_supported_globs=("crates/**/*.md",),
    ),
    "C-RUBYSEC": ProjectionRule(
        source_id="C-RUBYSEC",
        include_globs=("gems/**/*.yml", "gems/**/*.yaml"),
        adapter_supported_globs=("gems/**/*.yml", "gems/**/*.yaml"),
    ),
}


def load_source_manifest(path: Path | str) -> tuple[SourceSpec, ...]:
    rows: list[SourceSpec] = []
    with Path(path).open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            rows.append(
                SourceSpec(
                    source_id=row["source_id"],
                    url=row["url"],
                    source_type=row["source_type"],
                    commit=row["version_or_commit"],
                    license=row["license"],
                    role=row["role"],
                )
            )
    if set(LOCKED_PROJECTION_RULES) != {row.source_id for row in rows}:
        raise ValueError("source manifest does not match the locked source set")
    for row in rows:
        if len(row.commit) != 40 or any(ch not in "0123456789abcdef" for ch in row.commit):
            raise ValueError(f"source {row.source_id} is not pinned to a full commit")
    return tuple(sorted(rows, key=lambda row: row.source_id))


def download_archive(spec: SourceSpec, destination: Path | str) -> dict[str, object]:
    destination_path = Path(destination)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination_path.with_suffix(destination_path.suffix + ".partial")
    request = urllib.request.Request(
        spec.archive_url,
        headers={"User-Agent": "action-separating-suites-reproducer/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response, temporary.open(
            "wb"
        ) as output:
            shutil.copyfileobj(response, output, length=1024 * 1024)
        temporary.replace(destination_path)
    finally:
        temporary.unlink(missing_ok=True)
    return {
        "source_id": spec.source_id,
        "commit": spec.commit,
        "archive_sha256": sha256_file(destination_path),
        "archive_bytes": destination_path.stat().st_size,
    }


def _safe_member_name(name: str) -> str:
    normalized = Path(name)
    if normalized.is_absolute() or ".." in normalized.parts:
        raise ValueError(f"unsafe archive member path: {name}")
    parts = normalized.parts
    if len(parts) < 2:
        raise ValueError(f"archive member lacks a repository root: {name}")
    return Path(*parts[1:]).as_posix()


def iter_projected_archive_members(
    archive_path: Path | str,
    rule: ProjectionRule,
) -> Iterator[tuple[str, bytes, bool, str | None]]:
    with tarfile.open(archive_path, mode="r:gz") as archive:
        for member in sorted(archive.getmembers(), key=lambda value: value.name):
            if not member.isfile():
                continue
            relative = _safe_member_name(member.name)
            if not rule.includes(relative):
                continue
            extracted = archive.extractfile(member)
            if extracted is None:
                raise ValueError(f"could not read archive member: {member.name}")
            content = extracted.read()
            supported = rule.adapter_supported(relative)
            reason = None if supported else rule.unsupported_reason(relative)
            if not supported and reason is None:
                raise ValueError(f"projected unsupported path lacks reason: {relative}")
            yield relative, content, supported, reason


def syntax_decodable(path: str, content: bytes) -> bool:
    try:
        if path.endswith(".json"):
            json.loads(content.decode("utf-8"))
        elif path.endswith((".yaml", ".yml")):
            yaml.safe_load(content.decode("utf-8"))
        elif path.endswith(".md"):
            text = content.decode("utf-8")
            if not text.startswith("```toml\n"):
                raise ValueError("RustSec advisory lacks TOML front matter")
            closing = text.find("\n```", len("```toml\n"))
            if closing < 0:
                raise ValueError("RustSec advisory lacks closing front-matter fence")
            toml_loads(text[len("```toml\n"):closing])
        else:
            return False
    except (UnicodeDecodeError, json.JSONDecodeError, yaml.YAMLError, TomlCompatError, ValueError):
        return False
    return True


def build_projection_ledger(
    source_specs: Sequence[SourceSpec],
    archive_dir: Path | str,
    output_dir: Path | str,
    *,
    persist_projection: bool = True,
) -> dict[str, object]:
    archive_root = Path(archive_dir)
    output_root = Path(output_dir)
    output_root.mkdir(parents=True, exist_ok=True)
    source_rows: list[dict[str, object]] = []
    aggregate_entries: list[tuple[str, bytes]] = []
    exclusions: list[dict[str, object]] = []
    syntax_failures: list[dict[str, object]] = []

    for spec in source_specs:
        rule = LOCKED_PROJECTION_RULES[spec.source_id]
        archive_path = archive_root / f"{spec.source_id}.tar.gz"
        projected: list[tuple[str, bytes]] = []
        syntax_count = 0
        supported_count = 0
        for relative, content, supported, reason in iter_projected_archive_members(
            archive_path, rule
        ):
            canonical_path = f"{spec.source_id}/{relative}"
            projected.append((canonical_path, content))
            aggregate_entries.append((canonical_path, content))
            syntax_ok = syntax_decodable(relative, content)
            if syntax_ok:
                syntax_count += 1
                if supported:
                    supported_count += 1
                else:
                    exclusions.append(
                        {
                            "source_id": spec.source_id,
                            "path": relative,
                            "from_stage": "syntax_decoded_members",
                            "to_stage": "frozen_adapter_supported_members",
                            "reason_code": reason,
                            "outcome_blind": True,
                        }
                    )
            else:
                syntax_failures.append(
                    {
                        "source_id": spec.source_id,
                        "path": relative,
                        "reason_code": "SYNTAX_DECODE_FAILED",
                        "outcome_blind": True,
                    }
                )
            if persist_projection:
                atomic_write_bytes(output_root / "projection" / canonical_path, content)
        source_rows.append(
            {
                "source_id": spec.source_id,
                "commit": spec.commit,
                "archive_sha256": sha256_file(archive_path),
                "projected_members": len(projected),
                "syntax_decoded_members": syntax_count,
                "frozen_adapter_supported_members": supported_count,
                "projection_sha256": length_prefixed_path_content_digest(projected),
            }
        )

    ledger = {
        "schema_version": 1,
        "digest_scheme": "sha256(length64(path)||path||length64(content)||content), sorted by path",
        "sources": source_rows,
        "aggregate": {
            "projected_members": len(aggregate_entries),
            "syntax_decoded_members": sum(int(row["syntax_decoded_members"]) for row in source_rows),
            "frozen_adapter_supported_members": sum(int(row["frozen_adapter_supported_members"]) for row in source_rows),
            "projection_sha256": length_prefixed_path_content_digest(aggregate_entries),
        },
    }
    atomic_write_json(output_root / "resource_ledger.json", ledger)
    atomic_write_json(output_root / "preclaim_exclusions.json", exclusions)
    atomic_write_json(output_root / "syntax_failures.json", syntax_failures)
    return ledger


def decode_member(path: str, content: bytes) -> object:
    if path.endswith(".json"):
        return json.loads(content.decode("utf-8"))
    if path.endswith((".yaml", ".yml")):
        return yaml.safe_load(io.StringIO(content.decode("utf-8")))
    raise ValueError(f"no generic decoder for {path}")
