"""Deterministic, self-verifying repository release archives.

The archive verifier is intentionally independent from the writer. It validates lexical
paths, Unix file types and modes, deterministic timestamps, bounded expansion, inventory,
member digests, and a digest-bound manifest before extraction.
"""

from __future__ import annotations

import json
import stat
import zipfile
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TypeGuard

from .audit import iter_publishable_files
from .canonical import canonical_json_bytes, sha256_bytes, sha256_file

_FIXED_TIMESTAMP = (2020, 1, 1, 0, 0, 0)
_MANIFEST_NAME = "RELEASE_MANIFEST.json"
_MAX_ARCHIVE_MEMBERS = 100_000
_MAX_MEMBER_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_BYTES = 512 * 1024 * 1024
_MEMBER_FIELDS = frozenset({"path", "sha256", "size", "mode"})
_MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "project",
        "version",
        "root_prefix",
        "member_count",
        "members",
        "subject_sha256",
        "timestamp_policy",
        "permission_policy",
    }
)


class ReleaseArchiveError(ValueError):
    """A release archive violates the deterministic packaging contract."""


def _is_digest(value: object) -> TypeGuard[str]:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _safe_project(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise ReleaseArchiveError("manifest project is invalid")
    if PurePosixPath(value).name != value or value in {".", ".."}:
        raise ReleaseArchiveError("manifest project must be one safe path segment")
    if any(ord(character) < 32 for character in value):
        raise ReleaseArchiveError("manifest project contains control characters")
    return value


def _safe_version(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise ReleaseArchiveError("manifest version is invalid")
    if any(ord(character) < 32 for character in value):
        raise ReleaseArchiveError("manifest version contains control characters")
    return value


@dataclass(frozen=True)
class ReleaseMember:
    path: str
    sha256: str
    size: int
    mode: int

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "mode": f"{self.mode:04o}",
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> ReleaseMember:
        if set(value) != _MEMBER_FIELDS:
            raise ReleaseArchiveError("manifest member fields are incomplete or unknown")
        path = value.get("path")
        digest = value.get("sha256")
        size = value.get("size")
        mode = value.get("mode")
        if not isinstance(path, str) or not path or path == _MANIFEST_NAME:
            raise ReleaseArchiveError("manifest member path must be non-empty")
        _safe_relative(path)
        if not _is_digest(digest):
            raise ReleaseArchiveError("manifest member SHA-256 is invalid")
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or not 0 <= size <= _MAX_MEMBER_BYTES
        ):
            raise ReleaseArchiveError("manifest member size is invalid")
        if not isinstance(mode, str) or mode not in {"0644", "0755"}:
            raise ReleaseArchiveError("manifest member mode is invalid")
        return cls(path=path, sha256=digest, size=size, mode=int(mode, 8))


@dataclass(frozen=True)
class ReleaseManifest:
    project: str
    version: str
    root_prefix: str
    members: tuple[ReleaseMember, ...]
    subject_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "project": self.project,
            "version": self.version,
            "root_prefix": self.root_prefix,
            "member_count": len(self.members),
            "members": [member.to_dict() for member in self.members],
            "subject_sha256": self.subject_sha256,
            "timestamp_policy": "ZIP_DOS_2020-01-01T00:00:00",
            "permission_policy": "0644_FILES_0755_SCRIPTS",
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> ReleaseManifest:
        if set(value) != _MANIFEST_FIELDS:
            raise ReleaseArchiveError("manifest fields are incomplete or unknown")
        if value.get("schema_version") != 1:
            raise ReleaseArchiveError("manifest schema_version is invalid")
        if value.get("timestamp_policy") != "ZIP_DOS_2020-01-01T00:00:00":
            raise ReleaseArchiveError("manifest timestamp policy is invalid")
        if value.get("permission_policy") != "0644_FILES_0755_SCRIPTS":
            raise ReleaseArchiveError("manifest permission policy is invalid")
        rows = value.get("members")
        if not isinstance(rows, list) or not all(isinstance(row, Mapping) for row in rows):
            raise ReleaseArchiveError("manifest members must be a JSON object array")
        members = tuple(ReleaseMember.from_dict(row) for row in rows)
        if value.get("member_count") != len(members):
            raise ReleaseArchiveError("manifest member_count is inconsistent")
        project = _safe_project(value.get("project"))
        version = _safe_version(value.get("version"))
        prefix = value.get("root_prefix")
        if not isinstance(prefix, str) or prefix != f"{project}/":
            raise ReleaseArchiveError("manifest root_prefix is invalid")
        subject = value.get("subject_sha256")
        if not _is_digest(subject):
            raise ReleaseArchiveError("manifest subject_sha256 is invalid")
        paths = tuple(member.path for member in members)
        if paths != tuple(sorted(set(paths))):
            raise ReleaseArchiveError("manifest members are not unique and canonically sorted")
        if sum(member.size for member in members) > _MAX_TOTAL_BYTES:
            raise ReleaseArchiveError("manifest total uncompressed size exceeds the safety limit")
        return cls(project, version, prefix, members, subject)


def _safe_relative(path: str) -> PurePosixPath:
    value = PurePosixPath(path)
    if value.is_absolute() or ".." in value.parts or not value.parts:
        raise ReleaseArchiveError(f"unsafe archive path: {path!r}")
    if any(part in {"", "."} for part in value.parts):
        raise ReleaseArchiveError(f"non-canonical archive path: {path!r}")
    if "\\" in path or path != value.as_posix():
        raise ReleaseArchiveError(f"non-canonical archive path: {path!r}")
    return value


def _subject_digest(members: Iterable[ReleaseMember]) -> str:
    return sha256_bytes(canonical_json_bytes([member.to_dict() for member in members]))


def _mode_for(relative: str) -> int:
    return (
        0o755
        if relative.endswith(".py")
        and (relative.startswith("scripts/") or "/scripts/" in relative)
        else 0o644
    )


def _write_member(
    archive: zipfile.ZipFile,
    name: str,
    content: bytes,
    mode: int,
) -> None:
    info = zipfile.ZipInfo(name, _FIXED_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (stat.S_IFREG | mode) << 16
    info.create_system = 3
    archive.writestr(info, content, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def _contains_symlink(root: Path, relative: Path) -> bool:
    cursor = root
    for part in relative.parts:
        cursor /= part
        if cursor.is_symlink():
            return True
    return False


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _release_rows(root: Path, files: Sequence[Path]) -> list[tuple[ReleaseMember, bytes]]:
    rows: list[tuple[ReleaseMember, bytes]] = []
    for path in files:
        try:
            relative_path = path.relative_to(root)
        except ValueError as exc:
            raise ReleaseArchiveError(f"release member lies outside root: {path}") from exc
        if _contains_symlink(root, relative_path) or not path.is_file():
            raise ReleaseArchiveError(f"release member is not a regular file: {path}")
        relative = relative_path.as_posix()
        _safe_relative(relative)
        if relative == _MANIFEST_NAME:
            continue
        content = path.read_bytes()
        if len(content) > _MAX_MEMBER_BYTES:
            raise ReleaseArchiveError(f"release member exceeds size limit: {relative}")
        rows.append(
            (
                ReleaseMember(relative, sha256_bytes(content), len(content), _mode_for(relative)),
                content,
            )
        )
    rows.sort(key=lambda row: row[0].path)
    paths = [row[0].path for row in rows]
    if len(paths) != len(set(paths)):
        raise ReleaseArchiveError("release file set contains duplicate paths")
    if len(rows) > _MAX_ARCHIVE_MEMBERS:
        raise ReleaseArchiveError("release file count exceeds the safety limit")
    if sum(member.size for member, _content in rows) > _MAX_TOTAL_BYTES:
        raise ReleaseArchiveError("release total size exceeds the safety limit")
    return rows


def create_deterministic_zip(
    root: Path | str,
    output: Path | str,
    *,
    project: str = "RepairWitness",
    version: str = "1.0.0",
    files: Iterable[Path] | None = None,
) -> ReleaseManifest:
    """Create a byte-identical ZIP from a stable, explicitly audited file set."""

    root_path = Path(root).resolve()
    output_path = Path(output).resolve()
    if _is_relative_to(output_path, root_path):
        raise ReleaseArchiveError("release archive output must be outside the audited project tree")
    project = _safe_project(project)
    version = _safe_version(version)
    candidates = iter_publishable_files(root_path) if files is None else files
    selected = tuple(sorted((Path(path).absolute() for path in candidates), key=Path.as_posix))
    rows = _release_rows(root_path, selected)
    members = tuple(member for member, _content in rows)
    manifest = ReleaseManifest(
        project=project,
        version=version,
        root_prefix=f"{project}/",
        members=members,
        subject_sha256=_subject_digest(members),
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_suffix(output_path.suffix + ".tmp")
    try:
        with zipfile.ZipFile(temporary, "w") as archive:
            for member, content in rows:
                _write_member(archive, manifest.root_prefix + member.path, content, member.mode)
            _write_member(
                archive,
                manifest.root_prefix + _MANIFEST_NAME,
                canonical_json_bytes(manifest.to_dict()),
                0o644,
            )
        temporary.replace(output_path)
    finally:
        temporary.unlink(missing_ok=True)
    return manifest


def _decode_manifest(content: bytes) -> ReleaseManifest:
    try:
        value = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseArchiveError("release manifest is not valid UTF-8 JSON") from exc
    if not isinstance(value, Mapping):
        raise ReleaseArchiveError("release manifest root must be an object")
    return ReleaseManifest.from_dict(value)


def _archive_metadata_errors(infos: Sequence[zipfile.ZipInfo]) -> list[str]:
    errors: list[str] = []
    names = [info.filename for info in infos]
    if len(infos) > _MAX_ARCHIVE_MEMBERS:
        errors.append("archive member count exceeds the safety limit")
    if len(names) != len(set(names)):
        errors.append("archive contains duplicate member names")
    if sum(info.file_size for info in infos) > _MAX_TOTAL_BYTES:
        errors.append("archive total uncompressed size exceeds the safety limit")
    for info in infos:
        errors.extend(_member_metadata_errors(info))
    return errors


def _member_metadata_errors(info: zipfile.ZipInfo) -> list[str]:
    errors: list[str] = []
    try:
        _safe_relative(info.filename)
    except ReleaseArchiveError as exc:
        errors.append(str(exc))
    if info.is_dir():
        errors.append(f"archive contains an unexpected directory entry: {info.filename}")
    if info.date_time != _FIXED_TIMESTAMP:
        errors.append(f"member has a non-deterministic timestamp: {info.filename}")
    mode = (info.external_attr >> 16) & 0o7777
    if mode not in {0o644, 0o755}:
        errors.append(f"member has an invalid permission mode: {info.filename}")
    file_type = (info.external_attr >> 16) & 0o170000
    if file_type not in {0, stat.S_IFREG}:
        errors.append(f"member is not a regular file: {info.filename}")
    if info.file_size > _MAX_MEMBER_BYTES:
        errors.append(f"member exceeds the uncompressed size limit: {info.filename}")
    return errors


def _manifest_name(names: Sequence[str]) -> tuple[str | None, list[str]]:
    candidates = [name for name in names if name.endswith("/" + _MANIFEST_NAME)]
    if len(candidates) != 1:
        return None, ["archive must contain exactly one release manifest"]
    return candidates[0], []


def _manifest_inventory_errors(
    names: Sequence[str],
    manifest_name: str,
    manifest: ReleaseManifest,
) -> list[str]:
    errors: list[str] = []
    expected_manifest_name = manifest.root_prefix + _MANIFEST_NAME
    if manifest_name != expected_manifest_name:
        errors.append("release manifest path does not match root_prefix")
    expected_names = {manifest.root_prefix + member.path for member in manifest.members} | {
        expected_manifest_name
    }
    if set(names) != expected_names:
        errors.append("archive member inventory differs from the manifest")
    return errors


def _manifest_member_errors(
    archive: zipfile.ZipFile,
    manifest: ReleaseManifest,
) -> list[str]:
    errors: list[str] = []
    for member in manifest.members:
        archive_name = manifest.root_prefix + member.path
        try:
            info = archive.getinfo(archive_name)
            content = archive.read(info)
        except KeyError:
            continue
        if len(content) != member.size:
            errors.append(f"size mismatch for {member.path}")
        if sha256_bytes(content) != member.sha256:
            errors.append(f"SHA-256 mismatch for {member.path}")
        if ((info.external_attr >> 16) & 0o7777) != member.mode:
            errors.append(f"permission mismatch for {member.path}")
    if _subject_digest(manifest.members) != manifest.subject_sha256:
        errors.append("manifest subject digest does not replay")
    return errors


def _verify_open_archive(
    archive: zipfile.ZipFile,
) -> tuple[list[str], ReleaseManifest | None]:
    infos = archive.infolist()
    names = [info.filename for info in infos]
    errors = _archive_metadata_errors(infos)
    manifest_name, manifest_name_errors = _manifest_name(names)
    errors.extend(manifest_name_errors)
    if manifest_name is None:
        return errors, None
    try:
        manifest = _decode_manifest(archive.read(manifest_name))
    except (KeyError, ReleaseArchiveError) as exc:
        errors.append(f"cannot decode release manifest: {type(exc).__name__}: {exc}")
        return errors, None
    errors.extend(_manifest_inventory_errors(names, manifest_name, manifest))
    if not any("size limit" in error for error in errors):
        errors.extend(_manifest_member_errors(archive, manifest))
    return errors, manifest


def verify_release_zip(path: Path | str) -> tuple[bool, tuple[str, ...], ReleaseManifest | None]:
    """Verify paths, metadata, expansion bounds, member hashes, and self-manifest."""

    errors: list[str] = []
    manifest: ReleaseManifest | None = None
    try:
        with zipfile.ZipFile(path, "r") as archive:
            errors, manifest = _verify_open_archive(archive)
    except (OSError, zipfile.BadZipFile, ReleaseArchiveError) as exc:
        errors.append(f"cannot verify archive: {type(exc).__name__}: {exc}")
    return not errors, tuple(sorted(set(errors))), manifest


def safe_extract_release(path: Path | str, destination: Path | str) -> ReleaseManifest:
    """Verify first, then extract without following links or escaping the destination."""

    passed, errors, manifest = verify_release_zip(path)
    if not passed or manifest is None:
        raise ReleaseArchiveError("release verification failed: " + "; ".join(errors))
    destination_path = Path(destination).resolve()
    destination_path.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "r") as archive:
        for info in archive.infolist():
            relative = _safe_relative(info.filename)
            target = destination_path.joinpath(*relative.parts).resolve()
            if destination_path not in target.parents:
                raise ReleaseArchiveError(f"member escapes extraction root: {info.filename}")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(info))
            target.chmod((info.external_attr >> 16) & 0o777)
    return manifest


def archive_report(path: Path | str) -> dict[str, object]:
    passed, errors, manifest = verify_release_zip(path)
    source = Path(path)
    return {
        "status": "PASS" if passed else "FAIL",
        "archive": source.name,
        "archive_sha256": sha256_file(source),
        "archive_bytes": source.stat().st_size,
        "subject_sha256": None if manifest is None else manifest.subject_sha256,
        "member_count": None if manifest is None else len(manifest.members),
        "errors": list(errors),
    }
