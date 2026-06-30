from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

import yaml

from .canonical import canonical_json_bytes, sha256_bytes
from .tomlcompat import loads as toml_loads


@dataclass(frozen=True)
class StructuralClaim:
    claim_id: str
    source_id: str
    record_id: str
    package_ecosystem: str
    package_name: str
    aliases: tuple[str, ...]
    withdrawn: bool
    ranges: tuple[Mapping[str, Any], ...]
    versions: tuple[str, ...]
    advisory_targets: tuple[str, ...]
    alternative_actions: tuple[str, ...]
    source_path: str

    @property
    def package_key(self) -> str:
        return f"{self.package_ecosystem.lower()}::{self.package_name.lower()}"

    def to_dict(self) -> dict[str, object]:
        return {
            "claim_id": self.claim_id,
            "source_id": self.source_id,
            "record_id": self.record_id,
            "package_ecosystem": self.package_ecosystem,
            "package_name": self.package_name,
            "package_key": self.package_key,
            "aliases": list(self.aliases),
            "withdrawn": self.withdrawn,
            "ranges": list(self.ranges),
            "versions": list(self.versions),
            "advisory_targets": list(self.advisory_targets),
            "alternative_actions": list(self.alternative_actions),
            "source_path": self.source_path,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "StructuralClaim":
        return cls(
            claim_id=str(value["claim_id"]),
            source_id=str(value["source_id"]),
            record_id=str(value["record_id"]),
            package_ecosystem=str(value["package_ecosystem"]),
            package_name=str(value["package_name"]),
            aliases=tuple(str(item) for item in value.get("aliases", [])),
            withdrawn=bool(value.get("withdrawn", False)),
            ranges=tuple(row for row in value.get("ranges", []) if isinstance(row, Mapping)),
            versions=tuple(str(item) for item in value.get("versions", [])),
            advisory_targets=tuple(str(item) for item in value.get("advisory_targets", [])),
            alternative_actions=tuple(str(item) for item in value.get("alternative_actions", [])),
            source_path=str(value["source_path"]),
        )


_ECOSYSTEM_ALIASES = {
    "pip": "PyPI",
    "pypi": "PyPI",
    "rubygems": "RubyGems",
    "cargo": "crates.io",
    "crates.io": "crates.io",
    "go": "Go",
}


def _text(value: Any) -> str:
    if isinstance(value, (dt.date, dt.datetime)):
        return value.isoformat()
    return str(value)


def _normalize_ids(values: Iterable[Any]) -> tuple[str, ...]:
    result = {
        _text(value).strip().upper()
        for value in values
        if value is not None and _text(value).strip()
    }
    return tuple(sorted(result))


def _normalize_ecosystem(value: Any) -> str:
    raw = _text(value).strip()
    return _ECOSYSTEM_ALIASES.get(raw.lower(), raw)


def _extract_fixed_targets(ranges: Sequence[Mapping[str, Any]]) -> tuple[str, ...]:
    targets: set[str] = set()
    for range_row in ranges:
        for event in range_row.get("events", []) or []:
            if isinstance(event, Mapping) and event.get("fixed") is not None:
                targets.add(_text(event["fixed"]).strip())
    return tuple(sorted(item for item in targets if item))


def _claim_id(payload: Mapping[str, object]) -> str:
    return "claim-" + sha256_bytes(canonical_json_bytes(payload))[:24]


def parse_osv_record(
    source_id: str,
    source_path: str,
    record: Mapping[str, Any],
) -> tuple[StructuralClaim, ...]:
    record_id = _text(record.get("id", "")).strip()
    if not record_id:
        raise ValueError("OSV record lacks an id")
    aliases = _normalize_ids([record_id, *(record.get("aliases") or [])])
    withdrawn = record.get("withdrawn") is not None
    claims: list[StructuralClaim] = []
    for index, affected in enumerate(record.get("affected") or []):
        if not isinstance(affected, Mapping):
            continue
        package = affected.get("package") or {}
        if not isinstance(package, Mapping):
            continue
        ecosystem = _normalize_ecosystem(package.get("ecosystem", ""))
        package_name = _text(package.get("name", "")).strip()
        if not ecosystem or not package_name:
            continue
        ranges_raw = affected.get("ranges") or []
        ranges = tuple(row for row in ranges_raw if isinstance(row, Mapping))
        versions = tuple(sorted({_text(item).strip() for item in affected.get("versions") or [] if _text(item).strip()}))
        targets = _extract_fixed_targets(ranges)
        identity_payload = {
            "source_id": source_id,
            "source_path": source_path,
            "record_id": record_id,
            "affected_index": index,
            "ecosystem": ecosystem,
            "package_name": package_name,
        }
        claims.append(
            StructuralClaim(
                claim_id=_claim_id(identity_payload),
                source_id=source_id,
                record_id=record_id,
                package_ecosystem=ecosystem,
                package_name=package_name,
                aliases=aliases,
                withdrawn=withdrawn,
                ranges=ranges,
                versions=versions,
                advisory_targets=targets,
                alternative_actions=(),
                source_path=source_path,
            )
        )
    return tuple(claims)


def parse_rustsec_markdown(
    source_id: str,
    source_path: str,
    content: bytes,
) -> tuple[StructuralClaim, ...]:
    text = content.decode("utf-8")
    match = re.match(r"\A```toml\n(.*?)\n```", text, flags=re.DOTALL)
    if not match:
        raise ValueError("RustSec record lacks TOML front matter")
    metadata = toml_loads(match.group(1))
    advisory = metadata.get("advisory") or {}
    versions = metadata.get("versions") or {}
    record_id = _text(advisory.get("id", "")).strip()
    package_name = _text(advisory.get("package", "")).strip()
    if not record_id or not package_name:
        raise ValueError("RustSec record lacks advisory id or package name")
    aliases = _normalize_ids(
        [
            record_id,
            *(advisory.get("aliases") or []),
            advisory.get("cve"),
        ]
    )
    patched = tuple(sorted({_text(item).strip() for item in versions.get("patched") or [] if _text(item).strip()}))
    unaffected = tuple(sorted({_text(item).strip() for item in versions.get("unaffected") or [] if _text(item).strip()}))
    pseudo_ranges: tuple[Mapping[str, Any], ...] = (
        {
            "type": "RUSTSEC_REQUIREMENT_SETS",
            "patched": list(patched),
            "unaffected": list(unaffected),
        },
    )
    claim = StructuralClaim(
        claim_id=_claim_id(
            {
                "source_id": source_id,
                "source_path": source_path,
                "record_id": record_id,
                "package_name": package_name,
            }
        ),
        source_id=source_id,
        record_id=record_id,
        package_ecosystem="crates.io",
        package_name=package_name,
        aliases=aliases,
        withdrawn=bool(advisory.get("withdrawn")),
        ranges=pseudo_ranges,
        versions=(),
        advisory_targets=patched,
        alternative_actions=(),
        source_path=source_path,
    )
    return (claim,)


def parse_ruby_advisory(
    source_id: str,
    source_path: str,
    content: bytes,
) -> tuple[StructuralClaim, ...]:
    record = yaml.safe_load(content.decode("utf-8"))
    if not isinstance(record, Mapping):
        raise ValueError("Ruby advisory is not a mapping")
    package_name = _text(record.get("gem", "")).strip()
    if not package_name:
        raise ValueError("Ruby advisory lacks gem")
    ids = [record.get("cve"), record.get("ghsa"), record.get("osvdb")]
    aliases = _normalize_ids(ids)
    record_id = aliases[0] if aliases else PathLikeStem(source_path)
    patched = tuple(sorted({_text(item).strip() for item in record.get("patched_versions") or [] if _text(item).strip()}))
    unaffected = tuple(sorted({_text(item).strip() for item in record.get("unaffected_versions") or [] if _text(item).strip()}))
    ranges: tuple[Mapping[str, Any], ...] = (
        {
            "type": "RUBYGEMS_REQUIREMENT_SETS",
            "patched": list(patched),
            "unaffected": list(unaffected),
            "vulnerable": [
                _text(item).strip()
                for item in record.get("vulnerable_versions") or []
                if _text(item).strip()
            ],
        },
    )
    claim = StructuralClaim(
        claim_id=_claim_id(
            {
                "source_id": source_id,
                "source_path": source_path,
                "record_id": record_id,
                "package_name": package_name,
            }
        ),
        source_id=source_id,
        record_id=record_id,
        package_ecosystem="RubyGems",
        package_name=package_name,
        aliases=aliases,
        withdrawn=bool(record.get("withdrawn")),
        ranges=ranges,
        versions=(),
        advisory_targets=patched,
        alternative_actions=(),
        source_path=source_path,
    )
    return (claim,)


def PathLikeStem(path: str) -> str:
    filename = path.rsplit("/", 1)[-1]
    return filename.rsplit(".", 1)[0].upper()


def parse_supported_member(
    source_id: str,
    source_path: str,
    content: bytes,
) -> tuple[StructuralClaim, ...]:
    if source_id in {"C-GHAD", "C-GOVULNDB"} and source_path.endswith(".json"):
        import json

        record = json.loads(content.decode("utf-8"))
        if not isinstance(record, Mapping):
            raise ValueError("OSV record is not a mapping")
        return parse_osv_record(source_id, source_path, record)
    if source_id == "C-PYPA":
        record = yaml.safe_load(content.decode("utf-8"))
        if not isinstance(record, Mapping):
            raise ValueError("PyPA record is not a mapping")
        return parse_osv_record(source_id, source_path, record)
    if source_id == "C-RUSTSEC":
        return parse_rustsec_markdown(source_id, source_path, content)
    if source_id == "C-RUBYSEC":
        return parse_ruby_advisory(source_id, source_path, content)
    raise ValueError(f"no frozen adapter for {source_id}:{source_path}")
