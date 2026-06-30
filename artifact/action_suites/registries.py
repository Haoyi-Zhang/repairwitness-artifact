from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from .canonical import atomic_write_bytes, canonical_json_bytes, sha256_bytes, sha256_file


class RegistryError(RuntimeError):
    pass


@dataclass(frozen=True)
class RegistryResponse:
    ecosystem: str
    package_name: str
    status: str
    releases: tuple[str, ...]
    source_url: str
    response_sha256: str | None
    error_code: str | None = None
    detail: str | None = None

    def __post_init__(self) -> None:
        if self.status not in {"SUCCESS", "EMPTY", "FAILED"}:
            raise ValueError(f"invalid terminal status: {self.status}")
        if self.status == "SUCCESS" and not self.releases:
            raise ValueError("SUCCESS requires at least one release")
        if self.status != "SUCCESS" and self.releases:
            raise ValueError("EMPTY/FAILED cannot carry releases")
        if self.status == "FAILED" and not self.error_code:
            raise ValueError("FAILED requires an error code")

    @property
    def package_key(self) -> str:
        return f"{self.ecosystem.lower()}::{self.package_name.lower()}"

    def to_manifest_row(self) -> dict[str, object]:
        return {
            "package_key": self.package_key,
            "ecosystem": self.ecosystem,
            "package_name": self.package_name,
            "status": self.status,
            "release_count": len(self.releases),
            "response_sha256": self.response_sha256 or "",
            "error_code": self.error_code or "",
            "detail": self.detail or "",
            "source_url": self.source_url,
        }

    def to_universe_row(self) -> dict[str, object]:
        return {
            "package_key": self.package_key,
            "ecosystem": self.ecosystem,
            "package_name": self.package_name,
            "status": self.status,
            "releases": list(self.releases),
            "source_url": self.source_url,
            "response_sha256": self.response_sha256,
            "error_code": self.error_code,
            "detail": self.detail,
        }


def _request_bytes(url: str, *, timeout: int = 90, attempts: int = 3) -> bytes:
    last_error: Exception | None = None
    for attempt in range(attempts):
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json, text/plain;q=0.9, */*;q=0.1",
                "User-Agent": "action-separating-suites-reproducer/1",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read()
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = exc
            if attempt + 1 < attempts:
                time.sleep(0.5 * (2**attempt))
    raise RegistryError(f"request failed after {attempts} attempts: {last_error}")


def _json(url: str) -> tuple[Any, bytes]:
    content = _request_bytes(url)
    return json.loads(content.decode("utf-8")), content


def _sorted_unique(values: Iterable[object]) -> tuple[str, ...]:
    normalized: set[str] = set()
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            normalized.add(text)
    return tuple(sorted(normalized))


def _quoted_package(package: str, *, safe: str = "") -> str:
    return urllib.parse.quote(package, safe=safe)


def _pypi(package: str) -> tuple[str, tuple[str, ...], bytes]:
    url = f"https://pypi.org/pypi/{_quoted_package(package)}/json"
    payload, content = _json(url)
    releases = _sorted_unique((payload.get("releases") or {}).keys())
    return url, releases, content


def _npm(package: str) -> tuple[str, tuple[str, ...], bytes]:
    url = f"https://registry.npmjs.org/{_quoted_package(package, safe='@')}"
    payload, content = _json(url)
    releases = _sorted_unique((payload.get("versions") or {}).keys())
    return url, releases, content


def _rubygems(package: str) -> tuple[str, tuple[str, ...], bytes]:
    url = f"https://rubygems.org/api/v1/versions/{_quoted_package(package)}.json"
    payload, content = _json(url)
    releases = _sorted_unique(row.get("number") for row in payload if isinstance(row, Mapping))
    return url, releases, content


def _crates(package: str) -> tuple[str, tuple[str, ...], bytes]:
    base = f"https://crates.io/api/v1/crates/{_quoted_package(package)}"
    releases: list[str] = []
    page = 1
    pages: list[bytes] = []
    while True:
        url = f"{base}/versions?page={page}&per_page=100"
        payload, content = _json(url)
        pages.append(content)
        rows = payload.get("versions") or []
        releases.extend(str(row.get("num", "")) for row in rows if isinstance(row, Mapping))
        if len(rows) < 100:
            break
        page += 1
        if page > 1000:
            raise RegistryError("crates.io pagination exceeded safety bound")
    canonical_pages = canonical_json_bytes([sha256_bytes(page) for page in pages])
    return base + "/versions", _sorted_unique(releases), canonical_pages


def _go_escape_path(module: str) -> str:
    # Go proxy escaping: uppercase ASCII is encoded as ! followed by lowercase.
    output: list[str] = []
    for character in module:
        if "A" <= character <= "Z":
            output.extend(("!", character.lower()))
        else:
            output.append(character)
    return urllib.parse.quote("".join(output), safe="/!$&'()*+,;=:@-._~")


def _go(package: str) -> tuple[str, tuple[str, ...], bytes]:
    url = f"https://proxy.golang.org/{_go_escape_path(package)}/@v/list"
    content = _request_bytes(url)
    releases = _sorted_unique(content.decode("utf-8").splitlines())
    return url, releases, content


def _packagist(package: str) -> tuple[str, tuple[str, ...], bytes]:
    url = f"https://repo.packagist.org/p2/{_quoted_package(package, safe='/')}.json"
    payload, content = _json(url)
    packages = payload.get("packages") or {}
    rows = packages.get(package) or packages.get(package.lower()) or []
    releases = _sorted_unique(row.get("version_normalized") or row.get("version") for row in rows if isinstance(row, Mapping))
    return url, releases, content


def _nuget(package: str) -> tuple[str, tuple[str, ...], bytes]:
    url = f"https://api.nuget.org/v3/registration5-semver1/{_quoted_package(package.lower())}/index.json"
    payload, content = _json(url)
    releases: list[str] = []
    for page in payload.get("items") or []:
        if not isinstance(page, Mapping):
            continue
        page_items = page.get("items")
        if page_items is None and page.get("@id"):
            page_payload, page_content = _json(str(page["@id"]))
            page_items = page_payload.get("items") or []
            content += b"\n" + page_content
        for item in page_items or []:
            if not isinstance(item, Mapping):
                continue
            entry = item.get("catalogEntry") or {}
            if isinstance(entry, Mapping) and entry.get("version") is not None:
                releases.append(str(entry["version"]))
    return url, _sorted_unique(releases), content


def _maven(package: str) -> tuple[str, tuple[str, ...], bytes]:
    if ":" not in package:
        raise RegistryError("Maven package name must be group:artifact")
    group, artifact = package.split(":", 1)
    query = urllib.parse.quote(f'g:"{group}" AND a:"{artifact}"')
    base = f"https://search.maven.org/solrsearch/select?q={query}&core=gav&rows=200&wt=json"
    releases: list[str] = []
    start = 0
    pages: list[bytes] = []
    total = 1
    while start < total:
        url = f"{base}&start={start}"
        payload, content = _json(url)
        pages.append(content)
        response = payload.get("response") or {}
        docs = response.get("docs") or []
        total = int(response.get("numFound", 0))
        releases.extend(str(row.get("v", "")) for row in docs if isinstance(row, Mapping))
        start += len(docs)
        if not docs:
            break
        if start > 1_000_000:
            raise RegistryError("Maven pagination exceeded safety bound")
    canonical_pages = canonical_json_bytes([sha256_bytes(page) for page in pages])
    return base, _sorted_unique(releases), canonical_pages


def _hex(package: str) -> tuple[str, tuple[str, ...], bytes]:
    url = f"https://hex.pm/api/packages/{_quoted_package(package)}"
    payload, content = _json(url)
    releases = _sorted_unique(row.get("version") for row in payload.get("releases") or [] if isinstance(row, Mapping))
    return url, releases, content


_FETCHERS: dict[str, Callable[[str], tuple[str, tuple[str, ...], bytes]]] = {
    "pypi": _pypi,
    "npm": _npm,
    "rubygems": _rubygems,
    "crates.io": _crates,
    "go": _go,
    "packagist": _packagist,
    "nuget": _nuget,
    "maven": _maven,
    "hex": _hex,
}


def supported_registry_ecosystems() -> tuple[str, ...]:
    return tuple(sorted(_FETCHERS))


def fetch_release_universe(
    ecosystem: str,
    package_name: str,
    *,
    response_dir: Path | str | None = None,
) -> RegistryResponse:
    normalized = ecosystem.strip().lower()
    fetcher = _FETCHERS.get(normalized)
    fallback_url = ""
    if fetcher is None:
        return RegistryResponse(
            ecosystem=ecosystem,
            package_name=package_name,
            status="FAILED",
            releases=(),
            source_url=fallback_url,
            response_sha256=None,
            error_code="UNSUPPORTED_REGISTRY_ECOSYSTEM",
            detail=f"no frozen registry adapter for {ecosystem}",
        )
    try:
        url, releases, content = fetcher(package_name)
        digest = sha256_bytes(content)
        if response_dir is not None:
            destination = Path(response_dir) / normalized / f"{sha256_bytes(package_name.encode('utf-8'))}.response"
            atomic_write_bytes(destination, content)
            if sha256_file(destination) != digest:
                raise RegistryError("persisted response digest mismatch")
        if not releases:
            return RegistryResponse(
                ecosystem=ecosystem,
                package_name=package_name,
                status="EMPTY",
                releases=(),
                source_url=url,
                response_sha256=digest,
                error_code=None,
                detail="registry response contained no releases",
            )
        return RegistryResponse(
            ecosystem=ecosystem,
            package_name=package_name,
            status="SUCCESS",
            releases=releases,
            source_url=url,
            response_sha256=digest,
        )
    except Exception as exc:  # package failures remain visible as terminal rows
        return RegistryResponse(
            ecosystem=ecosystem,
            package_name=package_name,
            status="FAILED",
            releases=(),
            source_url=fallback_url,
            response_sha256=None,
            error_code=type(exc).__name__.upper(),
            detail=str(exc)[:500],
        )
