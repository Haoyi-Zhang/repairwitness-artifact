from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest

from action_suites import registries
from action_suites.registries import RegistryResponse, fetch_release_universe, supported_registry_ecosystems
from action_suites.sources import SourceSpec
from action_suites.structural_pipeline import build_structural_frame


def _write_tar(path: Path, members: dict[str, bytes]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, content in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))


def test_registry_fetchers_parse_native_release_shapes(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_json(url: str):
        if "pypi.org" in url:
            return {"releases": {"1.0": {}, "2.0": {}, "": {}}}, b"pypi"
        if "registry.npmjs.org" in url:
            return {"versions": {"0.9.0": {}, "1.0.0": {}}}, b"npm"
        if "rubygems.org" in url:
            return [{"number": "3.0.0"}, {"number": ""}, {}], b"ruby"
        if "crates.io" in url and "page=1&" in url:
            return {"versions": [{"num": f"1.0.{idx}"} for idx in range(100)]}, b"crates1"
        if "crates.io" in url and "page=2&" in url:
            return {"versions": [{"num": "2.0.0"}]}, b"crates2"
        if "packagist" in url:
            return {
                "packages": {
                    "vendor/pkg": [
                        {"version_normalized": "1.0.0.0"},
                        {"version": "2.0.0"},
                    ]
                }
            }, b"packagist"
        if "registration5-semver1" in url:
            return {"items": [{"@id": "https://unit.test/nuget-page"}]}, b"nuget-index"
        if "nuget-page" in url:
            return {"items": [{"catalogEntry": {"version": "4.0.0"}}]}, b"nuget-page"
        if "search.maven.org" in url:
            return {"response": {"numFound": 2, "docs": [{"v": "1.0"}, {"v": "1.1"}]}}, b"maven"
        if "hex.pm" in url:
            return {"releases": [{"version": "0.1.0"}, {}]}, b"hex"
        raise AssertionError(url)

    monkeypatch.setattr(registries, "_json", fake_json)
    monkeypatch.setattr(registries, "_request_bytes", lambda url: b"v1\nv2\n" if "golang" in url else b"")

    assert registries._pypi("demo")[1] == ("1.0", "2.0")
    assert registries._npm("@scope/demo")[1] == ("0.9.0", "1.0.0")
    assert registries._rubygems("demo")[1] == ("3.0.0",)
    assert registries._crates("demo")[1][0] == "1.0.0"
    assert registries._crates("demo")[1][-1] == "2.0.0"
    assert registries._go("Example.com/Mod")[1] == ("v1", "v2")
    assert registries._packagist("vendor/pkg")[1] == ("1.0.0.0", "2.0.0")
    assert registries._nuget("Demo.Package")[1] == ("4.0.0",)
    assert registries._maven("g:a")[1] == ("1.0", "1.1")
    assert registries._hex("demo")[1] == ("0.1.0",)
    with pytest.raises(registries.RegistryError):
        registries._maven("missing-artifact-separator")


def test_fetch_release_universe_terminal_rows_and_persistence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setitem(
        registries._FETCHERS,
        "unit-success",
        lambda package: ("https://registry.invalid/success", ("1.0", "1.1"), b"success"),
    )
    monkeypatch.setitem(
        registries._FETCHERS,
        "unit-empty",
        lambda package: ("https://registry.invalid/empty", (), b"empty"),
    )

    def failing_fetcher(package: str):
        raise registries.RegistryError("boom")

    monkeypatch.setitem(registries._FETCHERS, "unit-fail", failing_fetcher)

    success = fetch_release_universe("Unit-Success", "Demo", response_dir=tmp_path / "responses")
    assert success.status == "SUCCESS"
    assert success.package_key == "unit-success::demo"
    assert success.to_manifest_row()["release_count"] == 2
    assert list((tmp_path / "responses" / "unit-success").glob("*.response"))

    empty = fetch_release_universe("unit-empty", "Demo")
    assert empty.status == "EMPTY"
    assert empty.to_universe_row()["releases"] == []

    failed = fetch_release_universe("unit-fail", "Demo")
    assert failed.status == "FAILED"
    assert failed.error_code == "REGISTRYERROR"

    unsupported = fetch_release_universe("unknown-eco", "Demo")
    assert unsupported.status == "FAILED"
    assert unsupported.error_code == "UNSUPPORTED_REGISTRY_ECOSYSTEM"
    assert "pypi" in supported_registry_ecosystems()

    with pytest.raises(ValueError, match="SUCCESS requires"):
        RegistryResponse("x", "p", "SUCCESS", (), "u", None)
    with pytest.raises(ValueError, match="FAILED requires"):
        RegistryResponse("x", "p", "FAILED", (), "u", None)


def test_structural_frame_builds_edges_and_records_blind_exclusions(tmp_path: Path) -> None:
    archive_dir = tmp_path / "archives"
    archive_dir.mkdir()
    cve = "CVE-2026-6419"
    osv_json = (
        '{"id":"GHSA-aaaa","aliases":["'
        + cve
        + '"],"affected":[{"package":{"ecosystem":"PyPI","name":"demo"},'
        '"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.2.0"}]}]}]}'
    ).encode()
    pypa_yaml = (
        "id: PYSEC-2026-1\n"
        f"aliases: [{cve}]\n"
        "affected:\n"
        "  - package:\n"
        "      ecosystem: pip\n"
        "      name: demo\n"
        "    ranges:\n"
        "      - type: ECOSYSTEM\n"
        "        events:\n"
        "          - introduced: '0'\n"
        "          - fixed: 1.3.0\n"
    ).encode()
    unsupported_go_yaml = b"id: GO-2026-1\n"

    _write_tar(
        archive_dir / "C-GHAD.tar.gz",
        {"ghad/advisories/github-reviewed/2026/01/GHSA-aaaa.json": osv_json},
    )
    _write_tar(archive_dir / "C-PYPA.tar.gz", {"pypa/vulns/demo/PYSEC-2026-1.yaml": pypa_yaml})
    _write_tar(
        archive_dir / "C-GOVULNDB.tar.gz",
        {
            "govuln/data/osv/GO-2026-1.json": b'{"id":"GO-2026-1","affected":[]}',
            "govuln/data/reports/GO-2026-1.yaml": unsupported_go_yaml,
        },
    )

    specs = [
        SourceSpec("C-GHAD", "https://github.com/github/advisory-database", "git", "a" * 40, "MIT", "test"),
        SourceSpec("C-GOVULNDB", "https://github.com/golang/vulndb", "git", "b" * 40, "MIT", "test"),
        SourceSpec("C-PYPA", "https://github.com/pypa/advisory-database", "git", "c" * 40, "MIT", "test"),
    ]
    summary = build_structural_frame(specs, archive_dir, tmp_path / "out")

    assert summary["recognized_advisory_records"] == 3
    assert summary["claim_bearing_members"] == 2
    assert summary["normalized_claims"] == 2
    assert summary["alias_package_groups"] == 1
    assert summary["qualified_edges"] == 1
    assert summary["target_bearing_edges"] == 1
    exclusions = (tmp_path / "out" / "structural_exclusions.json").read_text(encoding="utf-8")
    assert "GO_NATIVE_REPORT_NO_FROZEN_PRIMARY_ADAPTER" in exclusions
    assert "NO_QUALIFYING_AFFECTED_PACKAGE" in exclusions
