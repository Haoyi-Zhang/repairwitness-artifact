from __future__ import annotations

import pytest

from action_suites.adapters import (
    StructuralClaim,
    parse_osv_record,
    parse_ruby_advisory,
    parse_rustsec_markdown,
    parse_supported_member,
)
from action_suites.model import ActionKind, ReleaseUniverse
from action_suites.semantics import affected_status, evaluate_claim


def test_osv_fixed_event_becomes_public_upgrade_anchor() -> None:
    record = {
        "id": "GHSA-aaaa-bbbb-cccc",
        "aliases": ["CVE-2026-0001"],
        "affected": [{
            "package": {"ecosystem": "PyPI", "name": "demo"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}],
        }],
    }
    claim = parse_osv_record("C-GHAD", "record.json", record)[0]
    universe = ReleaseUniverse("pypi::demo", ("1.0", "1.5", "2.0"), "a" * 64)
    assert affected_status(claim, "1.5") is True
    action = evaluate_claim(claim, "1.5", universe)
    assert action.kind is ActionKind.UPGRADE_TO_ADVISORY_TARGET
    assert action.targets == ("2.0",)
    assert evaluate_claim(claim, "2.0", universe).kind is ActionKind.NO_ACTION


def test_rustsec_package_and_requirement_anchor() -> None:
    content = b'''```toml\n[advisory]\nid = "RUSTSEC-2026-0001"\npackage = "demo"\naliases = ["CVE-2026-0002"]\n[versions]\npatched = [">= 1.2.0"]\nunaffected = ["< 1.0.0"]\n```\n\n# Demo\n'''
    claim = parse_rustsec_markdown("C-RUSTSEC", "crates/demo/a.md", content)[0]
    universe = ReleaseUniverse("crates.io::demo", ("0.9.0", "1.0.0", "1.2.0", "1.3.0"), "b" * 64)
    assert evaluate_claim(claim, "0.9.0", universe).kind is ActionKind.NO_ACTION
    action = evaluate_claim(claim, "1.0.0", universe)
    assert action.kind is ActionKind.UPGRADE_TO_ADVISORY_TARGET
    assert action.targets == ("1.2.0",)


def test_osv_multiple_intervals_do_not_overwrite_earlier_segment() -> None:
    record = {
        "id": "GHSA-dddd-eeee-ffff",
        "affected": [{
            "package": {"ecosystem": "PyPI", "name": "demo"},
            "ranges": [{
                "type": "ECOSYSTEM",
                "events": [
                    {"introduced": "0"}, {"fixed": "1.0"},
                    {"introduced": "2.0"}, {"fixed": "3.0"},
                ],
            }],
        }],
    }
    claim = parse_osv_record("C-GHAD", "record.json", record)[0]
    assert affected_status(claim, "0.5") is True
    assert affected_status(claim, "1.5") is False
    assert affected_status(claim, "2.5") is True
    assert affected_status(claim, "3.0") is False


def test_semver_prerelease_order_is_not_lexical() -> None:
    from action_suites.semantics import compare_versions

    assert compare_versions("npm", "1.0.0-beta.2", "1.0.0-beta.11") < 0
    assert compare_versions("npm", "1.0.0-beta.11", "1.0.0") < 0
    assert compare_versions("npm", "1.0.0+build.1", "1.0.0+build.9") == 0


def test_pypi_uses_pep440_ordering() -> None:
    from action_suites.semantics import compare_versions

    assert compare_versions("PyPI", "1!1.0rc1", "1!1.0") < 0
    assert compare_versions("PyPI", "1.0.post1", "1.0") > 0


def test_unsupported_ecosystem_abstains_instead_of_guessing() -> None:
    record = {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "affected": [{
            "package": {"ecosystem": "SwiftURL", "name": "demo"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
        }],
    }
    claim = parse_osv_record("C-GHAD", "record.json", record)[0]
    universe = ReleaseUniverse("swifturl::demo", ("1.0.0", "2.0.0"), "c" * 64)
    action = evaluate_claim(claim, "1.0.0", universe)
    from action_suites.model import BlockerCode

    assert action.kind is ActionKind.UNKNOWN
    assert action.blocker is BlockerCode.UNSUPPORTED_ECOSYSTEM


def test_maven_qualifier_is_rejected_by_numeric_subset() -> None:
    record = {
        "id": "GHSA-mmmm-aaaa-vvvv",
        "affected": [{
            "package": {"ecosystem": "Maven", "name": "g:a"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0.RELEASE"}]}],
        }],
    }
    claim = parse_osv_record("C-GHAD", "record.json", record)[0]
    universe = ReleaseUniverse("maven::g:a", ("1.0.0.RELEASE", "2.0.0.RELEASE"), "d" * 64)
    assert evaluate_claim(claim, "1.0.0.RELEASE", universe).kind is ActionKind.UNKNOWN


def test_rubygems_pessimistic_requirement_subset() -> None:
    from action_suites.semantics import requirement_matches

    assert requirement_matches("RubyGems", "2.2.9", "~> 2.2")
    assert not requirement_matches("RubyGems", "3.0.0", "~> 2.2")
    assert requirement_matches("RubyGems", "2.2.5", ">= 2.2, < 2.3")


def test_rubysec_advisory_preserves_patched_and_vulnerable_ranges() -> None:
    content = b"""gem: demo\ncve: CVE-2026-1000\npatched_versions:\n  - \">= 2.0.0\"\nunaffected_versions:\n  - \"< 1.0.0\"\nvulnerable_versions:\n  - \">= 1.0.0, < 2.0.0\"\n"""
    claim = parse_ruby_advisory("C-RUBYSEC", "gems/demo/CVE-2026-1000.yml", content)[0]
    universe = ReleaseUniverse("rubygems::demo", ("0.9.0", "1.5.0", "2.0.0"), "e" * 64)

    assert claim.record_id == "CVE-2026-1000"
    assert evaluate_claim(claim, "0.9.0", universe).kind is ActionKind.NO_ACTION
    action = evaluate_claim(claim, "1.5.0", universe)
    assert action.kind is ActionKind.UPGRADE_TO_ADVISORY_TARGET
    assert action.targets == ("2.0.0",)
    assert evaluate_claim(claim, "2.0.0", universe).kind is ActionKind.NO_ACTION


def test_supported_member_dispatches_frozen_sources_and_rejects_unknown() -> None:
    pypa_yaml = b"""id: PYSEC-2026-1\naffected:\n  - package:\n      ecosystem: PyPI\n      name: demo\n    ranges:\n      - type: ECOSYSTEM\n        events:\n          - introduced: \"0\"\n          - fixed: \"1.0\"\n"""
    claims = parse_supported_member("C-PYPA", "vulns/demo.yaml", pypa_yaml)
    assert len(claims) == 1
    assert claims[0].package_key == "pypi::demo"

    with pytest.raises(ValueError, match="no frozen adapter"):
        parse_supported_member("C-UNKNOWN", "record.json", b"{}")


def test_osv_parser_skips_malformed_affected_members_without_guessing() -> None:
    record = {
        "id": "GHSA-skip-malformed",
        "withdrawn": "2026-01-01T00:00:00Z",
        "affected": [
            "not-a-mapping",
            {"package": "not-a-mapping"},
            {"package": {"ecosystem": "PyPI", "name": ""}},
            {
                "package": {"ecosystem": "pip", "name": "demo"},
                "versions": ["1.0", "1.0", ""],
            },
        ],
    }
    claims = parse_osv_record("C-GHAD", "record.json", record)
    assert len(claims) == 1
    assert isinstance(claims[0], StructuralClaim)
    assert claims[0].withdrawn is True
    assert claims[0].package_ecosystem == "PyPI"
    assert claims[0].versions == ("1.0",)
