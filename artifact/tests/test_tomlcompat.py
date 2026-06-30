from __future__ import annotations

from action_suites.tomlcompat import loads


def test_hash_characters_inside_strings_are_not_comments() -> None:
    data = loads(
        """
title = "repair claim #42" # only this suffix is a comment
literal = 'package#name' # comments may follow literal strings

[advisory]
id = "RUSTSEC-2026-0001"
package = "demo#crate"
aliases = ["CVE-2026-0002", "GHSA-aa#bb-cccc"]
"""
    )

    assert data["title"] == "repair claim #42"
    assert data["literal"] == "package#name"
    assert data["advisory"]["package"] == "demo#crate"
    assert data["advisory"]["aliases"] == ["CVE-2026-0002", "GHSA-aa#bb-cccc"]


def test_nested_tables_inline_tables_and_arrays_match_artifact_metadata() -> None:
    data = loads(
        """
[project]
name = "repairwitness"
license = {file = "LICENSE.txt"}
dependencies = [
  "numpy>=2.1,<3", # numeric backend
  "packaging==25.0",
]

[project.optional-dependencies]
test = ["pytest==9.0.2", "coverage>=7.6,<8"]

[tool.pytest.ini_options]
testpaths = ["tests"]
markers = { offline = true, tags = ["artifact#offline", "cpu"] }
"""
    )

    assert data["project"]["license"] == {"file": "LICENSE.txt"}
    assert data["project"]["dependencies"] == ["numpy>=2.1,<3", "packaging==25.0"]
    assert data["project"]["optional-dependencies"]["test"] == [
        "pytest==9.0.2",
        "coverage>=7.6,<8",
    ]
    assert data["tool"]["pytest"]["ini_options"]["markers"] == {
        "offline": True,
        "tags": ["artifact#offline", "cpu"],
    }


def test_multiline_arrays_preserve_inline_tables_and_trailing_comments() -> None:
    data = loads(
        """
[versions]
patched = [
  { requirement = ">= 1.2.0", ecosystems = ["crates.io", "pypi#legacy"] }, # first fix
  { requirement = ">= 2.0.0", ecosystems = ["npm"] },
]
unaffected = [
  "< 1.0.0", # historical safe range
  ">= 3.0.0 # metadata note",
]
"""
    )

    assert data["versions"]["patched"] == [
        {"requirement": ">= 1.2.0", "ecosystems": ["crates.io", "pypi#legacy"]},
        {"requirement": ">= 2.0.0", "ecosystems": ["npm"]},
    ]
    assert data["versions"]["unaffected"] == [
        "< 1.0.0",
        ">= 3.0.0 # metadata note",
    ]
