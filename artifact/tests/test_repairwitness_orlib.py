from __future__ import annotations

from pathlib import Path

import pytest

from repairwitness.orlib import OrlibFormatError, parse_orlib_scp


def test_parse_minimal_orlib_instance() -> None:
    content = b"2 3 1 2 3 2 1 2 2 2 3\n"
    instance = parse_orlib_scp(content, name="tiny")
    obligations, costs = instance.to_problem()
    assert instance.row_count == 2
    assert obligations == {"row-00001": frozenset({"column-000001", "column-000002"}), "row-00002": frozenset({"column-000002", "column-000003"})}
    assert costs["column-000003"] == 3


def test_orlib_trailing_tokens_rejected() -> None:
    with pytest.raises(OrlibFormatError):
        parse_orlib_scp(b"1 1 1 1 1 99", name="bad")


def test_real_orlib_instance_parses() -> None:
    path = Path(__file__).parents[1] / "benchmarks" / "orlib50" / "inputs" / "scp41.txt"
    if not path.exists():
        pytest.skip("external benchmark inputs not installed")
    instance = parse_orlib_scp(path.read_bytes(), name="scp41")
    assert (instance.row_count, instance.column_count) == (200, 1000)
    assert instance.source_sha256
