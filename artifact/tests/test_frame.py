from __future__ import annotations

from action_suites.adapters import StructuralClaim
from action_suites.frame import build_groups_and_edges


def claim(claim_id: str, source: str, alias: str) -> StructuralClaim:
    return StructuralClaim(
        claim_id=claim_id, source_id=source, record_id=alias,
        package_ecosystem="PyPI", package_name="demo", aliases=(alias,),
        withdrawn=False, ranges=(), versions=("1.0",), advisory_targets=(),
        alternative_actions=(), source_path=f"{claim_id}.json",
    )


def test_only_cross_curation_edges_are_qualified() -> None:
    claims = [claim("a", "C-GHAD", "CVE-1"), claim("b", "C-PYPA", "CVE-1"), claim("c", "C-GHAD", "CVE-1")]
    groups, edges = build_groups_and_edges(claims)
    assert len(groups) == 1
    assert len(edges) == 2
    assert all(edge.comparison_kind == "CURATION_LINEAGE" for edge in edges)
    assert all(edge.left_source_id != edge.right_source_id for edge in edges)
