from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from itertools import combinations
from typing import Iterable, Mapping

from .adapters import StructuralClaim
from .canonical import canonical_json_bytes, sha256_bytes


class UnionFind:
    def __init__(self, items: Iterable[str]) -> None:
        self.parent = {item: item for item in items}

    def find(self, item: str) -> str:
        parent = self.parent[item]
        if parent != item:
            self.parent[item] = self.find(parent)
        return self.parent[item]

    def union(self, left: str, right: str) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root == right_root:
            return
        if left_root < right_root:
            self.parent[right_root] = left_root
        else:
            self.parent[left_root] = right_root


@dataclass(frozen=True)
class ClaimGroup:
    group_id: str
    package_key: str
    claim_ids: tuple[str, ...]
    source_ids: tuple[str, ...]
    vulnerability_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "group_id": self.group_id,
            "package_key": self.package_key,
            "claim_ids": list(self.claim_ids),
            "source_ids": list(self.source_ids),
            "vulnerability_ids": list(self.vulnerability_ids),
        }


@dataclass(frozen=True)
class QualifiedEdge:
    edge_id: str
    group_id: str
    package_key: str
    left_claim_id: str
    right_claim_id: str
    left_source_id: str
    right_source_id: str
    target_bearing: bool
    comparison_kind: str = "CURATION_LINEAGE"

    def to_dict(self) -> dict[str, object]:
        return self.__dict__.copy()


def build_groups_and_edges(
    claims: Iterable[StructuralClaim],
) -> tuple[tuple[ClaimGroup, ...], tuple[QualifiedEdge, ...]]:
    claims_tuple = tuple(sorted(claims, key=lambda item: item.claim_id))
    by_package: dict[str, list[StructuralClaim]] = defaultdict(list)
    for claim in claims_tuple:
        by_package[claim.package_key].append(claim)

    groups: list[ClaimGroup] = []
    edges: list[QualifiedEdge] = []
    for package_key, package_claims in sorted(by_package.items()):
        union_find = UnionFind(claim.claim_id for claim in package_claims)
        alias_owner: dict[str, str] = {}
        for claim in package_claims:
            identifiers = claim.aliases or (claim.record_id.upper(),)
            for identifier in identifiers:
                previous = alias_owner.get(identifier)
                if previous is None:
                    alias_owner[identifier] = claim.claim_id
                else:
                    union_find.union(previous, claim.claim_id)

        components: dict[str, list[StructuralClaim]] = defaultdict(list)
        for claim in package_claims:
            components[union_find.find(claim.claim_id)].append(claim)

        for component in components.values():
            source_ids = {claim.source_id for claim in component}
            if len(component) < 2 or len(source_ids) < 2:
                continue
            claim_ids = tuple(sorted(claim.claim_id for claim in component))
            vulnerability_ids = tuple(
                sorted({identifier for claim in component for identifier in claim.aliases})
            )
            group_id = "group-" + sha256_bytes(
                canonical_json_bytes(
                    {"package_key": package_key, "claim_ids": list(claim_ids)}
                )
            )[:24]
            group = ClaimGroup(
                group_id=group_id,
                package_key=package_key,
                claim_ids=claim_ids,
                source_ids=tuple(sorted(source_ids)),
                vulnerability_ids=vulnerability_ids,
            )
            groups.append(group)
            by_id = {claim.claim_id: claim for claim in component}
            for left_id, right_id in combinations(claim_ids, 2):
                left = by_id[left_id]
                right = by_id[right_id]
                if left.source_id == right.source_id:
                    continue
                edge_payload = {
                    "group_id": group_id,
                    "left_claim_id": left_id,
                    "right_claim_id": right_id,
                }
                edges.append(
                    QualifiedEdge(
                        edge_id="edge-"
                        + sha256_bytes(canonical_json_bytes(edge_payload))[:24],
                        group_id=group_id,
                        package_key=package_key,
                        left_claim_id=left_id,
                        right_claim_id=right_id,
                        left_source_id=left.source_id,
                        right_source_id=right.source_id,
                        target_bearing=bool(
                            left.advisory_targets or right.advisory_targets
                        ),
                    )
                )
    return (
        tuple(sorted(groups, key=lambda item: item.group_id)),
        tuple(sorted(edges, key=lambda item: item.edge_id)),
    )
