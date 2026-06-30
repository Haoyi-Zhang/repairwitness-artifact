from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, MutableMapping, Sequence

from .canonical import canonical_json_bytes, sha256_bytes


def _normalize_obligations(
    obligations: Mapping[str, Iterable[str]],
) -> dict[str, frozenset[str]]:
    normalized: dict[str, frozenset[str]] = {}
    for edge_id in sorted(obligations):
        witnesses = frozenset(str(item) for item in obligations[edge_id])
        if not witnesses:
            raise ValueError(f"divergent edge {edge_id!r} has no concrete witness")
        normalized[str(edge_id)] = witnesses
    if not normalized:
        raise ValueError("at least one divergent edge is required")
    return normalized


def obligation_digest(obligations: Mapping[str, Iterable[str]]) -> str:
    normalized = _normalize_obligations(obligations)
    payload = {edge: sorted(witnesses) for edge, witnesses in normalized.items()}
    return sha256_bytes(canonical_json_bytes(payload))


@dataclass(frozen=True)
class KernelStats:
    original_edges: int
    residual_edges: int
    forced_releases: tuple[str, ...]
    forced_covered_edges: int
    redundant_edges: int
    components: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "original_edges": self.original_edges,
            "residual_edges": self.residual_edges,
            "forced_releases": list(self.forced_releases),
            "forced_covered_edges": self.forced_covered_edges,
            "redundant_edges": self.redundant_edges,
            "components": self.components,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object] | None) -> "KernelStats":
        if value is None:
            return cls(0, 0, tuple(), 0, 0)
        return cls(
            original_edges=int(value.get("original_edges", 0)),
            residual_edges=int(value.get("residual_edges", 0)),
            forced_releases=tuple(
                str(item) for item in value.get("forced_releases", [])  # type: ignore[arg-type]
            ),
            forced_covered_edges=int(value.get("forced_covered_edges", 0)),
            redundant_edges=int(value.get("redundant_edges", 0)),
            components=int(value.get("components", 0)),
        )


@dataclass(frozen=True)
class SuiteCertificate:
    algorithm: str
    status: str
    selected_releases: tuple[str, ...]
    edge_witness: tuple[tuple[str, str], ...]
    obligation_sha256: str
    lower_bound: int
    upper_bound: int
    explored_nodes: int
    kernel: KernelStats = KernelStats(0, 0, tuple(), 0, 0)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 2,
            "algorithm": self.algorithm,
            "status": self.status,
            "selected_releases": list(self.selected_releases),
            "edge_witness": [
                {"edge_id": edge_id, "release": release}
                for edge_id, release in self.edge_witness
            ],
            "obligation_sha256": self.obligation_sha256,
            "lower_bound": self.lower_bound,
            "upper_bound": self.upper_bound,
            "explored_nodes": self.explored_nodes,
            "kernel": self.kernel.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "SuiteCertificate":
        rows = value.get("edge_witness", [])
        kernel_value = value.get("kernel")
        return cls(
            algorithm=str(value["algorithm"]),
            status=str(value["status"]),
            selected_releases=tuple(str(item) for item in value["selected_releases"]),
            edge_witness=tuple(
                (str(row["edge_id"]), str(row["release"]))  # type: ignore[index]
                for row in rows  # type: ignore[assignment]
            ),
            obligation_sha256=str(value["obligation_sha256"]),
            lower_bound=int(value["lower_bound"]),
            upper_bound=int(value["upper_bound"]),
            explored_nodes=int(value["explored_nodes"]),
            kernel=KernelStats.from_dict(
                kernel_value if isinstance(kernel_value, Mapping) else None
            ),
        )


def _coverage_index(
    obligations: Mapping[str, frozenset[str]],
) -> dict[str, frozenset[str]]:
    coverage: MutableMapping[str, set[str]] = {}
    for edge_id, witnesses in obligations.items():
        for release in witnesses:
            coverage.setdefault(release, set()).add(edge_id)
    return {release: frozenset(edges) for release, edges in coverage.items()}


def _kernelize(
    obligations: Mapping[str, frozenset[str]],
) -> tuple[dict[str, frozenset[str]], tuple[str, ...], KernelStats]:
    """Apply sound cardinality-preserving reductions.

    Singleton witness sets force their only release. After propagating forced
    releases, duplicate obligations and witness-set supersets are redundant:
    hitting a retained subset obligation necessarily hits its supersets.
    Certificates are still emitted and replayed against the unreduced map.
    """

    residual = dict(obligations)
    forced: set[str] = set()
    forced_covered: set[str] = set()

    while residual:
        singleton_releases = {
            next(iter(witnesses))
            for witnesses in residual.values()
            if len(witnesses) == 1
        }
        new_forced = singleton_releases - forced
        if not new_forced:
            break
        forced.update(new_forced)
        covered = {
            edge_id
            for edge_id, witnesses in residual.items()
            if witnesses.intersection(new_forced)
        }
        forced_covered.update(covered)
        residual = {
            edge_id: witnesses
            for edge_id, witnesses in residual.items()
            if edge_id not in covered
        }

    kept: dict[str, frozenset[str]] = {}
    redundant = 0
    for edge_id in sorted(residual, key=lambda edge: (len(residual[edge]), edge)):
        witnesses = residual[edge_id]
        if any(retained.issubset(witnesses) for retained in kept.values()):
            redundant += 1
            continue
        kept[edge_id] = witnesses

    coverage = _coverage_index(kept) if kept else {}
    unseen = set(kept)
    components = 0
    while unseen:
        components += 1
        stack = [min(unseen)]
        unseen.remove(stack[0])
        while stack:
            edge_id = stack.pop()
            neighbors: set[str] = set()
            for release in kept[edge_id]:
                neighbors.update(coverage[release])
            for neighbor in sorted(neighbors.intersection(unseen)):
                unseen.remove(neighbor)
                stack.append(neighbor)

    stats = KernelStats(
        original_edges=len(obligations),
        residual_edges=len(kept),
        forced_releases=tuple(sorted(forced)),
        forced_covered_edges=len(forced_covered),
        redundant_edges=redundant,
        components=components,
    )
    return kept, tuple(sorted(forced)), stats


def _certificate(
    algorithm: str,
    status: str,
    selected: Sequence[str],
    obligations: Mapping[str, frozenset[str]],
    lower_bound: int,
    explored_nodes: int,
    kernel: KernelStats,
) -> SuiteCertificate:
    selected_tuple = tuple(sorted(set(selected)))
    mapping: list[tuple[str, str]] = []
    for edge_id in sorted(obligations):
        candidates = sorted(obligations[edge_id].intersection(selected_tuple))
        if not candidates:
            raise AssertionError(f"selected suite does not cover edge {edge_id}")
        mapping.append((edge_id, candidates[0]))
    return SuiteCertificate(
        algorithm=algorithm,
        status=status,
        selected_releases=selected_tuple,
        edge_witness=tuple(mapping),
        obligation_sha256=obligation_digest(obligations),
        lower_bound=lower_bound,
        upper_bound=len(selected_tuple),
        explored_nodes=explored_nodes,
        kernel=kernel,
    )


def _greedy_selected(
    obligations: Mapping[str, frozenset[str]],
) -> tuple[str, ...]:
    if not obligations:
        return tuple()
    coverage = _coverage_index(obligations)
    uncovered = set(obligations)
    selected: list[str] = []
    while uncovered:
        release = min(
            coverage,
            key=lambda candidate: (
                -len(coverage[candidate].intersection(uncovered)),
                candidate,
            ),
        )
        newly_covered = coverage[release].intersection(uncovered)
        if not newly_covered:
            raise AssertionError("uncoverable obligation reached greedy solver")
        selected.append(release)
        uncovered.difference_update(newly_covered)
    return tuple(selected)


def solve_greedy(
    obligations: Mapping[str, Iterable[str]],
) -> SuiteCertificate:
    normalized = _normalize_obligations(obligations)
    reduced, forced, kernel = _kernelize(normalized)
    selected = tuple((*forced, *_greedy_selected(reduced)))
    lower_bound = len(forced) + _disjoint_obligation_lower_bound(
        reduced, frozenset(reduced)
    )
    return _certificate(
        "KERNELIZED_GREEDY_MAX_COVER",
        "HEURISTIC",
        selected,
        normalized,
        lower_bound=lower_bound,
        explored_nodes=0,
        kernel=kernel,
    )


def _disjoint_obligation_lower_bound(
    obligations: Mapping[str, frozenset[str]],
    uncovered: frozenset[str],
) -> int:
    """Return a valid (not necessarily maximum) disjoint-family lower bound."""

    used_releases: set[str] = set()
    count = 0
    for edge_id in sorted(uncovered, key=lambda edge: (len(obligations[edge]), edge)):
        witnesses = obligations[edge_id]
        if witnesses.isdisjoint(used_releases):
            used_releases.update(witnesses)
            count += 1
    return count


def solve_exact(
    obligations: Mapping[str, Iterable[str]],
    *,
    max_nodes: int | None = None,
) -> SuiteCertificate:
    """Solve minimum hitting set with deterministic kernelized branch-and-bound.

    If ``max_nodes`` is reached, the returned certificate is BOUNDED and reports a
    sound lower bound together with the best replayable upper-bound suite found.
    """

    normalized = _normalize_obligations(obligations)
    reduced, forced, kernel = _kernelize(normalized)
    forced_count = len(forced)

    if not reduced:
        return _certificate(
            "KERNELIZED_DETERMINISTIC_BRANCH_AND_BOUND",
            "EXACT",
            forced,
            normalized,
            lower_bound=forced_count,
            explored_nodes=0,
            kernel=kernel,
        )

    coverage = _coverage_index(reduced)
    best_residual = tuple(sorted(_greedy_selected(reduced)))
    explored_nodes = 0
    exhausted = False
    root_residual_lower = _disjoint_obligation_lower_bound(
        reduced, frozenset(reduced)
    )

    def better(candidate: tuple[str, ...], incumbent: tuple[str, ...]) -> bool:
        return (len(candidate), candidate) < (len(incumbent), incumbent)

    def search(selected: tuple[str, ...], uncovered: frozenset[str]) -> None:
        nonlocal best_residual, explored_nodes, exhausted
        if exhausted:
            return
        explored_nodes += 1
        if max_nodes is not None and explored_nodes > max_nodes:
            exhausted = True
            return
        if not uncovered:
            candidate = tuple(sorted(selected))
            if better(candidate, best_residual):
                best_residual = candidate
            return

        lower = _disjoint_obligation_lower_bound(reduced, uncovered)
        if len(selected) + lower > len(best_residual):
            return
        if len(selected) >= len(best_residual):
            return

        pivot = min(
            uncovered,
            key=lambda edge: (len(reduced[edge]), edge),
        )
        candidates = sorted(
            reduced[pivot],
            key=lambda release: (
                -len(coverage[release].intersection(uncovered)),
                release,
            ),
        )
        for release in candidates:
            if release in selected:
                continue
            next_selected = tuple(sorted((*selected, release)))
            next_uncovered = frozenset(uncovered - coverage[release])
            search(next_selected, next_uncovered)
            if exhausted:
                return

    search(tuple(), frozenset(reduced))
    status = "BOUNDED" if exhausted else "EXACT"
    lower_bound = (
        forced_count + root_residual_lower
        if exhausted
        else forced_count + len(best_residual)
    )
    selected = tuple((*forced, *best_residual))
    return _certificate(
        "KERNELIZED_DETERMINISTIC_BRANCH_AND_BOUND",
        status,
        selected,
        normalized,
        lower_bound=lower_bound,
        explored_nodes=explored_nodes,
        kernel=kernel,
    )


def verify_certificate(
    obligations: Mapping[str, Iterable[str]],
    certificate: SuiteCertificate,
) -> tuple[bool, tuple[str, ...]]:
    errors: list[str] = []
    normalized = _normalize_obligations(obligations)
    expected_digest = obligation_digest(normalized)
    if certificate.obligation_sha256 != expected_digest:
        errors.append("obligation digest mismatch")
    selected = set(certificate.selected_releases)
    if certificate.upper_bound != len(selected):
        errors.append("upper bound does not equal selected suite size")
    if certificate.lower_bound < 0 or certificate.lower_bound > certificate.upper_bound:
        errors.append("invalid lower/upper bound interval")
    mapping = dict(certificate.edge_witness)
    if len(mapping) != len(certificate.edge_witness):
        errors.append("duplicate edge identifiers in witness mapping")
    if set(mapping) != set(normalized):
        errors.append("witness mapping does not match obligation set")
    for edge_id, witnesses in normalized.items():
        release = mapping.get(edge_id)
        if release is None:
            continue
        if release not in selected:
            errors.append(f"edge {edge_id} maps to an unselected release")
        if release not in witnesses:
            errors.append(f"edge {edge_id} maps to a non-witness release")
    if certificate.status == "EXACT" and certificate.lower_bound != certificate.upper_bound:
        errors.append("exact certificate has a nonzero optimality gap")
    if certificate.kernel.original_edges not in (0, len(normalized)):
        errors.append("kernel original-edge count mismatch")
    if not set(certificate.kernel.forced_releases).issubset(selected):
        errors.append("kernel forced release absent from selected suite")
    return not errors, tuple(errors)
