"""Certified weighted action-separating release suites.

The primary registered analysis is the unit-cost, unit-demand special case.  The
implementation deliberately supports positive integer execution costs and redundant
witness demands because those extensions expose otherwise hidden assumptions and
permit robustness analyses without changing the primary estimand.

The module has four trust layers:

* canonical problem normalization and digest binding;
* sound reductions (signature quotient, forced propagation, row dominance, and
  connected-component decomposition);
* deterministic exact/bounded/greedy solvers; and
* replayable certificates whose optimality can be checked by an independent oracle.

UNKNOWN actions are filtered before obligations reach this module; every member of an
obligation is therefore a concrete release witness.
"""

from __future__ import annotations

import heapq
import math
from collections.abc import Iterable, Mapping, MutableMapping, Sequence
from dataclasses import dataclass
from fractions import Fraction

from .canonical import canonical_json_bytes, sha256_bytes
from .oracle import solve_independent_oracle

SOLVER_VERSION = "0.4.0"


class InfeasibleSuiteProblem(ValueError):
    """Raised when an obligation cannot meet its registered witness demand."""


def _sequence_field(value: object, field: str) -> Sequence[object]:
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return value
    raise ValueError(f"{field} must be a JSON array")


def _integer_value(value: object, field: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be an integer, not a Boolean")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError as exc:
            raise ValueError(f"{field} must be an integer") from exc
    raise ValueError(f"{field} must be an integer")


def _integer_field(value: Mapping[str, object], field: str, default: int) -> int:
    return _integer_value(value.get(field, default), field)


@dataclass(frozen=True)
class _Problem:
    obligations: dict[str, frozenset[str]]
    demands: dict[str, int]
    costs: dict[str, int]
    releases: tuple[str, ...]
    digest: str


@dataclass(frozen=True)
class KernelStats:
    original_edges: int
    original_releases: int
    residual_edges: int
    residual_releases: int
    original_signatures: int
    retained_signatures: int
    signature_pruned_releases: int
    forced_releases: tuple[str, ...]
    forced_cost: int
    forced_satisfied_edges: int
    redundant_edges: int
    original_components: int
    residual_components: int
    state_space_upper_bound: int

    @property
    def components(self) -> int:
        """Backward-compatible alias for the residual component count."""

        return self.residual_components

    @property
    def forced_covered_edges(self) -> int:
        """Backward-compatible alias for satisfied obligations."""

        return self.forced_satisfied_edges

    def to_dict(self) -> dict[str, object]:
        return {
            "original_edges": self.original_edges,
            "original_releases": self.original_releases,
            "residual_edges": self.residual_edges,
            "residual_releases": self.residual_releases,
            "original_signatures": self.original_signatures,
            "retained_signatures": self.retained_signatures,
            "signature_pruned_releases": self.signature_pruned_releases,
            "forced_releases": list(self.forced_releases),
            "forced_cost": self.forced_cost,
            "forced_satisfied_edges": self.forced_satisfied_edges,
            "redundant_edges": self.redundant_edges,
            "original_components": self.original_components,
            "residual_components": self.residual_components,
            "components": self.residual_components,
            "state_space_upper_bound": self.state_space_upper_bound,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object] | None) -> KernelStats:
        if value is None:
            return cls(0, 0, 0, 0, 0, 0, 0, (), 0, 0, 0, 0, 0, 1)
        # Schema-v2 compatibility is intentional: old certificates remain readable,
        # but their digest will not validate against a weighted problem silently.
        forced_raw = _sequence_field(value.get("forced_releases", ()), "kernel.forced_releases")
        forced_releases = tuple(str(item) for item in forced_raw)
        return cls(
            original_edges=_integer_field(value, "original_edges", 0),
            original_releases=_integer_field(value, "original_releases", 0),
            residual_edges=_integer_field(value, "residual_edges", 0),
            residual_releases=_integer_field(value, "residual_releases", 0),
            original_signatures=_integer_field(value, "original_signatures", 0),
            retained_signatures=_integer_field(value, "retained_signatures", 0),
            signature_pruned_releases=_integer_field(value, "signature_pruned_releases", 0),
            forced_releases=forced_releases,
            forced_cost=_integer_field(value, "forced_cost", len(forced_releases)),
            forced_satisfied_edges=_integer_value(
                value.get("forced_satisfied_edges", value.get("forced_covered_edges", 0)),
                "forced_satisfied_edges",
            ),
            redundant_edges=_integer_field(value, "redundant_edges", 0),
            original_components=_integer_field(
                value,
                "original_components",
                _integer_field(value, "components", 0),
            ),
            residual_components=_integer_field(
                value,
                "residual_components",
                _integer_field(value, "components", 0),
            ),
            state_space_upper_bound=_integer_field(value, "state_space_upper_bound", 1),
        )


@dataclass(frozen=True)
class ComponentProof:
    edge_ids: tuple[str, ...]
    selected_releases: tuple[str, ...]
    lower_bound: int
    upper_bound: int
    explored_nodes: int
    node_budget: int | None
    exact: bool
    proof_kind: str

    def to_dict(self) -> dict[str, object]:
        return {
            "edge_ids": list(self.edge_ids),
            "selected_releases": list(self.selected_releases),
            "lower_bound": self.lower_bound,
            "upper_bound": self.upper_bound,
            "explored_nodes": self.explored_nodes,
            "node_budget": self.node_budget,
            "exact": self.exact,
            "proof_kind": self.proof_kind,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> ComponentProof:
        edge_ids = tuple(
            str(item) for item in _sequence_field(value.get("edge_ids"), "component.edge_ids")
        )
        selected = tuple(
            str(item)
            for item in _sequence_field(
                value.get("selected_releases"), "component.selected_releases"
            )
        )
        exact = value.get("exact")
        if not isinstance(exact, bool):
            raise ValueError("component.exact must be Boolean")
        return cls(
            edge_ids=edge_ids,
            selected_releases=selected,
            lower_bound=_integer_value(value["lower_bound"], "component.lower_bound"),
            upper_bound=_integer_value(value["upper_bound"], "component.upper_bound"),
            explored_nodes=_integer_value(value["explored_nodes"], "component.explored_nodes"),
            node_budget=(
                None
                if value.get("node_budget") is None
                else _integer_value(value["node_budget"], "component.node_budget")
            ),
            exact=exact,
            proof_kind=str(value["proof_kind"]),
        )


@dataclass(frozen=True)
class SuiteCertificate:
    solver_version: str
    algorithm: str
    status: str
    selected_releases: tuple[str, ...]
    edge_witnesses: tuple[tuple[str, tuple[str, ...]], ...]
    obligation_sha256: str
    lower_bound: int
    upper_bound: int
    explored_nodes: int
    proof_kind: str
    kernel: KernelStats
    component_proofs: tuple[ComponentProof, ...]
    approximation_factor_bound: float | None = None

    @property
    def edge_witness(self) -> tuple[tuple[str, str], ...]:
        """Backward-compatible first-witness view for unit-demand consumers."""

        return tuple(
            (edge_id, witnesses[0]) for edge_id, witnesses in self.edge_witnesses if witnesses
        )

    @property
    def suite_size(self) -> int:
        return len(self.selected_releases)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 5,
            "solver_version": self.solver_version,
            "algorithm": self.algorithm,
            "status": self.status,
            "selected_releases": list(self.selected_releases),
            "selected_release_count": self.suite_size,
            "edge_witnesses": [
                {"edge_id": edge_id, "releases": list(releases)}
                for edge_id, releases in self.edge_witnesses
            ],
            # Retain the unit-demand view for simple downstream tables.
            "edge_witness": [
                {"edge_id": edge_id, "release": release} for edge_id, release in self.edge_witness
            ],
            "obligation_sha256": self.obligation_sha256,
            "lower_bound": self.lower_bound,
            "upper_bound": self.upper_bound,
            "explored_nodes": self.explored_nodes,
            "proof_kind": self.proof_kind,
            "approximation_factor_bound": self.approximation_factor_bound,
            "kernel": self.kernel.to_dict(),
            "component_proofs": [row.to_dict() for row in self.component_proofs],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> SuiteCertificate:
        rows = value.get("edge_witnesses")
        if isinstance(rows, list):
            edge_witness_rows: list[tuple[str, tuple[str, ...]]] = []
            for row in rows:
                if not isinstance(row, Mapping):
                    raise ValueError("edge_witnesses rows must be JSON objects")
                releases_raw = _sequence_field(row.get("releases", ()), "edge_witnesses.releases")
                edge_witness_rows.append(
                    (
                        str(row["edge_id"]),
                        tuple(str(item) for item in releases_raw),
                    )
                )
            edge_witnesses = tuple(edge_witness_rows)
        else:
            legacy_rows = _sequence_field(value.get("edge_witness", ()), "edge_witness")
            legacy_witnesses: list[tuple[str, tuple[str, ...]]] = []
            for row in legacy_rows:
                if not isinstance(row, Mapping):
                    raise ValueError("edge_witness rows must be JSON objects")
                legacy_witnesses.append((str(row["edge_id"]), (str(row["release"]),)))
            edge_witnesses = tuple(legacy_witnesses)
        approximation = value.get("approximation_factor_bound")
        selected_raw = _sequence_field(value.get("selected_releases"), "selected_releases")
        kernel_raw = value.get("kernel")
        kernel = KernelStats.from_dict(kernel_raw if isinstance(kernel_raw, Mapping) else None)
        component_rows = _sequence_field(value.get("component_proofs", ()), "component_proofs")
        component_proofs = tuple(
            ComponentProof.from_dict(row) for row in component_rows if isinstance(row, Mapping)
        )
        if len(component_proofs) != len(component_rows):
            raise ValueError("component_proofs rows must be JSON objects")
        return cls(
            solver_version=str(value.get("solver_version", "LEGACY")),
            algorithm=str(value["algorithm"]),
            status=str(value["status"]),
            selected_releases=tuple(str(item) for item in selected_raw),
            edge_witnesses=edge_witnesses,
            obligation_sha256=str(value["obligation_sha256"]),
            lower_bound=_integer_value(value["lower_bound"], "lower_bound"),
            upper_bound=_integer_value(value["upper_bound"], "upper_bound"),
            explored_nodes=_integer_value(value["explored_nodes"], "explored_nodes"),
            proof_kind=str(value.get("proof_kind", "LEGACY_BOUND_ATTESTATION")),
            approximation_factor_bound=(
                float(str(approximation)) if approximation is not None else None
            ),
            kernel=kernel,
            component_proofs=component_proofs,
        )


def _normalize_problem(
    obligations: Mapping[str, Iterable[str]],
    *,
    demands: Mapping[str, int] | None = None,
    costs: Mapping[str, int] | None = None,
) -> _Problem:
    normalized: dict[str, frozenset[str]] = {}
    for raw_edge_id in sorted(obligations, key=str):
        edge_id = str(raw_edge_id)
        if not edge_id:
            raise ValueError("edge identifiers must be non-empty")
        witnesses = frozenset(str(item) for item in obligations[raw_edge_id])
        if not witnesses or "" in witnesses:
            raise ValueError(f"divergent edge {edge_id!r} has no concrete witness")
        normalized[edge_id] = witnesses
    if not normalized:
        raise ValueError("at least one divergent edge is required")

    releases = tuple(sorted(set().union(*normalized.values())))
    demand_values: dict[str, int] = {}
    if demands is not None:
        extras = set(map(str, demands)) - set(normalized)
        if extras:
            raise ValueError(f"demands contain unknown edges: {sorted(extras)}")
    for edge_id, witnesses in normalized.items():
        demand = int(demands.get(edge_id, 1) if demands is not None else 1)
        if demand < 1:
            raise ValueError(f"edge {edge_id!r} has non-positive demand")
        if demand > len(witnesses):
            raise InfeasibleSuiteProblem(
                f"edge {edge_id!r} demands {demand} distinct witnesses but has "
                f"only {len(witnesses)}"
            )
        demand_values[edge_id] = demand

    cost_values: dict[str, int] = {}
    if costs is not None:
        extras = set(map(str, costs)) - set(releases)
        if extras:
            raise ValueError(f"costs contain unknown releases: {sorted(extras)}")
    for release in releases:
        cost = int(costs.get(release, 1) if costs is not None else 1)
        if cost <= 0:
            raise ValueError(f"release {release!r} has non-positive execution cost")
        cost_values[release] = cost

    payload = {
        "obligations": {edge_id: sorted(witnesses) for edge_id, witnesses in normalized.items()},
        "demands": demand_values,
        "costs": cost_values,
    }
    digest = sha256_bytes(canonical_json_bytes(payload))
    return _Problem(normalized, demand_values, cost_values, releases, digest)


def obligation_digest(
    obligations: Mapping[str, Iterable[str]],
    *,
    demands: Mapping[str, int] | None = None,
    costs: Mapping[str, int] | None = None,
) -> str:
    """Return the canonical digest of witnesses, demands, and relevant costs."""

    return _normalize_problem(obligations, demands=demands, costs=costs).digest


def _coverage_index(
    obligations: Mapping[str, frozenset[str]],
) -> dict[str, frozenset[str]]:
    coverage: MutableMapping[str, set[str]] = {}
    for edge_id, witnesses in obligations.items():
        for release in witnesses:
            coverage.setdefault(release, set()).add(edge_id)
    return {release: frozenset(edges) for release, edges in coverage.items()}


def _signature_quotient(
    problem: _Problem,
) -> tuple[dict[str, frozenset[str]], dict[str, int], int, int, int]:
    """Retain at most ``max demand`` cheapest releases per coverage signature.

    Releases with an identical obligation-incidence vector are interchangeable for
    feasibility.  Selecting more than the maximum edge demand from one signature can
    never add useful coverage, so an optimum exists among the retained releases.
    """

    coverage = _coverage_index(problem.obligations)
    groups: MutableMapping[tuple[str, ...], list[str]] = {}
    for release in problem.releases:
        signature = tuple(sorted(coverage[release]))
        groups.setdefault(signature, []).append(release)
    cap = max(problem.demands.values())
    retained: set[str] = set()
    for releases in groups.values():
        ranked = sorted(releases, key=lambda item: (problem.costs[item], item))
        retained.update(ranked[:cap])
    obligations = {
        edge_id: frozenset(witnesses.intersection(retained))
        for edge_id, witnesses in problem.obligations.items()
    }
    costs = {release: problem.costs[release] for release in sorted(retained)}
    return obligations, costs, len(groups), len(groups), len(problem.releases) - len(retained)


def _propagate_forced(
    obligations: Mapping[str, frozenset[str]],
    demands: Mapping[str, int],
    costs: Mapping[str, int],
) -> tuple[
    dict[str, frozenset[str]],
    dict[str, int],
    dict[str, int],
    tuple[str, ...],
    int,
]:
    residual = dict(demands)
    available = set(costs)
    forced: set[str] = set()

    while True:
        newly_forced: set[str] = set()
        for edge_id in sorted(residual):
            demand = residual[edge_id]
            if demand <= 0:
                continue
            candidates = obligations[edge_id].intersection(available)
            if len(candidates) < demand:
                raise InfeasibleSuiteProblem(f"kernelization made edge {edge_id!r} infeasible")
            if len(candidates) == demand:
                newly_forced.update(candidates)
        newly_forced.difference_update(forced)
        if not newly_forced:
            break
        for release in sorted(newly_forced):
            forced.add(release)
            available.discard(release)
            for edge_id, witnesses in obligations.items():
                if residual[edge_id] > 0 and release in witnesses:
                    residual[edge_id] -= 1

    residual_obligations = {
        edge_id: frozenset(obligations[edge_id].intersection(available))
        for edge_id in sorted(obligations)
        if residual[edge_id] > 0
    }
    residual_demands = {edge_id: residual[edge_id] for edge_id in residual_obligations}
    residual_releases = (
        set().union(*residual_obligations.values()) if residual_obligations else set()
    )
    residual_costs = {release: costs[release] for release in sorted(residual_releases)}
    satisfied_edges = len(obligations) - len(residual_obligations)
    return (
        residual_obligations,
        residual_demands,
        residual_costs,
        tuple(sorted(forced)),
        satisfied_edges,
    )


def _remove_redundant_rows(
    obligations: Mapping[str, frozenset[str]],
    demands: Mapping[str, int],
) -> tuple[dict[str, frozenset[str]], dict[str, int], int]:
    """Delete obligations implied by a tighter retained obligation.

    If ``W_a subseteq W_b`` and ``d_a >= d_b``, satisfying ``a`` necessarily
    satisfies ``b``. Equal rows are resolved by edge identifier for determinism.
    """

    retained: list[str] = []
    redundant: set[str] = set()
    order = sorted(
        obligations,
        key=lambda edge_id: (
            len(obligations[edge_id]),
            -demands[edge_id],
            edge_id,
        ),
    )
    for edge_id in order:
        witnesses = obligations[edge_id]
        demand = demands[edge_id]
        implied = False
        for retained_id in retained:
            retained_witnesses = obligations[retained_id]
            retained_demand = demands[retained_id]
            if retained_witnesses.issubset(witnesses) and retained_demand >= demand:
                implied = True
                break
        if implied:
            redundant.add(edge_id)
        else:
            retained.append(edge_id)
    return (
        {edge_id: obligations[edge_id] for edge_id in retained},
        {edge_id: demands[edge_id] for edge_id in retained},
        len(redundant),
    )


def _components(
    obligations: Mapping[str, frozenset[str]],
) -> tuple[tuple[str, ...], ...]:
    if not obligations:
        return ()
    coverage = _coverage_index(obligations)
    unseen = set(obligations)
    components: list[tuple[str, ...]] = []
    while unseen:
        root = min(unseen)
        unseen.remove(root)
        stack = [root]
        component = {root}
        while stack:
            edge_id = stack.pop()
            neighbors: set[str] = set()
            for release in obligations[edge_id]:
                neighbors.update(coverage[release])
            for neighbor in sorted(neighbors.intersection(unseen)):
                unseen.remove(neighbor)
                component.add(neighbor)
                stack.append(neighbor)
        components.append(tuple(sorted(component)))
    return tuple(sorted(components, key=lambda rows: rows[0]))


@dataclass(frozen=True)
class _Kernel:
    obligations: dict[str, frozenset[str]]
    demands: dict[str, int]
    costs: dict[str, int]
    forced: tuple[str, ...]
    components: tuple[tuple[str, ...], ...]
    stats: KernelStats


def _kernelize(problem: _Problem) -> _Kernel:
    quotient_obligations, quotient_costs, original_signatures, retained_signatures, pruned = (
        _signature_quotient(problem)
    )
    (
        residual_obligations,
        residual_demands,
        residual_costs,
        forced,
        forced_satisfied,
    ) = _propagate_forced(quotient_obligations, problem.demands, quotient_costs)
    reduced_obligations, reduced_demands, redundant = _remove_redundant_rows(
        residual_obligations, residual_demands
    )
    residual_releases = set().union(*reduced_obligations.values()) if reduced_obligations else set()
    reduced_costs = {release: residual_costs[release] for release in sorted(residual_releases)}
    original_components = _components(problem.obligations)
    components = _components(reduced_obligations)
    state_space = 1
    for edge_id in reduced_demands:
        state_space *= reduced_demands[edge_id] + 1
    stats = KernelStats(
        original_edges=len(problem.obligations),
        original_releases=len(problem.releases),
        residual_edges=len(reduced_obligations),
        residual_releases=len(reduced_costs),
        original_signatures=original_signatures,
        retained_signatures=retained_signatures,
        signature_pruned_releases=pruned,
        forced_releases=forced,
        forced_cost=sum(problem.costs[release] for release in forced),
        forced_satisfied_edges=forced_satisfied,
        redundant_edges=redundant,
        original_components=len(original_components),
        residual_components=len(components),
        state_space_upper_bound=state_space,
    )
    return _Kernel(
        reduced_obligations,
        reduced_demands,
        reduced_costs,
        forced,
        components,
        stats,
    )


def _edge_assignments(
    problem: _Problem,
    selected: Iterable[str],
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    selected_set = set(selected)
    rows: list[tuple[str, tuple[str, ...]]] = []
    for edge_id in sorted(problem.obligations):
        witnesses = sorted(problem.obligations[edge_id].intersection(selected_set))
        demand = problem.demands[edge_id]
        if len(witnesses) < demand:
            raise AssertionError(f"selected suite does not satisfy edge {edge_id}")
        rows.append((edge_id, tuple(witnesses[:demand])))
    return tuple(rows)


def _selected_cost(problem: _Problem, selected: Iterable[str]) -> int:
    return sum(problem.costs[release] for release in set(selected))


def _certificate(
    *,
    problem: _Problem,
    algorithm: str,
    status: str,
    selected: Sequence[str],
    lower_bound: int,
    explored_nodes: int,
    proof_kind: str,
    kernel: KernelStats,
    component_proofs: Sequence[ComponentProof],
    approximation_factor_bound: float | None = None,
) -> SuiteCertificate:
    selected_tuple = tuple(sorted(set(selected)))
    upper_bound = _selected_cost(problem, selected_tuple)
    if lower_bound > upper_bound:
        raise AssertionError("solver produced an invalid bound interval")
    return SuiteCertificate(
        solver_version=SOLVER_VERSION,
        algorithm=algorithm,
        status=status,
        selected_releases=selected_tuple,
        edge_witnesses=_edge_assignments(problem, selected_tuple),
        obligation_sha256=problem.digest,
        lower_bound=lower_bound,
        upper_bound=upper_bound,
        explored_nodes=explored_nodes,
        proof_kind=proof_kind,
        approximation_factor_bound=approximation_factor_bound,
        kernel=kernel,
        component_proofs=tuple(component_proofs),
    )


def _harmonic(number: int) -> float:
    return sum(1.0 / index for index in range(1, number + 1)) if number else 1.0


def _greedy_component(
    obligations: Mapping[str, frozenset[str]],
    demands: Mapping[str, int],
    costs: Mapping[str, int],
) -> tuple[str, ...]:
    residual = dict(demands)
    available = set(costs)
    selected: list[str] = []
    coverage = _coverage_index(obligations)
    while any(value > 0 for value in residual.values()):
        gains: dict[str, int] = {}
        for release in available:
            gains[release] = sum(
                1 for edge_id in coverage.get(release, ()) if residual.get(edge_id, 0) > 0
            )
        candidates = [release for release, gain in gains.items() if gain > 0]
        if not candidates:
            raise InfeasibleSuiteProblem("no release can satisfy residual demand")
        release = min(
            candidates,
            key=lambda candidate: (
                -Fraction(gains[candidate], costs[candidate]),
                costs[candidate],
                candidate,
            ),
        )
        selected.append(release)
        available.remove(release)
        for edge_id in coverage.get(release, ()):
            if residual.get(edge_id, 0) > 0:
                residual[edge_id] -= 1
    return tuple(selected)


def _component_problem(
    kernel: _Kernel, component: tuple[str, ...]
) -> tuple[dict[str, frozenset[str]], dict[str, int], dict[str, int]]:
    obligations = {edge_id: kernel.obligations[edge_id] for edge_id in component}
    demands = {edge_id: kernel.demands[edge_id] for edge_id in component}
    releases = set().union(*obligations.values())
    costs = {release: kernel.costs[release] for release in sorted(releases)}
    return obligations, demands, costs


def _lower_bound(
    obligations: Mapping[str, frozenset[str]],
    edge_order: tuple[str, ...],
    residual: tuple[int, ...],
    available: frozenset[str],
    costs: Mapping[str, int],
) -> int | None:
    per_edge: dict[str, tuple[int, frozenset[str]]] = {}
    maximum = 0
    for index, edge_id in enumerate(edge_order):
        demand = residual[index]
        if demand <= 0:
            continue
        candidates = frozenset(obligations[edge_id].intersection(available))
        if len(candidates) < demand:
            return None
        cheapest = sorted(costs[release] for release in candidates)[:demand]
        edge_bound = sum(cheapest)
        maximum = max(maximum, edge_bound)
        per_edge[edge_id] = (edge_bound, candidates)

    # A deterministic disjoint-witness packing strengthens the max-of-rows bound.
    used: set[str] = set()
    packed = 0
    for edge_id in sorted(
        per_edge,
        key=lambda item: (
            len(per_edge[item][1]),
            -per_edge[item][0],
            item,
        ),
    ):
        edge_bound, candidates = per_edge[edge_id]
        if candidates.isdisjoint(used):
            packed += edge_bound
            used.update(candidates)
    return max(maximum, packed)


def _residual_after_select(
    edge_order: tuple[str, ...],
    obligations: Mapping[str, frozenset[str]],
    residual: tuple[int, ...],
    release: str,
) -> tuple[int, ...]:
    return tuple(
        max(0, residual[index] - (1 if release in obligations[edge_id] else 0))
        for index, edge_id in enumerate(edge_order)
    )


def _propagate_node(
    obligations: Mapping[str, frozenset[str]],
    edge_order: tuple[str, ...],
    costs: Mapping[str, int],
    selected: tuple[str, ...],
    selected_cost: int,
    available: frozenset[str],
    residual: tuple[int, ...],
) -> tuple[tuple[str, ...], int, frozenset[str], tuple[int, ...]] | None:
    selected_set = set(selected)
    available_set = set(available)
    residual_list = list(residual)
    while True:
        forced: set[str] = set()
        for index, edge_id in enumerate(edge_order):
            demand = residual_list[index]
            if demand <= 0:
                continue
            candidates = obligations[edge_id].intersection(available_set)
            if len(candidates) < demand:
                return None
            if len(candidates) == demand:
                forced.update(candidates)
        forced.difference_update(selected_set)
        if not forced:
            break
        for release in sorted(forced):
            if release not in available_set:
                continue
            selected_set.add(release)
            available_set.remove(release)
            selected_cost += costs[release]
            for index, edge_id in enumerate(edge_order):
                if residual_list[index] > 0 and release in obligations[edge_id]:
                    residual_list[index] -= 1
    return (
        tuple(sorted(selected_set)),
        selected_cost,
        frozenset(available_set),
        tuple(residual_list),
    )


@dataclass(frozen=True)
class _ComponentResult:
    selected: tuple[str, ...]
    lower_bound: int
    upper_bound: int
    explored_nodes: int
    exact: bool
    proof_kind: str


def _solve_component_dp(
    obligations: Mapping[str, frozenset[str]],
    demands: Mapping[str, int],
    costs: Mapping[str, int],
) -> _ComponentResult:
    edge_order = tuple(sorted(obligations))
    target = tuple(demands[edge_id] for edge_id in edge_order)
    zero = tuple(0 for _ in edge_order)
    # value = (cost, canonical selected tuple)
    states: dict[tuple[int, ...], tuple[int, tuple[str, ...]]] = {zero: (0, ())}
    explored = 0
    for release in sorted(costs):
        snapshot = list(states.items())
        for state, (state_cost, selected) in snapshot:
            explored += 1
            next_state = tuple(
                min(
                    target[index],
                    state[index] + (1 if release in obligations[edge_id] else 0),
                )
                for index, edge_id in enumerate(edge_order)
            )
            if next_state == state:
                continue
            candidate = (state_cost + costs[release], (*selected, release))
            incumbent = states.get(next_state)
            if incumbent is None or candidate < incumbent:
                states[next_state] = candidate
    if target not in states:
        raise InfeasibleSuiteProblem("dynamic program found no feasible suite")
    cost, selected = states[target]
    return _ComponentResult(
        selected=selected,
        lower_bound=cost,
        upper_bound=cost,
        explored_nodes=explored,
        exact=True,
        proof_kind="DYNAMIC_PROGRAMMING_EXHAUSTIVE",
    )


def _solve_component_bnb(
    obligations: Mapping[str, frozenset[str]],
    demands: Mapping[str, int],
    costs: Mapping[str, int],
    *,
    max_nodes: int | None,
) -> _ComponentResult:
    edge_order = tuple(sorted(obligations))
    initial_residual = tuple(demands[edge_id] for edge_id in edge_order)
    all_releases = frozenset(costs)
    greedy = tuple(sorted(_greedy_component(obligations, demands, costs)))
    incumbent = greedy
    incumbent_cost = sum(costs[release] for release in incumbent)

    root_propagated = _propagate_node(
        obligations,
        edge_order,
        costs,
        (),
        0,
        all_releases,
        initial_residual,
    )
    if root_propagated is None:
        raise InfeasibleSuiteProblem("branch-and-bound root is infeasible")
    root_selected, root_cost, root_available, root_residual = root_propagated
    root_extra = _lower_bound(obligations, edge_order, root_residual, root_available, costs)
    if root_extra is None:
        raise InfeasibleSuiteProblem("branch-and-bound root has no completion")

    # Heap entry: lower bound, selected cost, selected tuple, available tuple,
    # residual tuple.  Tuples make tie-breaking deterministic.
    heap: list[tuple[int, int, tuple[str, ...], tuple[str, ...], tuple[int, ...]]] = []
    heapq.heappush(
        heap,
        (
            root_cost + root_extra,
            root_cost,
            root_selected,
            tuple(sorted(root_available)),
            root_residual,
        ),
    )
    explored = 0

    while heap and (max_nodes is None or explored < max_nodes):
        node_lb, selected_cost, selected, available_tuple, residual = heapq.heappop(heap)
        if node_lb >= incumbent_cost:
            # Equality is enough to prove the current incumbent's cost optimal.
            continue
        explored += 1
        if all(value == 0 for value in residual):
            incumbent_cost, incumbent = min((incumbent_cost, incumbent), (selected_cost, selected))
            continue

        available = frozenset(available_tuple)
        unsatisfied = [
            (index, edge_id) for index, edge_id in enumerate(edge_order) if residual[index] > 0
        ]
        pivot_index, pivot = min(
            unsatisfied,
            key=lambda pair: (
                len(obligations[pair[1]].intersection(available)) - residual[pair[0]],
                len(obligations[pair[1]].intersection(available)),
                -residual[pair[0]],
                pair[1],
            ),
        )
        pivot_candidates = obligations[pivot].intersection(available)
        if len(pivot_candidates) < residual[pivot_index]:
            continue

        gains = {
            release: sum(
                1
                for index, edge_id in unsatisfied
                if release in obligations[edge_id] and residual[index] > 0
            )
            for release in pivot_candidates
        }
        branch_release = min(
            pivot_candidates,
            key=lambda release: (
                -Fraction(gains[release], costs[release]),
                costs[release],
                release,
            ),
        )

        # Include branch first; priority queue still orders globally by lower bound.
        include_residual = _residual_after_select(edge_order, obligations, residual, branch_release)
        include_selected = tuple(sorted((*selected, branch_release)))
        include_available = frozenset(available - {branch_release})
        include = _propagate_node(
            obligations,
            edge_order,
            costs,
            include_selected,
            selected_cost + costs[branch_release],
            include_available,
            include_residual,
        )
        branches = [include]
        exclude = _propagate_node(
            obligations,
            edge_order,
            costs,
            selected,
            selected_cost,
            frozenset(available - {branch_release}),
            residual,
        )
        branches.append(exclude)

        for propagated in branches:
            if propagated is None:
                continue
            child_selected, child_cost, child_available, child_residual = propagated
            if child_cost >= incumbent_cost:
                continue
            if all(value == 0 for value in child_residual):
                incumbent_cost, incumbent = min(
                    (incumbent_cost, incumbent), (child_cost, child_selected)
                )
                continue
            extra = _lower_bound(
                obligations,
                edge_order,
                child_residual,
                child_available,
                costs,
            )
            if extra is None:
                continue
            child_lb = child_cost + extra
            if child_lb >= incumbent_cost:
                continue
            heapq.heappush(
                heap,
                (
                    child_lb,
                    child_cost,
                    child_selected,
                    tuple(sorted(child_available)),
                    child_residual,
                ),
            )

    if not heap:
        return _ComponentResult(
            incumbent,
            incumbent_cost,
            incumbent_cost,
            explored,
            True,
            "BEST_FIRST_BRANCH_AND_BOUND_CLOSED",
        )
    global_lower = min(entry[0] for entry in heap)
    return _ComponentResult(
        incumbent,
        min(global_lower, incumbent_cost),
        incumbent_cost,
        explored,
        False,
        "BEST_FIRST_BRANCH_AND_BOUND_FRONTIER",
    )


def solve_greedy(
    obligations: Mapping[str, Iterable[str]],
    *,
    demands: Mapping[str, int] | None = None,
    costs: Mapping[str, int] | None = None,
) -> SuiteCertificate:
    """Construct a deterministic weighted multicover suite.

    The marginal-gain-per-cost rule is the standard greedy algorithm for integral
    submodular cover and has a ``H_Q`` guarantee, where ``Q`` is total demand.
    """

    problem = _normalize_problem(obligations, demands=demands, costs=costs)
    kernel = _kernelize(problem)
    selected = list(kernel.forced)
    lower = kernel.stats.forced_cost
    component_proofs: list[ComponentProof] = []
    for component in kernel.components:
        component_obligations, component_demands, component_costs = _component_problem(
            kernel, component
        )
        chosen = _greedy_component(component_obligations, component_demands, component_costs)
        selected.extend(chosen)
        edge_order = tuple(sorted(component_obligations))
        residual = tuple(component_demands[edge] for edge in edge_order)
        bound = _lower_bound(
            component_obligations,
            edge_order,
            residual,
            frozenset(component_costs),
            component_costs,
        )
        lower += 0 if bound is None else bound
        chosen_cost = sum(component_costs[release] for release in chosen)
        component_proofs.append(
            ComponentProof(
                edge_ids=component,
                selected_releases=tuple(sorted(chosen)),
                lower_bound=0 if bound is None else bound,
                upper_bound=chosen_cost,
                explored_nodes=0,
                node_budget=None,
                exact=False,
                proof_kind="HARMONIC_SUBMODULAR_COVER_BOUND",
            )
        )
    total_demand = sum(problem.demands.values())
    return _certificate(
        problem=problem,
        algorithm="SIGNATURE_KERNEL_WEIGHTED_GREEDY_MULTICOVER",
        status="HEURISTIC",
        selected=selected,
        lower_bound=min(lower, _selected_cost(problem, selected)),
        explored_nodes=0,
        proof_kind="HARMONIC_SUBMODULAR_COVER_BOUND",
        approximation_factor_bound=_harmonic(total_demand),
        kernel=kernel.stats,
        component_proofs=component_proofs,
    )


def solve_exact(
    obligations: Mapping[str, Iterable[str]],
    *,
    demands: Mapping[str, int] | None = None,
    costs: Mapping[str, int] | None = None,
    max_nodes: int | None = None,
    method: str = "auto",
    dp_state_limit: int = 1_000_000,
) -> SuiteCertificate:
    """Solve weighted redundant action separation exactly or with certified bounds.

    ``auto`` uses an exhaustive demand-state dynamic program when the component state
    space is small and no node budget is requested; otherwise it uses deterministic
    best-first branch-and-bound. A finite node budget returns a replayable ``BOUNDED``
    certificate with the minimum remaining frontier bound.
    """

    if method not in {"auto", "dp", "bnb"}:
        raise ValueError("method must be one of: auto, dp, bnb")
    if max_nodes is not None and max_nodes < 0:
        raise ValueError("max_nodes must be non-negative")
    if dp_state_limit < 1:
        raise ValueError("dp_state_limit must be positive")

    problem = _normalize_problem(obligations, demands=demands, costs=costs)
    kernel = _kernelize(problem)
    selected = list(kernel.forced)
    total_lower = kernel.stats.forced_cost
    total_upper = kernel.stats.forced_cost
    explored = 0
    exact = True
    proof_kinds: list[str] = []
    component_proofs: list[ComponentProof] = []
    remaining_nodes = max_nodes

    for component in kernel.components:
        component_obligations, component_demands, component_costs = _component_problem(
            kernel, component
        )
        state_space = math.prod(component_demands[edge_id] + 1 for edge_id in component_demands)
        use_dp = method == "dp" or (
            method == "auto" and max_nodes is None and state_space <= dp_state_limit
        )
        component_node_budget = None if use_dp else remaining_nodes
        if use_dp:
            result = _solve_component_dp(component_obligations, component_demands, component_costs)
        else:
            result = _solve_component_bnb(
                component_obligations,
                component_demands,
                component_costs,
                max_nodes=remaining_nodes,
            )
        selected.extend(result.selected)
        total_lower += result.lower_bound
        total_upper += result.upper_bound
        explored += result.explored_nodes
        exact = exact and result.exact
        proof_kinds.append(result.proof_kind)
        component_proofs.append(
            ComponentProof(
                edge_ids=component,
                selected_releases=result.selected,
                lower_bound=result.lower_bound,
                upper_bound=result.upper_bound,
                explored_nodes=result.explored_nodes,
                node_budget=component_node_budget,
                exact=result.exact,
                proof_kind=result.proof_kind,
            )
        )
        if remaining_nodes is not None:
            remaining_nodes = max(0, remaining_nodes - result.explored_nodes)

    # Defensive check against accidental component-cost accounting drift.
    actual_upper = _selected_cost(problem, selected)
    if actual_upper != total_upper:
        raise RuntimeError(
            f"component upper bounds sum to {total_upper}, selected cost is {actual_upper}"
        )
    status = "EXACT" if exact else "BOUNDED"
    if exact:
        total_lower = total_upper
    algorithm = (
        "SIGNATURE_KERNEL_COMPONENT_DP"
        if proof_kinds and all(kind == "DYNAMIC_PROGRAMMING_EXHAUSTIVE" for kind in proof_kinds)
        else "SIGNATURE_KERNEL_COMPONENT_HYBRID_EXACT"
    )
    return _certificate(
        problem=problem,
        algorithm=algorithm,
        status=status,
        selected=selected,
        lower_bound=total_lower,
        explored_nodes=explored,
        proof_kind="+".join(proof_kinds) if proof_kinds else "FORCED_KERNEL_ONLY",
        kernel=kernel.stats,
        component_proofs=component_proofs,
    )


def _verify_certificate_header(
    problem: _Problem,
    certificate: SuiteCertificate,
) -> tuple[set[str], list[str]]:
    errors: list[str] = []
    if certificate.obligation_sha256 != problem.digest:
        errors.append("problem digest mismatch")
    if certificate.solver_version != SOLVER_VERSION:
        errors.append(
            f"unsupported solver version: {certificate.solver_version!r}; "
            f"expected {SOLVER_VERSION!r}"
        )
    selected_tuple = certificate.selected_releases
    selected = set(selected_tuple)
    if len(selected) != len(selected_tuple):
        errors.append("selected release list contains duplicates")
    unknown = selected - set(problem.releases)
    if unknown:
        errors.append(f"selected release list contains unknown values: {sorted(unknown)}")
    expected_cost = sum(problem.costs[release] for release in selected if release in problem.costs)
    if certificate.upper_bound != expected_cost:
        errors.append("upper bound does not equal selected execution cost")
    if certificate.lower_bound < 0 or certificate.lower_bound > certificate.upper_bound:
        errors.append("invalid lower/upper bound interval")
    return selected, errors


def _verify_proof_identity(certificate: SuiteCertificate) -> list[str]:
    errors: list[str] = []
    expected_proof_kind = (
        "+".join(row.proof_kind for row in certificate.component_proofs)
        if certificate.component_proofs
        else "FORCED_KERNEL_ONLY"
    )
    if certificate.status == "HEURISTIC":
        expected_proof_kind = "HARMONIC_SUBMODULAR_COVER_BOUND"
    if certificate.proof_kind != expected_proof_kind:
        errors.append("global proof kind does not recompose from component proof kinds")
    if certificate.status == "HEURISTIC":
        if certificate.algorithm != "SIGNATURE_KERNEL_WEIGHTED_GREEDY_MULTICOVER":
            errors.append("heuristic certificate has an unexpected algorithm identifier")
        if any(
            row.proof_kind != "HARMONIC_SUBMODULAR_COVER_BOUND"
            for row in certificate.component_proofs
        ):
            errors.append("heuristic certificate contains a non-greedy component proof")
    elif certificate.algorithm not in {
        "SIGNATURE_KERNEL_COMPONENT_DP",
        "SIGNATURE_KERNEL_COMPONENT_HYBRID_EXACT",
    }:
        errors.append("exact/bounded certificate has an unexpected algorithm identifier")
    return errors


def _verify_witness_assignments(
    problem: _Problem,
    certificate: SuiteCertificate,
    selected: set[str],
) -> list[str]:
    errors: list[str] = []
    rows = dict(certificate.edge_witnesses)
    if len(rows) != len(certificate.edge_witnesses):
        errors.append("duplicate edge identifiers in witness assignments")
    if set(rows) != set(problem.obligations):
        errors.append("witness assignments do not match the obligation set")
    for edge_id, witnesses in problem.obligations.items():
        assigned = rows.get(edge_id, ())
        if len(assigned) != problem.demands[edge_id]:
            errors.append(
                f"edge {edge_id} has {len(assigned)} assigned witnesses; "
                f"expected {problem.demands[edge_id]}"
            )
        if len(set(assigned)) != len(assigned):
            errors.append(f"edge {edge_id} repeats an assigned witness")
        for release in assigned:
            if release not in selected:
                errors.append(f"edge {edge_id} maps to an unselected release")
            if release not in witnesses:
                errors.append(f"edge {edge_id} maps to a non-witness release")
        if len(witnesses.intersection(selected)) < problem.demands[edge_id]:
            errors.append(f"selected suite does not satisfy edge {edge_id}")
    return errors


def _verify_status(
    problem: _Problem,
    certificate: SuiteCertificate,
    *,
    verify_optimality: bool,
    prior_errors: Sequence[str],
) -> list[str]:
    errors: list[str] = []
    if certificate.status == "EXACT":
        if certificate.lower_bound != certificate.upper_bound:
            errors.append("exact certificate has a nonzero optimality gap")
        if verify_optimality and not prior_errors and not errors:
            try:
                oracle = solve_independent_oracle(
                    problem.obligations,
                    demands=problem.demands,
                    costs=problem.costs,
                )
            except Exception as exc:
                errors.append(f"independent optimality replay failed: {type(exc).__name__}: {exc}")
            else:
                if oracle.optimal_cost != certificate.upper_bound:
                    errors.append(
                        "independent oracle disagrees with claimed optimum: "
                        f"oracle={oracle.optimal_cost}, certificate={certificate.upper_bound}"
                    )
    elif certificate.status not in {"BOUNDED", "HEURISTIC"}:
        errors.append(f"unknown certificate status: {certificate.status}")
    return errors


def _replay_greedy_component(
    obligations: Mapping[str, frozenset[str]],
    demands: Mapping[str, int],
    costs: Mapping[str, int],
) -> _ComponentResult:
    selected = tuple(sorted(_greedy_component(obligations, demands, costs)))
    edge_order = tuple(sorted(obligations))
    residual = tuple(demands[edge_id] for edge_id in edge_order)
    lower = _lower_bound(
        obligations,
        edge_order,
        residual,
        frozenset(costs),
        costs,
    )
    return _ComponentResult(
        selected=selected,
        lower_bound=0 if lower is None else lower,
        upper_bound=sum(costs[release] for release in selected),
        explored_nodes=0,
        exact=False,
        proof_kind="HARMONIC_SUBMODULAR_COVER_BOUND",
    )


def _replay_component(
    kernel: _Kernel,
    component: tuple[str, ...],
    proof: ComponentProof,
) -> _ComponentResult:
    obligations, demands, costs = _component_problem(kernel, component)
    if proof.proof_kind == "DYNAMIC_PROGRAMMING_EXHAUSTIVE":
        return _solve_component_dp(obligations, demands, costs)
    if proof.proof_kind in {
        "BEST_FIRST_BRANCH_AND_BOUND_CLOSED",
        "BEST_FIRST_BRANCH_AND_BOUND_FRONTIER",
    }:
        return _solve_component_bnb(
            obligations,
            demands,
            costs,
            max_nodes=proof.node_budget,
        )
    if proof.proof_kind == "HARMONIC_SUBMODULAR_COVER_BOUND":
        return _replay_greedy_component(obligations, demands, costs)
    raise ValueError(f"unsupported proof kind: {proof.proof_kind}")


def _component_local_errors(
    problem: _Problem,
    kernel: _Kernel,
    component: tuple[str, ...],
    proof: ComponentProof,
    index: int,
) -> list[str]:
    errors: list[str] = []
    if len(set(proof.edge_ids)) != len(proof.edge_ids):
        errors.append(f"component {index} repeats an edge identifier")
    if len(set(proof.selected_releases)) != len(proof.selected_releases):
        errors.append(f"component {index} repeats a selected release")
    if proof.lower_bound < 0 or proof.lower_bound > proof.upper_bound:
        errors.append(f"component {index} has an invalid bound interval")
    if proof.exact and proof.lower_bound != proof.upper_bound:
        errors.append(f"component {index} is exact with a nonzero gap")
    expected_cost = sum(
        problem.costs[release] for release in proof.selected_releases if release in problem.costs
    )
    if expected_cost != proof.upper_bound:
        errors.append(f"component {index} upper bound does not match its cost")
    component_releases = set().union(*(kernel.obligations[edge_id] for edge_id in component))
    outside = set(proof.selected_releases) - component_releases
    if outside:
        errors.append(
            f"component {index} selects releases outside its component: {sorted(outside)}"
        )
    try:
        replay = _replay_component(kernel, component, proof)
    except Exception as exc:
        errors.append(f"component {index} proof replay failed: {type(exc).__name__}: {exc}")
    else:
        expected = ComponentProof(
            edge_ids=component,
            selected_releases=replay.selected,
            lower_bound=replay.lower_bound,
            upper_bound=replay.upper_bound,
            explored_nodes=replay.explored_nodes,
            node_budget=proof.node_budget,
            exact=replay.exact,
            proof_kind=replay.proof_kind,
        )
        if proof != expected:
            errors.append(f"component {index} proof does not replay deterministically")
    return errors


def _verify_kernel_recomposition(
    problem: _Problem,
    certificate: SuiteCertificate,
    selected: set[str],
) -> list[str]:
    errors: list[str] = []
    try:
        kernel = _kernelize(problem)
    except Exception as exc:
        return [f"kernel replay failed: {type(exc).__name__}: {exc}"]
    if certificate.kernel != kernel.stats:
        errors.append("kernel statistics mismatch")
    proof_edges = tuple(row.edge_ids for row in certificate.component_proofs)
    if proof_edges != kernel.components:
        errors.append("component proofs do not match the replayed component partition")

    component_selected: set[str] = set()
    component_lower = kernel.stats.forced_cost
    component_upper = kernel.stats.forced_cost
    component_explored = 0
    for index, proof in enumerate(certificate.component_proofs):
        if index < len(kernel.components):
            errors.extend(
                _component_local_errors(
                    problem,
                    kernel,
                    kernel.components[index],
                    proof,
                    index,
                )
            )
        component_selected.update(proof.selected_releases)
        component_lower += proof.lower_bound
        component_upper += proof.upper_bound
        component_explored += proof.explored_nodes

    if component_selected.union(kernel.forced) != selected:
        errors.append("component and forced selections do not recompose the suite")
    if component_lower != certificate.lower_bound:
        errors.append("component lower bounds do not recompose the global bound")
    if component_upper != certificate.upper_bound:
        errors.append("component upper bounds do not recompose the global cost")
    if component_explored != certificate.explored_nodes:
        errors.append("component explored-node counts do not recompose globally")
    return errors


def verify_certificate(
    obligations: Mapping[str, Iterable[str]],
    certificate: SuiteCertificate,
    *,
    demands: Mapping[str, int] | None = None,
    costs: Mapping[str, int] | None = None,
    verify_optimality: bool = True,
) -> tuple[bool, tuple[str, ...]]:
    """Independently replay digest, feasibility, reductions, bounds, and optimality."""

    try:
        problem = _normalize_problem(obligations, demands=demands, costs=costs)
    except Exception as exc:
        return False, (f"problem normalization failed: {type(exc).__name__}: {exc}",)

    selected, errors = _verify_certificate_header(problem, certificate)
    errors.extend(_verify_proof_identity(certificate))
    errors.extend(_verify_witness_assignments(problem, certificate, selected))
    errors.extend(
        _verify_status(
            problem,
            certificate,
            verify_optimality=verify_optimality,
            prior_errors=errors,
        )
    )
    errors.extend(_verify_kernel_recomposition(problem, certificate, selected))
    return not errors, tuple(errors)
