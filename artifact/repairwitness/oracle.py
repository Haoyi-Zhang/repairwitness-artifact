"""Independent optimization oracles for action-separating suite problems.

This module intentionally does not import :mod:`repairwitness.suite`.  It provides a
second encoding of weighted set multicover, so agreement is meaningful evidence rather
than a call back into the implementation under test.  Small instances use an exhaustive
branch-and-bound enumerator; larger instances can use SciPy/HiGHS MILP.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from itertools import combinations
from math import inf


@dataclass(frozen=True)
class OracleResult:
    """An independently computed optimum."""

    selected_releases: tuple[str, ...]
    optimal_cost: int
    backend: str
    explored_subsets: int


def _normalise(
    obligations: Mapping[str, Iterable[str]],
    *,
    demands: Mapping[str, int] | None,
    costs: Mapping[str, int] | None,
) -> tuple[dict[str, frozenset[str]], dict[str, int], dict[str, int], tuple[str, ...]]:
    if not obligations:
        return {}, {}, {}, ()
    rows: dict[str, frozenset[str]] = {}
    for edge_id, raw in obligations.items():
        edge = str(edge_id)
        witnesses = frozenset(str(value) for value in raw)
        if not edge:
            raise ValueError("obligation identifiers must be non-empty")
        if not witnesses:
            raise ValueError(f"obligation {edge!r} has no witnesses")
        rows[edge] = witnesses
    release_tuple = tuple(sorted(set().union(*rows.values())))
    demand_map: dict[str, int] = {}
    for edge, witnesses in rows.items():
        raw_demand = 1 if demands is None else demands.get(edge, 1)
        if isinstance(raw_demand, bool):
            raise ValueError(f"demand for {edge!r} must be a positive integer")
        demand = int(raw_demand)
        if demand < 1:
            raise ValueError(f"demand for {edge!r} must be a positive integer")
        if demand > len(witnesses):
            raise ValueError(f"demand for {edge!r} exceeds its witness set")
        demand_map[edge] = demand
    cost_map: dict[str, int] = {}
    for release in release_tuple:
        raw_cost = 1 if costs is None else costs.get(release, 1)
        if isinstance(raw_cost, bool):
            raise ValueError(f"cost for {release!r} must be a positive integer")
        cost = int(raw_cost)
        if cost < 1:
            raise ValueError(f"cost for {release!r} must be a positive integer")
        cost_map[release] = cost
    if demands is not None:
        extra = set(demands) - set(rows)
        if extra:
            raise ValueError(f"demands contain unknown obligations: {sorted(extra)}")
    if costs is not None:
        extra = set(costs) - set(release_tuple)
        if extra:
            raise ValueError(f"costs contain unknown releases: {sorted(extra)}")
    return rows, demand_map, cost_map, release_tuple


def _feasible(
    selected: frozenset[str],
    obligations: Mapping[str, frozenset[str]],
    demands: Mapping[str, int],
) -> bool:
    return all(
        len(witnesses & selected) >= demands[edge] for edge, witnesses in obligations.items()
    )


def solve_exhaustive_oracle(
    obligations: Mapping[str, Iterable[str]],
    *,
    demands: Mapping[str, int] | None = None,
    costs: Mapping[str, int] | None = None,
    release_limit: int = 26,
) -> OracleResult:
    """Solve exactly by exhaustive cardinality layers with cost pruning.

    The routine is deliberately simple and independent.  It is used as a differential
    oracle, not as the primary algorithm.  Enumeration is deterministic across Python
    hash seeds and returns the lexicographically smallest optimum.
    """

    rows, demand_map, cost_map, releases = _normalise(obligations, demands=demands, costs=costs)
    if len(releases) > release_limit:
        raise ValueError(
            f"exhaustive oracle supports at most {release_limit} releases; got {len(releases)}"
        )
    if not rows:
        return OracleResult((), 0, "EXHAUSTIVE", 1)

    best_cost = inf
    best: tuple[str, ...] | None = None
    explored = 0
    min_cardinality = max(demand_map.values(), default=0)
    for width in range(min_cardinality, len(releases) + 1):
        for candidate in combinations(releases, width):
            candidate_cost = sum(cost_map[release] for release in candidate)
            if candidate_cost > best_cost:
                continue
            explored += 1
            if _feasible(frozenset(candidate), rows, demand_map) and (
                candidate_cost < best_cost
                or (candidate_cost == best_cost and (best is None or candidate < best))
            ):
                best_cost = candidate_cost
                best = candidate
    if best is None:
        raise ValueError("infeasible set-multicover problem")
    return OracleResult(best, int(best_cost), "EXHAUSTIVE", explored)


def solve_milp_oracle(
    obligations: Mapping[str, Iterable[str]],
    *,
    demands: Mapping[str, int] | None = None,
    costs: Mapping[str, int] | None = None,
) -> OracleResult:
    """Solve the independent binary MILP with SciPy/HiGHS."""

    rows, demand_map, cost_map, releases = _normalise(obligations, demands=demands, costs=costs)
    if not rows:
        return OracleResult((), 0, "SCIPY_HIGHS_MILP", 0)
    try:
        import numpy as np
        from scipy.optimize import Bounds, LinearConstraint, milp  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover - optional dependency path
        raise RuntimeError("SciPy solver extra is required for the MILP oracle") from exc

    edges = tuple(sorted(rows))
    matrix = np.zeros((len(edges), len(releases)), dtype=float)
    for edge_index, edge in enumerate(edges):
        for release_index, release in enumerate(releases):
            if release in rows[edge]:
                matrix[edge_index, release_index] = 1.0
    objective = np.array([cost_map[release] for release in releases], dtype=float)
    lower = np.array([demand_map[edge] for edge in edges], dtype=float)
    upper = np.full(len(edges), np.inf)
    result = milp(
        c=objective,
        integrality=np.ones(len(releases), dtype=int),
        bounds=Bounds(np.zeros(len(releases)), np.ones(len(releases))),
        constraints=LinearConstraint(matrix, lower, upper),
        options={"presolve": True},
    )
    if not bool(result.success) or result.x is None or result.fun is None:
        raise RuntimeError(f"HiGHS failed to solve the oracle model: {result.message}")
    selected = tuple(
        release for release, value in zip(releases, result.x, strict=True) if value >= 0.5
    )
    if not _feasible(frozenset(selected), rows, demand_map):
        raise RuntimeError("HiGHS returned an infeasible rounded solution")
    exact_cost = sum(cost_map[release] for release in selected)
    rounded_objective = round(float(result.fun))
    if exact_cost != rounded_objective:
        raise RuntimeError(
            f"HiGHS objective mismatch after integer replay: {rounded_objective} != {exact_cost}"
        )
    nodes = int(getattr(result, "mip_node_count", 0) or 0)
    return OracleResult(selected, exact_cost, "SCIPY_HIGHS_MILP", nodes)


def solve_independent_oracle(
    obligations: Mapping[str, Iterable[str]],
    *,
    demands: Mapping[str, int] | None = None,
    costs: Mapping[str, int] | None = None,
    exhaustive_release_limit: int = 22,
) -> OracleResult:
    """Choose the independent exhaustive or MILP backend deterministically."""

    release_count = len({str(r) for values in obligations.values() for r in values})
    if release_count <= exhaustive_release_limit:
        return solve_exhaustive_oracle(
            obligations,
            demands=demands,
            costs=costs,
            release_limit=exhaustive_release_limit,
        )
    return solve_milp_oracle(obligations, demands=demands, costs=costs)
