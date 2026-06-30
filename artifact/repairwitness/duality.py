"""Exact-arithmetic LP-dual certificates for weighted action separation.

For obligations ``e`` with demand ``d_e`` and releases ``r`` with cost ``c_r``,
RepairWitness uses the relaxation

    min  sum_r c_r x_r
    s.t. sum_{r in W_e} x_r >= d_e, x_r >= 0.

Its dual is

    max  sum_e d_e y_e
    s.t. sum_{e: r in W_e} y_e <= c_r, y_e >= 0.

The relaxation permits repeated/fractional releases, so every dual-feasible objective is
a sound lower bound on the binary multicover optimum.  Certificates serialize rational
weights and are checked without trusting a numerical solver.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from fractions import Fraction

from .canonical import canonical_json_bytes, sha256_bytes


@dataclass(frozen=True)
class DualProblem:
    obligations: dict[str, frozenset[str]]
    demands: dict[str, int]
    costs: dict[str, int]
    releases: tuple[str, ...]
    digest: str


@dataclass(frozen=True)
class DualCertificate:
    """A digest-bound feasible solution of the multicover LP dual."""

    problem_sha256: str
    backend: str
    edge_weights: tuple[tuple[str, Fraction], ...]
    objective: Fraction
    integer_lower_bound: int

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "problem_sha256": self.problem_sha256,
            "backend": self.backend,
            "edge_weights": [
                {
                    "edge_id": edge,
                    "numerator": weight.numerator,
                    "denominator": weight.denominator,
                }
                for edge, weight in self.edge_weights
            ],
            "objective": {
                "numerator": self.objective.numerator,
                "denominator": self.objective.denominator,
            },
            "integer_lower_bound": self.integer_lower_bound,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> DualCertificate:
        raw_rows = value.get("edge_weights")
        if not isinstance(raw_rows, list):
            raise ValueError("edge_weights must be a JSON array")
        rows: list[tuple[str, Fraction]] = []
        for raw in raw_rows:
            if not isinstance(raw, Mapping):
                raise ValueError("edge_weights entries must be JSON objects")
            numerator = _strict_int(raw.get("numerator"), "edge weight numerator")
            denominator = _strict_int(raw.get("denominator"), "edge weight denominator")
            if denominator <= 0:
                raise ValueError("edge weight denominator must be positive")
            rows.append((str(raw.get("edge_id")), Fraction(numerator, denominator)))
        objective_raw = value.get("objective")
        if not isinstance(objective_raw, Mapping):
            raise ValueError("objective must be a JSON object")
        objective = Fraction(
            _strict_int(objective_raw.get("numerator"), "objective numerator"),
            _strict_int(objective_raw.get("denominator"), "objective denominator"),
        )
        return cls(
            problem_sha256=str(value.get("problem_sha256")),
            backend=str(value.get("backend")),
            edge_weights=tuple(rows),
            objective=objective,
            integer_lower_bound=_strict_int(
                value.get("integer_lower_bound"), "integer_lower_bound"
            ),
        )


def _strict_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be an integer")
    return value


def normalize_dual_problem(
    obligations: Mapping[str, Iterable[str]],
    *,
    demands: Mapping[str, int] | None = None,
    costs: Mapping[str, int] | None = None,
) -> DualProblem:
    rows: dict[str, frozenset[str]] = {}
    for raw_edge, raw_witnesses in obligations.items():
        edge = str(raw_edge)
        if not edge:
            raise ValueError("edge identifiers must be non-empty")
        witnesses = frozenset(str(item) for item in raw_witnesses)
        if not witnesses:
            raise ValueError(f"edge {edge!r} has no witnesses")
        rows[edge] = witnesses
    releases = tuple(sorted(set().union(*rows.values()))) if rows else ()
    demand_map: dict[str, int] = {}
    for edge, witnesses in rows.items():
        raw = 1 if demands is None else demands.get(edge, 1)
        demand = _strict_int(raw, f"demand for {edge}")
        if demand < 1 or demand > len(witnesses):
            raise ValueError(f"demand for {edge!r} must be in [1, {len(witnesses)}]")
        demand_map[edge] = demand
    if demands is not None and set(demands) - set(rows):
        raise ValueError("demands contain unknown edges")
    cost_map: dict[str, int] = {}
    for release in releases:
        raw = 1 if costs is None else costs.get(release, 1)
        cost = _strict_int(raw, f"cost for {release}")
        if cost < 1:
            raise ValueError(f"cost for {release!r} must be positive")
        cost_map[release] = cost
    if costs is not None and set(costs) - set(releases):
        raise ValueError("costs contain unknown releases")
    payload = {
        "obligations": {edge: sorted(rows[edge]) for edge in sorted(rows)},
        "demands": {edge: demand_map[edge] for edge in sorted(demand_map)},
        "costs": {release: cost_map[release] for release in releases},
    }
    return DualProblem(
        obligations=rows,
        demands=demand_map,
        costs=cost_map,
        releases=releases,
        digest=sha256_bytes(canonical_json_bytes(payload)),
    )


def _objective(problem: DualProblem, weights: Mapping[str, Fraction]) -> Fraction:
    return sum(
        (problem.demands[edge] * weights.get(edge, Fraction(0)) for edge in problem.obligations),
        start=Fraction(0),
    )


def _ceil_fraction(value: Fraction) -> int:
    return -(-value.numerator // value.denominator)


def _make_certificate(
    problem: DualProblem,
    weights: Mapping[str, Fraction],
    backend: str,
) -> DualCertificate:
    objective = _objective(problem, weights)
    return DualCertificate(
        problem_sha256=problem.digest,
        backend=backend,
        edge_weights=tuple(
            (edge, weights.get(edge, Fraction(0))) for edge in sorted(problem.obligations)
        ),
        objective=objective,
        integer_lower_bound=_ceil_fraction(objective),
    )


def _greedy_orderings(problem: DualProblem) -> tuple[tuple[str, ...], ...]:
    edges = tuple(sorted(problem.obligations))
    orderings = {
        edges,
        tuple(
            sorted(
                edges,
                key=lambda edge: (
                    len(problem.obligations[edge]),
                    -problem.demands[edge],
                    edge,
                ),
            )
        ),
        tuple(
            sorted(
                edges,
                key=lambda edge: (
                    -problem.demands[edge],
                    min(problem.costs[r] for r in problem.obligations[edge]),
                    edge,
                ),
            )
        ),
        tuple(
            sorted(
                edges,
                key=lambda edge: (
                    Fraction(
                        min(problem.costs[r] for r in problem.obligations[edge]),
                        problem.demands[edge],
                    ),
                    len(problem.obligations[edge]),
                    edge,
                ),
            )
        ),
    }
    return tuple(sorted(orderings))


def greedy_dual_certificate(
    obligations: Mapping[str, Iterable[str]],
    *,
    demands: Mapping[str, int] | None = None,
    costs: Mapping[str, int] | None = None,
) -> DualCertificate:
    """Construct the strongest of several deterministic dual-ascent orderings."""

    problem = normalize_dual_problem(obligations, demands=demands, costs=costs)
    best: DualCertificate | None = None
    for ordering in _greedy_orderings(problem):
        weights = {edge: Fraction(0) for edge in problem.obligations}
        loads = {release: Fraction(0) for release in problem.releases}
        for edge in ordering:
            slack = min(
                Fraction(problem.costs[release]) - loads[release]
                for release in problem.obligations[edge]
            )
            if slack <= 0:
                continue
            weights[edge] += slack
            for release in problem.obligations[edge]:
                loads[release] += slack
        candidate = _make_certificate(problem, weights, "DETERMINISTIC_DUAL_ASCENT")
        if best is None or (candidate.objective, candidate.edge_weights) > (
            best.objective,
            best.edge_weights,
        ):
            best = candidate
    return best or _make_certificate(problem, {}, "DETERMINISTIC_DUAL_ASCENT")


def _rationalize_and_scale(
    problem: DualProblem,
    edge_order: Sequence[str],
    values: Sequence[float],
    *,
    max_denominator: int,
) -> dict[str, Fraction]:
    weights = {
        edge: Fraction(max(0.0, float(value))).limit_denominator(max_denominator)
        for edge, value in zip(edge_order, values, strict=True)
    }
    scale = Fraction(1)
    for release in problem.releases:
        load = sum(
            (weights[edge] for edge in edge_order if release in problem.obligations[edge]),
            start=Fraction(0),
        )
        if load > problem.costs[release]:
            scale = min(scale, Fraction(problem.costs[release], 1) / load)
    if scale < 1:
        weights = {edge: weight * scale for edge, weight in weights.items()}
    return weights


def highs_dual_certificate(
    obligations: Mapping[str, Iterable[str]],
    *,
    demands: Mapping[str, int] | None = None,
    costs: Mapping[str, int] | None = None,
    max_denominator: int = 1_000_000,
) -> DualCertificate:
    """Use HiGHS for a candidate dual, then make it exact and self-verifying."""

    problem = normalize_dual_problem(obligations, demands=demands, costs=costs)
    if not problem.obligations:
        return _make_certificate(problem, {}, "SCIPY_HIGHS_DUAL")
    try:
        import numpy as np
        from scipy.optimize import linprog  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover - optional dependency path
        raise RuntimeError("SciPy solver extra is required for the LP dual") from exc
    edges = tuple(sorted(problem.obligations))
    matrix = np.zeros((len(problem.releases), len(edges)), dtype=float)
    for release_index, release in enumerate(problem.releases):
        for edge_index, edge in enumerate(edges):
            if release in problem.obligations[edge]:
                matrix[release_index, edge_index] = 1.0
    objective = -np.array([problem.demands[edge] for edge in edges], dtype=float)
    bounds = [(0.0, None) for _ in edges]
    result = linprog(
        objective,
        A_ub=matrix,
        b_ub=np.array([problem.costs[r] for r in problem.releases], dtype=float),
        bounds=bounds,
        method="highs",
    )
    if not bool(result.success) or result.x is None:
        raise RuntimeError(f"HiGHS dual solve failed: {result.message}")
    weights = _rationalize_and_scale(
        problem,
        edges,
        result.x,
        max_denominator=max_denominator,
    )
    certificate = _make_certificate(problem, weights, "SCIPY_HIGHS_DUAL_EXACT_REPLAY")
    passed, errors = verify_dual_certificate(
        obligations,
        certificate,
        demands=demands,
        costs=costs,
    )
    if not passed:
        raise RuntimeError(f"internal dual certificate verification failed: {errors}")
    return certificate


def strongest_dual_certificate(
    obligations: Mapping[str, Iterable[str]],
    *,
    demands: Mapping[str, int] | None = None,
    costs: Mapping[str, int] | None = None,
    use_highs: bool = True,
) -> DualCertificate:
    """Return the stronger verified result from dual ascent and optional HiGHS."""

    greedy = greedy_dual_certificate(obligations, demands=demands, costs=costs)
    if not use_highs:
        return greedy
    highs = highs_dual_certificate(obligations, demands=demands, costs=costs)
    return max((greedy, highs), key=lambda row: (row.objective, row.backend))


def verify_dual_certificate(
    obligations: Mapping[str, Iterable[str]],
    certificate: DualCertificate,
    *,
    demands: Mapping[str, int] | None = None,
    costs: Mapping[str, int] | None = None,
) -> tuple[bool, tuple[str, ...]]:
    """Check a dual certificate using only exact arithmetic."""

    errors: list[str] = []
    try:
        problem = normalize_dual_problem(obligations, demands=demands, costs=costs)
    except Exception as exc:
        return False, (f"problem normalization failed: {type(exc).__name__}: {exc}",)
    if certificate.problem_sha256 != problem.digest:
        errors.append("problem digest mismatch")
    rows = dict(certificate.edge_weights)
    if len(rows) != len(certificate.edge_weights):
        errors.append("duplicate edge weight entries")
    if set(rows) != set(problem.obligations):
        errors.append("edge weight identifiers do not match the problem")
    for edge, weight in rows.items():
        if weight < 0:
            errors.append(f"edge {edge} has a negative dual weight")
    for release in problem.releases:
        load = sum(
            (
                rows.get(edge, Fraction(0))
                for edge in problem.obligations
                if release in problem.obligations[edge]
            ),
            start=Fraction(0),
        )
        if load > problem.costs[release]:
            errors.append(
                f"release {release} violates dual feasibility: {load} > {problem.costs[release]}"
            )
    expected_objective = _objective(problem, rows)
    if certificate.objective != expected_objective:
        errors.append("dual objective does not match the weighted edge sum")
    if certificate.integer_lower_bound != _ceil_fraction(expected_objective):
        errors.append("integer lower bound is not the ceiling of the dual objective")
    if not certificate.backend:
        errors.append("dual backend identifier is empty")
    return not errors, tuple(errors)
