"""Certified minimum-cost interval multicover.

The general weighted redundant suite problem is NP-hard.  When every obligation is a
contiguous interval in a fixed release order, however, the incidence matrix has the
consecutive-ones property and is totally unimodular.  The bounded covering LP therefore
has an integral optimum for integer demands.  This module solves that LP and emits an
exact-arithmetic primal/dual certificate:

    min  c^T x                   max  d^T y - 1^T z
    s.t. A x >= d               s.t. A^T y - z <= c
         0 <= x <= 1                 y,z >= 0.

The checker does not trust floating-point solver status.  It verifies the binary primal,
rational dual feasibility, objective arithmetic, and equality of the integer primal cost
with the ceiling of the dual objective.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from fractions import Fraction

from .canonical import canonical_json_bytes, sha256_bytes
from .interval import IntervalObligation, IntervalRecognition, recognition_from_bounds


@dataclass(frozen=True)
class IntervalLPDualCertificate:
    edge_weights: tuple[tuple[str, Fraction], ...]
    cap_weights: tuple[tuple[str, Fraction], ...]
    objective: Fraction
    integer_lower_bound: int
    backend: str

    def to_dict(self) -> dict[str, object]:
        return {
            "edge_weights": [
                {
                    "edge_id": edge,
                    "numerator": weight.numerator,
                    "denominator": weight.denominator,
                }
                for edge, weight in self.edge_weights
            ],
            "cap_weights": [
                {
                    "release": release,
                    "numerator": weight.numerator,
                    "denominator": weight.denominator,
                }
                for release, weight in self.cap_weights
            ],
            "objective": {
                "numerator": self.objective.numerator,
                "denominator": self.objective.denominator,
            },
            "integer_lower_bound": self.integer_lower_bound,
            "backend": self.backend,
        }


@dataclass(frozen=True)
class WeightedIntervalCertificate:
    schema_version: int
    problem_sha256: str
    release_order: tuple[str, ...]
    intervals: tuple[IntervalObligation, ...]
    costs: tuple[tuple[str, int], ...]
    selected_releases: tuple[str, ...]
    objective: int
    dual: IntervalLPDualCertificate
    proof_kind: str = "CONSECUTIVE_ONES_TU_PRIMAL_DUAL"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "problem_sha256": self.problem_sha256,
            "release_order": list(self.release_order),
            "intervals": [row.to_dict() for row in self.intervals],
            "costs": [
                {"release": release, "cost": cost} for release, cost in self.costs
            ],
            "selected_releases": list(self.selected_releases),
            "objective": self.objective,
            "dual": self.dual.to_dict(),
            "proof_kind": self.proof_kind,
        }


@dataclass(frozen=True)
class _WeightedIntervalProblem:
    recognition: IntervalRecognition
    costs: dict[str, int]
    digest: str


def _ceil_fraction(value: Fraction) -> int:
    return -(-value.numerator // value.denominator)


def _normalise_costs(
    recognition: IntervalRecognition,
    costs: Mapping[str, int],
) -> _WeightedIntervalProblem:
    order = recognition.release_order
    extras = set(map(str, costs)) - set(order)
    if extras:
        raise ValueError(f"costs contain releases outside release_order: {sorted(extras)}")
    normalized: dict[str, int] = {}
    for release in order:
        raw = costs.get(release)
        if isinstance(raw, bool) or not isinstance(raw, int) or raw < 1:
            raise ValueError(f"cost for {release!r} must be a positive integer")
        normalized[release] = raw
    payload = {
        "release_order": list(order),
        "intervals": [row.to_dict() for row in recognition.intervals],
        "costs": {release: normalized[release] for release in order},
    }
    return _WeightedIntervalProblem(
        recognition=recognition,
        costs=normalized,
        digest=sha256_bytes(canonical_json_bytes(payload)),
    )


def _fraction_vector(values: Sequence[float], max_denominator: int) -> list[Fraction]:
    return [
        Fraction(max(0.0, float(value))).limit_denominator(max_denominator)
        for value in values
    ]


def _scale_dual_feasible(
    problem: _WeightedIntervalProblem,
    edge_values: list[Fraction],
    cap_values: list[Fraction],
) -> tuple[list[Fraction], list[Fraction]]:
    scale = Fraction(1)
    intervals = problem.recognition.intervals
    for release_index, release in enumerate(problem.recognition.release_order):
        load = sum(
            (
                edge_values[edge_index]
                for edge_index, interval in enumerate(intervals)
                if interval.left <= release_index <= interval.right
            ),
            start=Fraction(0),
        ) - cap_values[release_index]
        if load > problem.costs[release]:
            scale = min(scale, Fraction(problem.costs[release], 1) / load)
    if scale < 1:
        edge_values = [value * scale for value in edge_values]
        cap_values = [value * scale for value in cap_values]
    return edge_values, cap_values


def _dual_objective(
    intervals: Sequence[IntervalObligation],
    edge_values: Sequence[Fraction],
    cap_values: Sequence[Fraction],
) -> Fraction:
    return sum(
        (
            interval.demand * edge_values[index]
            for index, interval in enumerate(intervals)
        ),
        start=Fraction(0),
    ) - sum(cap_values, start=Fraction(0))


def solve_weighted_interval_bounds(
    release_order: Sequence[str],
    intervals: Mapping[str, tuple[int, int] | tuple[int, int, int]],
    *,
    costs: Mapping[str, int],
    max_denominator: int = 1_000_000,
) -> WeightedIntervalCertificate:
    """Solve weighted redundant interval separation and emit an exact dual proof."""

    if max_denominator < 1:
        raise ValueError("max_denominator must be positive")
    recognition = recognition_from_bounds(release_order, intervals)
    problem = _normalise_costs(recognition, costs)
    if not recognition.intervals:
        dual = IntervalLPDualCertificate((), tuple((r, Fraction(0)) for r in release_order), Fraction(0), 0, "EMPTY")
        return WeightedIntervalCertificate(
            schema_version=1,
            problem_sha256=problem.digest,
            release_order=recognition.release_order,
            intervals=recognition.intervals,
            costs=tuple((release, problem.costs[release]) for release in recognition.release_order),
            selected_releases=(),
            objective=0,
            dual=dual,
        )
    try:
        import numpy as np
        from scipy.optimize import linprog  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover - optional dependency path
        raise RuntimeError("SciPy is required for weighted interval certificates") from exc

    rows = recognition.intervals
    order = recognition.release_order
    matrix = np.zeros((len(rows), len(order)), dtype=float)
    for row_index, interval in enumerate(rows):
        matrix[row_index, interval.left : interval.right + 1] = 1.0
    cost_vector = np.array([problem.costs[release] for release in order], dtype=float)
    demand_vector = np.array([interval.demand for interval in rows], dtype=float)
    primal = linprog(
        cost_vector,
        A_ub=-matrix,
        b_ub=-demand_vector,
        bounds=[(0.0, 1.0) for _ in order],
        method="highs",
    )
    if not bool(primal.success) or primal.x is None:
        raise RuntimeError(f"HiGHS primal solve failed: {primal.message}")
    selected_indices = tuple(
        index for index, value in enumerate(primal.x) if float(value) >= 0.5
    )
    selected = tuple(order[index] for index in selected_indices)
    selected_set = set(selected_indices)
    if any(
        sum(1 for index in selected_set if interval.left <= index <= interval.right)
        < interval.demand
        for interval in rows
    ):
        raise RuntimeError("integral rounding of the interval LP was infeasible")
    objective = sum(problem.costs[order[index]] for index in selected_indices)

    # Independent dual solve. Variables are y_e followed by z_r.
    dual_matrix = np.zeros((len(order), len(rows) + len(order)), dtype=float)
    for release_index in range(len(order)):
        for edge_index, interval in enumerate(rows):
            if interval.left <= release_index <= interval.right:
                dual_matrix[release_index, edge_index] = 1.0
        dual_matrix[release_index, len(rows) + release_index] = -1.0
    dual_objective = np.concatenate((-demand_vector, np.ones(len(order))))
    dual_result = linprog(
        dual_objective,
        A_ub=dual_matrix,
        b_ub=cost_vector,
        bounds=[(0.0, None) for _ in range(len(rows) + len(order))],
        method="highs",
    )
    if not bool(dual_result.success) or dual_result.x is None:
        raise RuntimeError(f"HiGHS dual solve failed: {dual_result.message}")
    edge_values = _fraction_vector(dual_result.x[: len(rows)], max_denominator)
    cap_values = _fraction_vector(dual_result.x[len(rows) :], max_denominator)
    edge_values, cap_values = _scale_dual_feasible(problem, edge_values, cap_values)
    exact_objective = _dual_objective(rows, edge_values, cap_values)
    dual = IntervalLPDualCertificate(
        edge_weights=tuple(
            (interval.edge_id, edge_values[index])
            for index, interval in enumerate(rows)
        ),
        cap_weights=tuple(
            (release, cap_values[index]) for index, release in enumerate(order)
        ),
        objective=exact_objective,
        integer_lower_bound=_ceil_fraction(exact_objective),
        backend="SCIPY_HIGHS_TU_LP_EXACT_RATIONAL_REPLAY",
    )
    certificate = WeightedIntervalCertificate(
        schema_version=1,
        problem_sha256=problem.digest,
        release_order=order,
        intervals=rows,
        costs=tuple((release, problem.costs[release]) for release in order),
        selected_releases=selected,
        objective=objective,
        dual=dual,
    )
    valid, errors = verify_weighted_interval_bounds(
        release_order,
        intervals,
        certificate,
        costs=costs,
    )
    if not valid:
        raise RuntimeError("weighted interval certificate failed replay: " + "; ".join(errors))
    return certificate


def verify_weighted_interval_bounds(
    release_order: Sequence[str],
    intervals: Mapping[str, tuple[int, int] | tuple[int, int, int]],
    certificate: WeightedIntervalCertificate,
    *,
    costs: Mapping[str, int],
) -> tuple[bool, tuple[str, ...]]:
    """Verify primal feasibility and dual optimality using exact arithmetic."""

    errors: list[str] = []
    try:
        problem = _normalise_costs(recognition_from_bounds(release_order, intervals), costs)
    except Exception as exc:
        return False, (f"problem normalization failed: {type(exc).__name__}: {exc}",)
    recognition = problem.recognition
    if certificate.schema_version != 1:
        errors.append("unsupported weighted interval certificate schema")
    if certificate.proof_kind != "CONSECUTIVE_ONES_TU_PRIMAL_DUAL":
        errors.append("unexpected weighted interval proof kind")
    if certificate.problem_sha256 != problem.digest:
        errors.append("weighted interval problem digest mismatch")
    if certificate.release_order != recognition.release_order:
        errors.append("release order mismatch")
    if certificate.intervals != recognition.intervals:
        errors.append("interval inventory mismatch")
    expected_costs = tuple(
        (release, problem.costs[release]) for release in recognition.release_order
    )
    if certificate.costs != expected_costs:
        errors.append("release-cost inventory mismatch")

    selected = certificate.selected_releases
    selected_set = set(selected)
    if len(selected_set) != len(selected):
        errors.append("selected releases contain duplicates")
    unknown = selected_set - set(recognition.release_order)
    if unknown:
        errors.append(f"selected releases contain unknown values: {sorted(unknown)}")
    index = {release: position for position, release in enumerate(recognition.release_order)}
    selected_indices = {index[release] for release in selected_set if release in index}
    for interval in recognition.intervals:
        count = sum(
            1
            for position in selected_indices
            if interval.left <= position <= interval.right
        )
        if count < interval.demand:
            errors.append(f"selected suite does not satisfy interval {interval.edge_id}")
    expected_objective = sum(
        problem.costs[release] for release in selected_set if release in problem.costs
    )
    if certificate.objective != expected_objective:
        errors.append("primal objective does not equal selected release cost")

    edge_weights = dict(certificate.dual.edge_weights)
    cap_weights = dict(certificate.dual.cap_weights)
    if len(edge_weights) != len(certificate.dual.edge_weights):
        errors.append("duplicate interval dual weights")
    if len(cap_weights) != len(certificate.dual.cap_weights):
        errors.append("duplicate cap dual weights")
    if set(edge_weights) != {row.edge_id for row in recognition.intervals}:
        errors.append("interval dual identifiers do not match the problem")
    if set(cap_weights) != set(recognition.release_order):
        errors.append("cap dual identifiers do not match the release order")
    if any(value < 0 for value in edge_weights.values()):
        errors.append("interval dual contains a negative weight")
    if any(value < 0 for value in cap_weights.values()):
        errors.append("cap dual contains a negative weight")
    for release_index, release in enumerate(recognition.release_order):
        load = sum(
            (
                edge_weights.get(interval.edge_id, Fraction(0))
                for interval in recognition.intervals
                if interval.left <= release_index <= interval.right
            ),
            start=Fraction(0),
        ) - cap_weights.get(release, Fraction(0))
        if load > problem.costs[release]:
            errors.append(f"release {release} violates exact dual feasibility")
    expected_dual_objective = sum(
        (
            interval.demand * edge_weights.get(interval.edge_id, Fraction(0))
            for interval in recognition.intervals
        ),
        start=Fraction(0),
    ) - sum(
        (cap_weights.get(release, Fraction(0)) for release in recognition.release_order),
        start=Fraction(0),
    )
    if certificate.dual.objective != expected_dual_objective:
        errors.append("dual objective arithmetic mismatch")
    expected_lower = _ceil_fraction(expected_dual_objective)
    if certificate.dual.integer_lower_bound != expected_lower:
        errors.append("integer lower bound is not the ceiling of the dual objective")
    if not certificate.dual.backend:
        errors.append("dual backend identifier is empty")
    if certificate.dual.integer_lower_bound != certificate.objective:
        errors.append("primal and certified integer dual bounds do not meet")
    return not errors, tuple(errors)
