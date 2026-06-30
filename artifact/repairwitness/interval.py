"""Interval structure for action-separating obligations.

When releases are totally ordered and each disagreement witness set is contiguous,
minimum-cardinality redundant separation is an interval stabbing multicover.  Processing
intervals by nondecreasing right endpoint and inserting the rightmost still-unselected
points needed by each interval is optimal.  This module recognizes that structure,
implements the greedy-exact algorithm with a Fenwick tree and predecessor disjoint-set,
and emits a replayable trace.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

from .canonical import canonical_json_bytes, sha256_bytes


@dataclass(frozen=True, order=True)
class IntervalObligation:
    """A demand over the closed release-index interval ``[left, right]``."""

    edge_id: str
    left: int
    right: int
    demand: int = 1

    def to_dict(self) -> dict[str, object]:
        return {
            "edge_id": self.edge_id,
            "left": self.left,
            "right": self.right,
            "demand": self.demand,
        }


@dataclass(frozen=True)
class IntervalRecognition:
    release_order: tuple[str, ...]
    intervals: tuple[IntervalObligation, ...]
    problem_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "release_order": list(self.release_order),
            "intervals": [row.to_dict() for row in self.intervals],
            "problem_sha256": self.problem_sha256,
        }


@dataclass(frozen=True)
class IntervalStep:
    edge_id: str
    selected_before: int
    inserted_indices: tuple[int, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "edge_id": self.edge_id,
            "selected_before": self.selected_before,
            "inserted_indices": list(self.inserted_indices),
        }


@dataclass(frozen=True)
class IntervalCertificate:
    problem_sha256: str
    release_order: tuple[str, ...]
    intervals: tuple[IntervalObligation, ...]
    selected_releases: tuple[str, ...]
    steps: tuple[IntervalStep, ...]
    proof_kind: str = "RIGHT_ENDPOINT_INTERVAL_MULTICOVER"

    @property
    def objective(self) -> int:
        return len(self.selected_releases)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "problem_sha256": self.problem_sha256,
            "release_order": list(self.release_order),
            "intervals": [row.to_dict() for row in self.intervals],
            "selected_releases": list(self.selected_releases),
            "objective": self.objective,
            "steps": [row.to_dict() for row in self.steps],
            "proof_kind": self.proof_kind,
        }


class _Fenwick:
    def __init__(self, size: int) -> None:
        self._tree = [0] * (size + 1)

    def add(self, index: int, delta: int) -> None:
        cursor = index + 1
        while cursor < len(self._tree):
            self._tree[cursor] += delta
            cursor += cursor & -cursor

    def prefix(self, end_exclusive: int) -> int:
        total = 0
        cursor = end_exclusive
        while cursor:
            total += self._tree[cursor]
            cursor -= cursor & -cursor
        return total

    def range_sum(self, left: int, right: int) -> int:
        return self.prefix(right + 1) - self.prefix(left)


class _Predecessor:
    """Return the largest unselected index not exceeding a query."""

    def __init__(self, size: int) -> None:
        # Shift indices by one.  Node 0 is the sentinel ``no predecessor``.
        self._parent = list(range(size + 1))

    def _find(self, node: int) -> int:
        while self._parent[node] != node:
            self._parent[node] = self._parent[self._parent[node]]
            node = self._parent[node]
        return node

    def predecessor(self, index: int) -> int | None:
        node = self._find(index + 1)
        return None if node == 0 else node - 1

    def remove(self, index: int) -> None:
        node = index + 1
        self._parent[node] = self._find(node - 1)


def _normalise_order(release_order: Sequence[str]) -> tuple[str, ...]:
    order = tuple(str(value) for value in release_order)
    if not order:
        raise ValueError("release_order must not be empty")
    if any(not value for value in order):
        raise ValueError("release identifiers must be non-empty")
    if len(set(order)) != len(order):
        raise ValueError("release_order contains duplicates")
    return order


def _digest(order: tuple[str, ...], intervals: tuple[IntervalObligation, ...]) -> str:
    payload = {
        "release_order": list(order),
        "intervals": [row.to_dict() for row in intervals],
    }
    return sha256_bytes(canonical_json_bytes(payload))


def recognition_from_bounds(
    release_order: Sequence[str],
    intervals: Mapping[str, tuple[int, int] | tuple[int, int, int]],
) -> IntervalRecognition:
    order = _normalise_order(release_order)
    rows: list[IntervalObligation] = []
    for raw_edge, raw_bounds in intervals.items():
        edge = str(raw_edge)
        if not edge:
            raise ValueError("edge identifiers must be non-empty")
        if len(raw_bounds) == 2:
            left, right = raw_bounds
            demand = 1
        elif len(raw_bounds) == 3:
            left, right, demand = raw_bounds
        else:
            raise ValueError(f"interval for {edge!r} must have two or three integers")
        if any(isinstance(value, bool) or not isinstance(value, int) for value in (left, right, demand)):
            raise ValueError(f"interval for {edge!r} must contain integers")
        if left < 0 or right < left or right >= len(order):
            raise ValueError(f"interval for {edge!r} is outside release_order")
        if demand < 1 or demand > right - left + 1:
            raise ValueError(f"demand for {edge!r} exceeds its interval width")
        rows.append(IntervalObligation(edge, left, right, demand))
    if len({row.edge_id for row in rows}) != len(rows):
        raise ValueError("duplicate edge identifiers")
    canonical = tuple(sorted(rows, key=lambda row: (row.right, row.left, row.edge_id)))
    return IntervalRecognition(order, canonical, _digest(order, canonical))


def recognize_intervals(
    release_order: Sequence[str],
    obligations: Mapping[str, Iterable[str]],
    *,
    demands: Mapping[str, int] | None = None,
) -> IntervalRecognition:
    order = _normalise_order(release_order)
    position = {release: index for index, release in enumerate(order)}
    bounds: dict[str, tuple[int, int, int]] = {}
    for raw_edge, raw_witnesses in obligations.items():
        edge = str(raw_edge)
        witnesses = {str(value) for value in raw_witnesses}
        if not witnesses:
            raise ValueError(f"obligation {edge!r} has no witnesses")
        unknown = witnesses - set(position)
        if unknown:
            raise ValueError(f"obligation {edge!r} contains unknown releases: {sorted(unknown)}")
        indices = sorted(position[value] for value in witnesses)
        if indices != list(range(indices[0], indices[-1] + 1)):
            raise ValueError(f"obligation {edge!r} is not contiguous in release_order")
        demand = 1 if demands is None else demands.get(edge, 1)
        if isinstance(demand, bool) or not isinstance(demand, int):
            raise ValueError(f"demand for {edge!r} must be an integer")
        bounds[edge] = (indices[0], indices[-1], demand)
    if demands is not None:
        extras = set(demands) - {str(edge) for edge in obligations}
        if extras:
            raise ValueError(f"demands contain unknown obligations: {sorted(extras)}")
    return recognition_from_bounds(order, bounds)


def solve_interval_multicover(
    release_order: Sequence[str],
    intervals: Mapping[str, tuple[int, int] | tuple[int, int, int]],
) -> IntervalCertificate:
    """Return an optimal minimum-cardinality interval multicover certificate."""

    recognition = recognition_from_bounds(release_order, intervals)
    order = recognition.release_order
    selected = [False] * len(order)
    fenwick = _Fenwick(len(order))
    predecessor = _Predecessor(len(order))
    steps: list[IntervalStep] = []
    for row in recognition.intervals:
        before = fenwick.range_sum(row.left, row.right)
        missing = row.demand - before
        inserted: list[int] = []
        while missing > 0:
            index = predecessor.predecessor(row.right)
            if index is None or index < row.left:
                raise ValueError(f"interval problem is infeasible at {row.edge_id}")
            if selected[index]:  # defensive; DSU should make this unreachable
                raise AssertionError("predecessor returned an already-selected index")
            selected[index] = True
            fenwick.add(index, 1)
            predecessor.remove(index)
            inserted.append(index)
            missing -= 1
        steps.append(IntervalStep(row.edge_id, before, tuple(inserted)))
    chosen = tuple(order[index] for index, value in enumerate(selected) if value)
    certificate = IntervalCertificate(
        problem_sha256=recognition.problem_sha256,
        release_order=order,
        intervals=recognition.intervals,
        selected_releases=chosen,
        steps=tuple(steps),
    )
    passed, errors = verify_interval_certificate(release_order, intervals, certificate)
    if not passed:
        raise RuntimeError("internal interval certificate failure: " + "; ".join(errors))
    return certificate


def verify_interval_certificate(
    release_order: Sequence[str],
    intervals: Mapping[str, tuple[int, int] | tuple[int, int, int]],
    certificate: IntervalCertificate,
) -> tuple[bool, tuple[str, ...]]:
    """Replay the greedy-exact construction and its exchange-proof trace."""

    errors: list[str] = []
    try:
        expected = recognition_from_bounds(release_order, intervals)
    except Exception as exc:
        return False, (f"problem normalization failed: {type(exc).__name__}: {exc}",)
    if certificate.proof_kind != "RIGHT_ENDPOINT_INTERVAL_MULTICOVER":
        errors.append("unexpected interval proof kind")
    if certificate.problem_sha256 != expected.problem_sha256:
        errors.append("interval problem digest mismatch")
    if certificate.release_order != expected.release_order:
        errors.append("release order mismatch")
    if certificate.intervals != expected.intervals:
        errors.append("interval inventory mismatch")
    if len(certificate.steps) != len(expected.intervals):
        errors.append("step inventory length mismatch")
        return False, tuple(errors)

    selected: set[int] = set()
    for row, step in zip(expected.intervals, certificate.steps, strict=True):
        if step.edge_id != row.edge_id:
            errors.append(f"step edge mismatch for {row.edge_id}")
            continue
        before = sum(row.left <= index <= row.right for index in selected)
        if step.selected_before != before:
            errors.append(f"selected_before mismatch for {row.edge_id}")
        need = max(0, row.demand - before)
        if len(step.inserted_indices) != need:
            errors.append(f"insert count mismatch for {row.edge_id}")
        expected_insertions: list[int] = []
        available = [
            index
            for index in range(row.left, row.right + 1)
            if index not in selected
        ]
        for _ in range(need):
            if not available:
                errors.append(f"infeasible trace for {row.edge_id}")
                break
            index = available.pop()
            expected_insertions.append(index)
            selected.add(index)
        if tuple(expected_insertions) != step.inserted_indices:
            errors.append(f"right-endpoint insertion mismatch for {row.edge_id}")

    reported = tuple(expected.release_order[index] for index in sorted(selected))
    if certificate.selected_releases != reported:
        errors.append("selected release inventory does not match the trace")
    for row in expected.intervals:
        if sum(row.left <= index <= row.right for index in selected) < row.demand:
            errors.append(f"selected suite does not satisfy {row.edge_id}")
    return not errors, tuple(errors)
