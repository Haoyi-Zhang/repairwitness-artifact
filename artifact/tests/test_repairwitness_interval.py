from __future__ import annotations

from dataclasses import replace

from repairwitness.interval import solve_interval_multicover, verify_interval_certificate
from repairwitness.weighted_interval import (
    solve_weighted_interval_bounds,
    verify_weighted_interval_bounds,
)


def test_interval_exact_right_endpoint_solution() -> None:
    order = ("1", "2", "3", "4", "5", "6")
    intervals = {
        "e0": (0, 2),
        "e1": (1, 4),
        "e2": (3, 5),
    }
    certificate = solve_interval_multicover(order, intervals)
    valid, errors = verify_interval_certificate(order, intervals, certificate)
    assert valid, errors
    assert certificate.selected_releases == ("3", "6")


def test_interval_redundancy() -> None:
    order = ("a", "b", "c", "d")
    intervals = {"e0": (0, 3, 2), "e1": (1, 3, 2)}
    certificate = solve_interval_multicover(order, intervals)
    valid, errors = verify_interval_certificate(order, intervals, certificate)
    assert valid, errors
    assert certificate.selected_releases == ("c", "d")


def test_interval_tamper_detected() -> None:
    order = ("a", "b", "c")
    intervals = {"e0": (0, 2)}
    certificate = solve_interval_multicover(order, intervals)
    tampered = replace(certificate, problem_sha256="0" * 64)
    valid, errors = verify_interval_certificate(order, intervals, tampered)
    assert not valid
    assert "interval problem digest mismatch" in errors


def test_weighted_interval_primal_dual_certificate() -> None:
    order = ("1", "2", "3", "4")
    intervals = {"e0": (0, 2), "e1": (1, 3)}
    costs = {"1": 7, "2": 2, "3": 3, "4": 9}
    certificate = solve_weighted_interval_bounds(order, intervals, costs=costs)
    valid, errors = verify_weighted_interval_bounds(order, intervals, certificate, costs=costs)
    assert valid, errors
    assert certificate.objective == 2
    assert certificate.dual.integer_lower_bound == 2
