from __future__ import annotations

from dataclasses import replace

import pytest

from repairwitness.certification import solve_certified, verify_certified_bundle
from repairwitness.oracle import solve_exhaustive_oracle
from repairwitness.suite import InfeasibleSuiteProblem, solve_exact, solve_greedy, verify_certificate


def problem():
    obligations = {
        "e0": {"1.0", "1.1"},
        "e1": {"1.1", "2.0"},
        "e2": {"2.0", "3.0"},
    }
    costs = {"1.0": 3, "1.1": 1, "2.0": 2, "3.0": 5}
    return obligations, costs


def test_exact_matches_independent_oracle() -> None:
    obligations, costs = problem()
    certificate = solve_exact(obligations, costs=costs)
    valid, errors = verify_certificate(obligations, certificate, costs=costs, verify_optimality=True)
    oracle = solve_exhaustive_oracle(obligations, costs=costs, release_limit=10)
    assert valid, errors
    assert certificate.status == "EXACT"
    assert certificate.upper_bound == oracle.optimal_cost == 3


def test_redundant_demands_are_enforced() -> None:
    obligations = {"e0": {"a", "b", "c"}, "e1": {"b", "c", "d"}}
    demands = {"e0": 2, "e1": 2}
    certificate = solve_exact(obligations, demands=demands)
    valid, errors = verify_certificate(
        obligations,
        certificate,
        demands=demands,
        verify_optimality=True,
    )
    assert valid, errors
    assert certificate.upper_bound == 2
    assert set(certificate.selected_releases) == {"b", "c"}


def test_infeasible_demand_rejected() -> None:
    with pytest.raises(InfeasibleSuiteProblem):
        solve_exact({"e": {"a"}}, demands={"e": 2})


def test_greedy_certificate_replays() -> None:
    obligations, costs = problem()
    certificate = solve_greedy(obligations, costs=costs)
    valid, errors = verify_certificate(obligations, certificate, costs=costs)
    assert valid, errors
    assert certificate.status == "HEURISTIC"
    assert certificate.approximation_factor_bound is not None


def test_bounded_search_never_claims_false_exactness() -> None:
    obligations = {
        "e0": {"a", "b", "c"},
        "e1": {"a", "d"},
        "e2": {"b", "e"},
        "e3": {"c", "f"},
    }
    certificate = solve_exact(obligations, max_nodes=0, method="bnb")
    valid, errors = verify_certificate(obligations, certificate)
    assert valid, errors
    assert certificate.status == "BOUNDED"
    assert certificate.lower_bound <= certificate.upper_bound


def test_cross_paradigm_bundle_is_strictly_replayable() -> None:
    obligations, costs = problem()
    bundle = solve_certified(obligations, costs=costs, independent_oracle=True)
    valid, errors = verify_certified_bundle(obligations, bundle, costs=costs, profile="strict")
    assert valid, errors
    assert bundle.status == "EXACT_CROSS_CHECKED"
    assert len(bundle.proof_channels) == 3


def test_certificate_tamper_is_detected() -> None:
    obligations, costs = problem()
    certificate = solve_exact(obligations, costs=costs)
    tampered = replace(certificate, upper_bound=certificate.upper_bound + 1)
    valid, errors = verify_certificate(obligations, tampered, costs=costs)
    assert not valid
    assert any("upper bound" in error for error in errors)
