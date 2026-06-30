from __future__ import annotations

from dataclasses import replace

from action_suites.suite import solve_exact, solve_greedy, verify_certificate


OBLIGATIONS = {
    "e1": {"1.0", "2.0"},
    "e2": {"2.0", "3.0"},
    "e3": {"3.0", "4.0"},
}


def test_exact_suite_and_replay() -> None:
    certificate = solve_exact(OBLIGATIONS)
    assert certificate.status == "EXACT"
    assert certificate.lower_bound == certificate.upper_bound == 2
    passed, errors = verify_certificate(OBLIGATIONS, certificate)
    assert passed, errors


def test_greedy_suite_replays() -> None:
    certificate = solve_greedy(OBLIGATIONS)
    passed, errors = verify_certificate(OBLIGATIONS, certificate)
    assert passed, errors


def test_bounded_certificate_has_sound_interval() -> None:
    certificate = solve_exact(OBLIGATIONS, max_nodes=0)
    assert certificate.status == "BOUNDED"
    assert 1 <= certificate.lower_bound <= certificate.upper_bound
    assert verify_certificate(OBLIGATIONS, certificate)[0]


def test_tampered_certificate_fails() -> None:
    certificate = solve_exact(OBLIGATIONS)
    tampered = replace(certificate, obligation_sha256="0" * 64)
    assert not verify_certificate(OBLIGATIONS, tampered)[0]


def test_exact_solver_matches_bruteforce_on_small_instances() -> None:
    from itertools import combinations
    import random

    random.seed(20260622)
    releases = [f"r{index}" for index in range(6)]
    for case in range(50):
        obligations = {}
        for edge_index in range(1 + case % 6):
            witnesses = {release for release in releases if random.random() < 0.4}
            if not witnesses:
                witnesses = {random.choice(releases)}
            obligations[f"e{edge_index}"] = witnesses
        optimum = None
        for size in range(1, len(releases) + 1):
            candidates = [
                subset
                for subset in combinations(releases, size)
                if all(set(subset).intersection(witnesses) for witnesses in obligations.values())
            ]
            if candidates:
                optimum = min(candidates)
                break
        assert optimum is not None
        certificate = solve_exact(obligations)
        assert certificate.status == "EXACT"
        assert len(certificate.selected_releases) == len(optimum)
        assert certificate.lower_bound == certificate.upper_bound


def test_kernelization_forces_singletons_and_preserves_original_replay() -> None:
    obligations = {
        "forced": {"r1"},
        "covered-by-forced": {"r1", "r2"},
        "residual-minimal": {"r3", "r4"},
        "residual-superset": {"r3", "r4", "r5"},
        "residual-duplicate": {"r3", "r4"},
    }
    certificate = solve_exact(obligations)
    assert certificate.status == "EXACT"
    assert "r1" in certificate.selected_releases
    assert certificate.kernel.original_edges == 5
    assert certificate.kernel.forced_releases == ("r1",)
    assert certificate.kernel.forced_covered_edges == 2
    assert certificate.kernel.residual_edges == 1
    assert certificate.kernel.redundant_edges == 2
    assert certificate.lower_bound == certificate.upper_bound == 2
    assert verify_certificate(obligations, certificate)[0]


def test_kernelized_certificate_round_trip() -> None:
    from action_suites.suite import SuiteCertificate

    certificate = solve_exact({"e1": {"r1"}, "e2": {"r1", "r2"}})
    restored = SuiteCertificate.from_dict(certificate.to_dict())
    assert restored == certificate
    assert verify_certificate({"e1": {"r1"}, "e2": {"r1", "r2"}}, restored)[0]


def test_kernelization_is_deterministic_under_mapping_order() -> None:
    left = {"b": {"r2", "r3"}, "a": {"r1"}, "c": {"r2", "r3", "r4"}}
    right = {"c": {"r4", "r3", "r2"}, "a": {"r1"}, "b": {"r3", "r2"}}
    assert solve_exact(left).to_dict() == solve_exact(right).to_dict()


def test_kernel_reports_disconnected_obligation_components() -> None:
    certificate = solve_exact(
        {
            "a": {"r1", "r2"},
            "b": {"r2", "r3"},
            "c": {"r9", "r10"},
        }
    )
    assert certificate.kernel.components == 2
    assert verify_certificate(
        {"a": {"r1", "r2"}, "b": {"r2", "r3"}, "c": {"r9", "r10"}},
        certificate,
    )[0]
