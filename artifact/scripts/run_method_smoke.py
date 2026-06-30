#!/usr/bin/env python3
"""Deterministic cross-oracle smoke validation for the certified solvers."""

from __future__ import annotations

import json
import sys
import random
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from repairwitness.interval import solve_interval_multicover, verify_interval_certificate
from repairwitness.oracle import solve_exhaustive_oracle
from repairwitness.suite import solve_exact, verify_certificate


def random_general(rng: random.Random, index: int) -> tuple[dict[str, set[str]], dict[str, int]]:
    release_count = rng.randint(4, 9)
    edge_count = rng.randint(3, 8)
    releases = [f"r{index}-{i}" for i in range(release_count)]
    obligations = {}
    for edge in range(edge_count):
        width = rng.randint(1, release_count)
        obligations[f"e{edge}"] = set(rng.sample(releases, width))
    used = sorted(set().union(*obligations.values()))
    costs = {release: rng.randint(1, 8) for release in used}
    return obligations, costs


def main() -> None:
    rng = random.Random(20270630)
    start = time.perf_counter()
    failures: list[str] = []
    general = 0
    interval = 0
    for index in range(120):
        obligations, costs = random_general(rng, index)
        certificate = solve_exact(obligations, costs=costs)
        valid, errors = verify_certificate(obligations, certificate, costs=costs, verify_optimality=True)
        oracle = solve_exhaustive_oracle(obligations, costs=costs, release_limit=12)
        if not valid or certificate.upper_bound != oracle.optimal_cost:
            failures.append(f"general-{index}: {errors}")
        general += 1
    for index in range(120):
        size = rng.randint(5, 24)
        order = tuple(f"v{index}-{i}" for i in range(size))
        bounds = {}
        for edge in range(rng.randint(3, 20)):
            left = rng.randrange(size)
            right = rng.randrange(left, size)
            demand = rng.randint(1, min(3, right - left + 1))
            bounds[f"e{edge}"] = (left, right, demand)
        certificate = solve_interval_multicover(order, bounds)
        valid, errors = verify_interval_certificate(order, bounds, certificate)
        if not valid:
            failures.append(f"interval-{index}: {errors}")
        interval += 1
    report = {
        "schema_version": 1,
        "seed": 20270630,
        "general_cross_oracle_cases": general,
        "interval_replay_cases": interval,
        "counterexamples": len(failures),
        "failures": failures,
        "elapsed_seconds": time.perf_counter() - start,
        "status": "PASS" if not failures else "FAIL",
    }
    path = ROOT / "verification" / "method_smoke.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    raise SystemExit(0 if not failures else 1)


if __name__ == "__main__":
    main()
