#!/usr/bin/env python3
"""Run a dense-overlap interval scalability control."""
from __future__ import annotations

import json
import sys
import time
import tracemalloc
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from repairwitness.interval import solve_interval_multicover, verify_interval_certificate  # noqa: E402


def dense_overlap_instance(
    release_count: int,
    obligation_count: int,
    width: int,
    demand: int,
) -> tuple[tuple[str, ...], dict[str, tuple[int, int, int]]]:
    releases = tuple(f"r{i:05d}" for i in range(release_count))
    span = release_count - width
    intervals: dict[str, tuple[int, int, int]] = {}
    for index in range(obligation_count):
        left = (index * 97) % (span + 1)
        right = left + width - 1
        intervals[f"dense-{index:05d}"] = (left, right, demand)
    return releases, intervals


def main() -> int:
    findings: list[dict[str, object]] = []
    releases, intervals = dense_overlap_instance(
        release_count=10_000,
        obligation_count=20_000,
        width=5_000,
        demand=3,
    )
    tracemalloc.start()
    start = time.perf_counter_ns()
    certificate = solve_interval_multicover(releases, intervals)
    solve_ns = time.perf_counter_ns() - start
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    verify_start = time.perf_counter_ns()
    valid, errors = verify_interval_certificate(releases, intervals, certificate)
    verify_ns = time.perf_counter_ns() - verify_start
    if not valid:
        findings.append({"kind": "certificate_replay_failed", "errors": list(errors)})
    if certificate.objective < 3:
        findings.append({"kind": "objective_too_small_for_demand", "objective": certificate.objective})
    if solve_ns / 1_000_000_000.0 > 60.0:
        findings.append({"kind": "dense_interval_runtime_above_reproduction_contract", "solve_seconds": solve_ns / 1_000_000_000.0})

    summary = {
        "schema_version": 1,
        "kind": "ADVERSARIAL_SCALABILITY",
        "status": "PASS" if not findings else "FAIL",
        "contract": "Dense-overlap interval control: 20,000 obligations over 10,000 releases with half-universe width and demand three. This is not a prevalence benchmark; it checks that the interval proof path is not only exercised on sparse favorable inputs. Runtime is reported as evidence and fails only if it exceeds the one-minute reproduction bound on the recorded environment.",
        "algorithm": certificate.proof_kind,
        "release_count": len(releases),
        "obligation_count": len(intervals),
        "interval_width": 5000,
        "demand": 3,
        "selected_count": certificate.objective,
        "solve_seconds": solve_ns / 1_000_000_000.0,
        "verify_seconds": verify_ns / 1_000_000_000.0,
        "runtime_seconds_bound": 60.0,
        "peak_traced_bytes": peak,
        "problem_sha256": certificate.problem_sha256,
        "finding_count": len(findings),
        "findings": findings,
    }
    output = ROOT / "verification" / "adversarial_scalability.json"
    output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
