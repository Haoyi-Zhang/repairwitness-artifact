#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from action_suites.canonical import atomic_write_json
from action_suites.suite import solve_exact, solve_greedy


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("obligations", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--algorithm", choices=("exact", "greedy"), default="exact")
    parser.add_argument("--max-nodes", type=int)
    arguments = parser.parse_args()
    obligations = json.loads(arguments.obligations.read_text(encoding="utf-8"))
    certificate = (
        solve_exact(obligations, max_nodes=arguments.max_nodes)
        if arguments.algorithm == "exact"
        else solve_greedy(obligations)
    )
    atomic_write_json(arguments.output, certificate.to_dict())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
