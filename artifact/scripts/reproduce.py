#!/usr/bin/env python3
"""One-command offline reproduction for RepairWitness."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent


def run(command: list[str], cwd: Path = ROOT) -> str:
    print("+", " ".join(command), flush=True)
    env = {**os.environ, "PYTHONPATH": str(ROOT), "PYTHONDONTWRITEBYTECODE": "1"}
    result = subprocess.run(command, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    print(result.stdout, end="")
    if result.returncode:
        raise SystemExit(result.returncode)
    return result.stdout


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def remove_bytecode_caches() -> None:
    for cache in ROOT.rglob("__pycache__"):
        if cache.is_dir():
            shutil.rmtree(cache)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--outdir",
        type=Path,
        default=None,
        help="Directory for run-local archives and reproduction reports; defaults outside the project tree.",
    )
    args = parser.parse_args()
    outdir = (
        args.outdir.resolve()
        if args.outdir
        else Path(tempfile.mkdtemp(prefix="repairwitness-reproduction-")).resolve()
    )
    if outdir == REPO.resolve() or REPO.resolve() in outdir.parents:
        raise SystemExit("reproduction output directory must be outside the project tree")
    outdir.mkdir(parents=True, exist_ok=True)

    run([sys.executable, "scripts/verify_offline_install_contract.py"])
    run([sys.executable, "scripts/run_tests_with_coverage.py"])
    run([sys.executable, "scripts/run_method_smoke.py"])
    run([sys.executable, "scripts/validate_results.py"])
    run([sys.executable, "scripts/verify_pdf_references.py"])
    remove_bytecode_caches()
    run([sys.executable, "scripts/audit_artifact.py", "--root", str(REPO), "--write-attestation"])
    run([sys.executable, "scripts/refresh_release_attestation.py"])
    first_combined = outdir / "repairwitness-combined-1.zip"
    first_code = outdir / "repairwitness-code-1.zip"
    second_combined = outdir / "repairwitness-combined-2.zip"
    second_code = outdir / "repairwitness-code-2.zip"
    clean_replay = outdir / "clean_replay.json"
    release_attestation = outdir / "release_attestation.json"
    run([sys.executable, "scripts/package_release.py", "--project-root", str(REPO), "--combined", str(first_combined), "--code", str(first_code)])
    run([sys.executable, "scripts/package_release.py", "--project-root", str(REPO), "--combined", str(second_combined), "--code", str(second_code)])
    if first_combined.read_bytes() != second_combined.read_bytes() or first_code.read_bytes() != second_code.read_bytes():
        raise SystemExit("deterministic archive mismatch")
    run([sys.executable, "scripts/clean_replay.py", str(first_combined), "--output", str(clean_replay)])
    run(
        [
            sys.executable,
            "scripts/refresh_release_attestation.py",
            "--combined",
            str(first_combined),
            "--code",
            str(first_code),
            "--clean-replay",
            str(clean_replay),
            "--output",
            str(release_attestation),
        ]
    )
    report = {
        "schema_version": 1,
        "kind": "LOCAL_REPRODUCTION",
        "status": "PASS",
        "output_directory": str(outdir),
        "self_test_combined_sha256": digest(first_combined),
        "self_test_code_sha256": digest(first_code),
        "tests": "PASS",
        "method_smoke": "PASS",
        "result_validation": "PASS",
        "anonymous_audit": "PASS",
        "deterministic_packaging": "PASS",
        "clean_extraction_replay": "PASS",
        "offline_install_contract": "PASS",
        "coverage_contract": "PASS",
        "safetydb_historical_scope": "PASS",
        "synthetic_advisory_benchmark": "PASS",
        "public_advisory_overlap": "PASS",
        "adversarial_scalability": "PASS",
        "optimization_impact": "PASS",
        "baseline_fairness": "PASS",
        "temporal_scope": "PASS",
    }
    (outdir / "local_reproduction.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    print("REPAIRWITNESS_REPRODUCTION=PASS")


if __name__ == "__main__":
    main()
