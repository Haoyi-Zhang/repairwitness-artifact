#!/usr/bin/env python3
"""Safely extract a combined release ZIP and run smoke checks."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
ARTIFACT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ARTIFACT_ROOT))

from repairwitness.package import archive_report, safe_extract_release  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    archive_path = args.archive.resolve()
    with tempfile.TemporaryDirectory(prefix="repairwitness-clean-") as temp:
        extracted = Path(temp) / "release"
        extracted.mkdir()
        manifest = safe_extract_release(archive_path, extracted)
        project = extracted / manifest.project
        top = {path.name for path in project.iterdir()}
        expected_top = {"RELEASE_MANIFEST.json", "paper", "artifact"}
        if top != expected_top:
            raise ValueError(f"unexpected top-level entries: {sorted(top)}")
        command = [sys.executable, "artifact/scripts/smoke.py", "--project-root", str(project)]
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": str(project / "artifact")}
        completed = subprocess.run(command, cwd=project, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
        report = {
            "schema_version": 1,
            "kind": "CLEAN_EXTRACTION_REPLAY",
            "status": "PASS" if completed.returncode == 0 else "FAIL",
            "archive": archive_path.name,
            "archive_report": archive_report(archive_path),
            "manifest_project": manifest.project,
            "manifest_subject_sha256": manifest.subject_sha256,
            "returncode": completed.returncode,
            "output_tail": completed.stdout[-3000:],
        }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
