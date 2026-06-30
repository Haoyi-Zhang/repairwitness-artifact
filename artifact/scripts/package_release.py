#!/usr/bin/env python3
"""Create deterministic combined and code-only release archives."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ARTIFACT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ARTIFACT_ROOT))

from action_suites.audit import audit_repository, iter_publishable_files
from repairwitness.package import archive_report, create_deterministic_zip, verify_release_zip


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _require_outputs_outside_project(project_root: Path, outputs: tuple[Path, ...]) -> None:
    for output in outputs:
        if _is_relative_to(output.resolve(), project_root):
            raise ValueError(
                "release archive outputs must be outside the audited project tree: "
                f"{output}"
            )


def create_code_zip(project_root: Path, output: Path) -> dict[str, object]:
    if _is_relative_to(output.resolve(), project_root.resolve()):
        raise ValueError("code archive output must be outside the audited project tree")
    passed, errors = audit_repository(project_root)
    if not passed:
        raise ValueError("artifact audit failed: " + "; ".join(errors))
    files = [
        path
        for path in iter_publishable_files(project_root)
        if path.relative_to(project_root).as_posix().startswith("artifact/")
    ]
    create_deterministic_zip(project_root, output, files=files)
    passed_zip, zip_errors, _manifest = verify_release_zip(output)
    report = archive_report(output)
    report["verified"] = passed_zip
    report["verification_errors"] = list(zip_errors)
    return report


def create_combined_zip(project_root: Path, output: Path) -> dict[str, object]:
    passed, errors = audit_repository(project_root)
    if not passed:
        raise ValueError("artifact audit failed: " + "; ".join(errors))
    create_deterministic_zip(project_root, output)
    passed_zip, zip_errors, _manifest = verify_release_zip(output)
    report = archive_report(output)
    report["verified"] = passed_zip
    report["verification_errors"] = list(zip_errors)
    return report


def write_bundle_files(output_dir: Path, report: dict[str, object]) -> dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=True)
    entries = []
    for label in ("combined", "code"):
        row = report[label]
        if isinstance(row, dict):
            entries.append((str(row["archive_sha256"]), str(row["archive"])))
    sha_file = output_dir / "SHA256SUMS"
    sha_file.write_text(
        "".join(
            f"{digest}  {name}\n"
            for digest, name in sorted(entries, key=lambda item: item[1])
        ),
        encoding="utf-8",
    )
    bundle_file = output_dir / "release_bundle.json"
    bundle_file.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {
        "sha256sums": sha_file.name,
        "release_bundle": bundle_file.name,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, default=ARTIFACT_ROOT.parent)
    parser.add_argument("--combined", type=Path, required=True)
    parser.add_argument("--code", type=Path, required=True)
    arguments = parser.parse_args()
    root = arguments.project_root.resolve()
    _require_outputs_outside_project(root, (arguments.combined, arguments.code))
    report = {
        "schema_version": 1,
        "kind": "RELEASE_PACKAGE",
        "combined": create_combined_zip(root, arguments.combined),
        "code": create_code_zip(root, arguments.code),
    }
    report["bundle_files"] = write_bundle_files(arguments.combined.parent, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
