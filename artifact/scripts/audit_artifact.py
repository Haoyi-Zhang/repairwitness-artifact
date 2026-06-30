#!/usr/bin/env python3
"""Audit the anonymous two-directory release tree."""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
sys.dont_write_bytecode = True
from pathlib import Path

ARTIFACT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ARTIFACT_ROOT))

from action_suites.audit import audit_repository, audit_subject_digest
from action_suites.canonical import atomic_write_json


def cited_keys(root: Path) -> set[str]:
    tex = (root / "paper/main.tex").read_text(encoding="utf-8")
    keys: set[str] = set()
    for match in re.finditer(r"\\cite\{([^}]+)\}", tex):
        keys.update(key.strip() for key in match.group(1).split(",") if key.strip())
    return keys


def clean_generated_files(root: Path) -> None:
    for directory_name in ('__pycache__', '.pytest_cache', '.mypy_cache', '.ruff_cache'):
        for directory in root.rglob(directory_name):
            for file in directory.rglob('*'):
                if file.is_file():
                    file.unlink()
            for child in sorted(directory.rglob('*'), reverse=True):
                if child.is_dir():
                    child.rmdir()
            directory.rmdir()


def clean_latex_transients(root: Path) -> None:
    transient_suffixes = {
        ".aux",
        ".bbl",
        ".blg",
        ".fdb_latexmk",
        ".fls",
        ".log",
        ".out",
        ".synctex.gz",
    }
    paper = root / "paper"
    if not paper.is_dir():
        return
    for file in paper.rglob("*"):
        if file.is_file() and any(file.name.endswith(suffix) for suffix in transient_suffixes):
            file.unlink()


def citation_errors(root: Path) -> list[str]:
    errors: list[str] = []
    cited = cited_keys(root)
    bib = (root / "paper/references.bib").read_text(encoding="utf-8")
    bib_keys = set(re.findall(r"@[A-Za-z]+\s*\{\s*([^,\s]+)", bib))
    with (root / "artifact/reference_ledger.csv").open(encoding="utf-8") as handle:
        ledger_keys = {row["bib_key"] for row in csv.DictReader(handle)}
    if cited != bib_keys:
        errors.append(f"citation/BibTeX key mismatch: cited={len(cited)} bib={len(bib_keys)}")
    if cited != ledger_keys:
        errors.append(f"citation/reference-ledger key mismatch: cited={len(cited)} ledger={len(ledger_keys)}")
    return errors


def citation_warnings(root: Path) -> list[str]:
    cited = cited_keys(root)
    if not 70 <= len(cited) <= 80:
        return [f"reference count outside registered release interval: {len(cited)}"]
    return []


def paper_errors(root: Path) -> list[str]:
    errors: list[str] = []
    required = ["main.pdf", "supplement.pdf", "main.tex", "supplement.tex", "references.bib"]
    for name in required:
        if not (root / "paper" / name).is_file():
            errors.append(f"missing paper/{name}")
    for name in ("scalability.dat", "orlib_ratio.dat"):
        if not (root / "paper/data" / name).is_file():
            errors.append(f"missing paper/data/{name}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--write-attestation", action="store_true")
    parser.add_argument("--allow-release-manifest", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    clean_generated_files(root / 'artifact')
    clean_latex_transients(root)
    allow_release_manifest = args.allow_release_manifest or (root / "RELEASE_MANIFEST.json").is_file()
    passed, repository_errors = audit_repository(
        root,
        allow_release_manifest=allow_release_manifest,
    )
    reference_count = len(cited_keys(root))
    errors = list(repository_errors) + citation_errors(root) + paper_errors(root)
    report = {
        "schema_version": 1,
        "kind": "ANONYMOUS_RELEASE_AUDIT",
        "status": "PASS" if not errors else "FAIL",
        "subject_tree_sha256": audit_subject_digest(root),
        "reference_count": reference_count,
        "errors": sorted(set(errors)),
        "warnings": citation_warnings(root),
    }
    if args.write_attestation:
        atomic_write_json(root / "artifact/verification/audit_attestation.json", report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
