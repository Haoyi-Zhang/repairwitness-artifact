#!/usr/bin/env python3
"""Verify the compiled paper PDFs and citation ledger."""
from __future__ import annotations

import csv
import hashlib
import json
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ARTIFACT_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = ARTIFACT_ROOT.parent
sys.path.insert(0, str(ARTIFACT_ROOT))

from action_suites.canonical import atomic_write_json  # noqa: E402

try:
    from pypdf import PdfReader
except Exception as exc:  # pragma: no cover - environment failure
    raise SystemExit(f"pypdf is required for PDF verification: {exc}") from exc


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cited_keys(tex: str) -> set[str]:
    keys: set[str] = set()
    for match in re.finditer(r"\\cite\{([^}]+)\}", tex):
        keys.update(key.strip() for key in match.group(1).split(",") if key.strip())
    return keys


def bib_keys(bib: str) -> set[str]:
    return set(re.findall(r"@[A-Za-z]+\s*\{\s*([^,\s]+)", bib))


def ledger_keys(path: Path) -> set[str]:
    with path.open(encoding="utf-8") as handle:
        return {row["bib_key"] for row in csv.DictReader(handle)}


def font_descriptors(font: object) -> list[object]:
    font_obj = font.get_object()
    descriptors: list[object] = []
    descriptor = font_obj.get("/FontDescriptor")
    if descriptor is not None:
        descriptors.append(descriptor.get_object())
    for descendant in font_obj.get("/DescendantFonts", []):
        descendant_obj = descendant.get_object()
        descendant_descriptor = descendant_obj.get("/FontDescriptor")
        if descendant_descriptor is not None:
            descriptors.append(descendant_descriptor.get_object())
    return descriptors


def fonts_embedded(reader: PdfReader) -> bool:
    for page in reader.pages:
        resources = page.get("/Resources") or {}
        fonts = resources.get("/Font") or {}
        for font in fonts.values():
            descriptors = font_descriptors(font)
            if not descriptors:
                return False
            for descriptor in descriptors:
                if not any(name in descriptor for name in ("/FontFile", "/FontFile2", "/FontFile3")):
                    return False
    return True


def main() -> int:
    paper = PROJECT_ROOT / "paper"
    verification = ARTIFACT_ROOT / "verification"
    main_pdf = paper / "main.pdf"
    supplement_pdf = paper / "supplement.pdf"
    main_reader = PdfReader(main_pdf)
    supplement_reader = PdfReader(supplement_pdf)

    reference_start = None
    reference_prefix = ""
    for index, page in enumerate(main_reader.pages, start=1):
        text = page.extract_text() or ""
        position = text.find("REFERENCES")
        if position >= 0:
            reference_start = index
            reference_prefix = text[:position].strip()
            break

    tex_keys = cited_keys((paper / "main.tex").read_text(encoding="utf-8"))
    bib_key_set = bib_keys((paper / "references.bib").read_text(encoding="utf-8"))
    ledger_key_set = ledger_keys(ARTIFACT_ROOT / "reference_ledger.csv")

    errors: list[str] = []
    if tex_keys != bib_key_set:
        errors.append(f"citation/BibTeX mismatch: cited={len(tex_keys)} bib={len(bib_key_set)}")
    if tex_keys != ledger_key_set:
        errors.append(f"citation/reference-ledger mismatch: cited={len(tex_keys)} ledger={len(ledger_key_set)}")
    if not 70 <= len(tex_keys) <= 80:
        errors.append(f"reference count outside release interval: {len(tex_keys)}")
    if len(main_reader.pages) != 12:
        errors.append(f"main PDF page count is {len(main_reader.pages)}, expected 12")
    if reference_start != 11:
        errors.append(f"references start on page {reference_start}, expected 11")
    if reference_prefix:
        errors.append("body text appears before REFERENCES on the first reference page")
    if len(supplement_reader.pages) != 9:
        errors.append(f"supplement PDF page count is {len(supplement_reader.pages)}, expected 9")
    if not fonts_embedded(main_reader) or not fonts_embedded(supplement_reader):
        errors.append("one or more PDF fonts are not embedded")

    reference_pages = (
        list(range(reference_start, len(main_reader.pages) + 1))
        if reference_start is not None
        else []
    )
    report = {
        "schema_version": 1,
        "kind": "PDF_AND_REFERENCE_ATTESTATION",
        "status": "PASS" if not errors else "FAIL",
        "main_pages": len(main_reader.pages),
        "main_text_pages": (reference_start - 1) if reference_start is not None else None,
        "reference_pages": reference_pages,
        "supplement_pages": len(supplement_reader.pages),
        "reference_count": len(tex_keys),
        "bib_entries": len(bib_key_set),
        "cited_keys": len(tex_keys),
        "ledger_entries": len(ledger_key_set),
        "key_sets_equal": tex_keys == bib_key_set == ledger_key_set,
        "fonts_embedded": not any("fonts" in error for error in errors),
        "main_pdf_sha256": sha256(main_pdf),
        "supplement_pdf_sha256": sha256(supplement_pdf),
        "paper_size": "US Letter",
        "errors": errors,
    }
    atomic_write_json(verification / "pdf_attestation.json", report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
