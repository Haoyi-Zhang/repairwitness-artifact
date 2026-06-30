from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from .canonical import length_prefixed_path_content_digest


_FORBIDDEN_DIRECTORY_NAMES = {
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".git",
    "node_modules",
    "tmp",
    "temp",
    "logs",
}
_FORBIDDEN_SUFFIXES = {
    ".aux",
    ".bbl",
    ".blg",
    ".log",
    ".out",
    ".synctex.gz",
    ".pyc",
    ".pyo",
}
_ALLOWED_TOP_LEVEL = {"paper", "artifact"}
_ALLOWED_PAPER_NAMES = {
    "main.tex",
    "supplement.tex",
    "references.bib",
    "main.pdf",
    "supplement.pdf",
    ".gitignore",
}
_RUN_LOCAL_OUTPUTS = {
    "artifact/verification/clean_replay.json",
    "artifact/verification/local_reproduction.json",
}
_FORBIDDEN_RELEASE_LABEL_RE = re.compile(
    r"(^|[_\-.])(" + "fin" + r"al|" + "sub" + r"mission|v[0-9]+)([_\-.]|$)",
    re.IGNORECASE,
)


def _forbidden_text_patterns() -> tuple[tuple[str, re.Pattern[str]], ...]:
    # Sensitive literals are assembled to keep the scanner from matching its own source.
    model_vendor = "Open" + "AI"
    chat_product = "Chat" + "GPT"
    runtime_mount = "/" + "mnt" + "/"
    temporary_root = "/" + "tmp" + "/"
    credential_prefixes = ("ghp" + "_", "github" + "_pat_", "sk" + "-")
    credential_pattern = "(?:" + "|".join(
        re.escape(prefix) for prefix in credential_prefixes
    ) + r")[A-Za-z0-9_-]{12,}"
    patterns = (
        ("unix absolute home path", re.compile(r"/(?:home|Users)/[^/\s]+/")),
        ("runtime mount path", re.compile(re.escape(runtime_mount))),
        ("temporary absolute path", re.compile(re.escape(temporary_root))),
        ("windows absolute path", re.compile(r"[A-Za-z]:\\(?:Users|Documents)\\")),
        ("model vendor name", re.compile(re.escape(model_vendor), re.IGNORECASE)),
        ("chat product name", re.compile(re.escape(chat_product), re.IGNORECASE)),
        (("dialogue " + "role marker"), re.compile(r"\b(?:user|assistant):\s", re.IGNORECASE)),
        ("private credential", re.compile(credential_pattern)),
    )
    return patterns


def _looks_textual(path: Path) -> bool:
    return path.suffix.lower() in {
        ".py",
        ".md",
        ".tex",
        ".bib",
        ".json",
        ".jsonl",
        ".csv",
        ".toml",
        ".ini",
        ".txt",
        ".yaml",
        ".yml",
        ".sh",
        ".dat",
    } or path.name in {"LICENSE", "Makefile"}


def audit_repository(
    root: Path | str,
    *,
    allow_release_manifest: bool = False,
) -> tuple[bool, tuple[str, ...]]:
    root_path = Path(root).resolve()
    errors: list[str] = []
    top_level = {path.name for path in root_path.iterdir()}
    expected_top_level = set(_ALLOWED_TOP_LEVEL)
    if allow_release_manifest and "RELEASE_MANIFEST.json" in top_level:
        expected_top_level.add("RELEASE_MANIFEST.json")
    if top_level != expected_top_level:
        errors.append(
            f"top-level entries must be exactly {sorted(expected_top_level)}; got {sorted(top_level)}"
        )

    required = {
        "paper/main.tex",
        "paper/supplement.tex",
        "paper/references.bib",
        "artifact/README.md",
        "artifact/reproduction.md",
        "artifact/study_protocol.md",
        "artifact/source_manifest.csv",
    }
    for relative in sorted(required):
        if not (root_path / relative).is_file():
            errors.append(f"missing required file: {relative}")

    for path in root_path.rglob("*"):
        relative_path = path.relative_to(root_path)
        relative = relative_path.as_posix()
        if any(part in _FORBIDDEN_DIRECTORY_NAMES for part in relative_path.parts):
            errors.append(f"forbidden directory in path: {relative}")
        if path.is_file():
            if _FORBIDDEN_RELEASE_LABEL_RE.search(path.name):
                errors.append(f"versioned release-label file name: {relative}")
            if any(path.name.endswith(suffix) for suffix in _FORBIDDEN_SUFFIXES):
                errors.append(f"forbidden generated file: {relative}")
            if relative.startswith("paper/"):
                data_file = relative.startswith("paper/data/") and path.suffix == ".dat"
                if not data_file and path.name not in _ALLOWED_PAPER_NAMES:
                    errors.append(f"unexpected paper file: {relative}")
            if _looks_textual(path):
                try:
                    text = path.read_text(encoding="utf-8")
                except UnicodeDecodeError:
                    errors.append(f"declared text file is not UTF-8: {relative}")
                    continue
                for label, pattern in _forbidden_text_patterns():
                    if pattern.search(text):
                        errors.append(f"{label} found in {relative}")
    return not errors, tuple(sorted(set(errors)))


def iter_publishable_files(root: Path | str) -> Iterable[Path]:
    root_path = Path(root).resolve()
    for path in sorted(root_path.rglob("*")):
        if not path.is_file():
            continue
        relative_path = path.relative_to(root_path)
        relative = relative_path.as_posix()
        if relative == "RELEASE_MANIFEST.json":
            continue
        if any(part in _FORBIDDEN_DIRECTORY_NAMES for part in relative_path.parts):
            continue
        if any(path.name.endswith(suffix) for suffix in _FORBIDDEN_SUFFIXES):
            continue
        if relative in _RUN_LOCAL_OUTPUTS:
            continue
        yield path

def iter_audit_subject_files(root: Path | str) -> Iterable[Path]:
    """Yield release bytes covered by the clean-replay attestation.

    Verification outputs are excluded to avoid circular self-attestation: they are
    evidence about the release subject, not part of the subject itself.
    """

    root_path = Path(root).resolve()
    for path in iter_publishable_files(root_path):
        relative = path.relative_to(root_path).as_posix()
        if relative.startswith("artifact/verification/"):
            continue
        yield path


def audit_subject_digest(root: Path | str) -> str:
    root_path = Path(root).resolve()
    return length_prefixed_path_content_digest(
        (path.relative_to(root_path).as_posix(), path.read_bytes())
        for path in iter_audit_subject_files(root_path)
    )
