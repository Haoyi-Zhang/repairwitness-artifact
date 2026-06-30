from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence, Tuple


class CanonicalizationError(ValueError):
    """Raised when a value cannot be represented by the locked canonical form."""


def canonical_json_bytes(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON bytes.

    The format is deliberately narrow: keys are sorted, insignificant whitespace is
    removed, NaN/Infinity are rejected, and UTF-8 is emitted directly.
    """

    try:
        text = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise CanonicalizationError(str(exc)) from exc
    return (text + "\n").encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path | str) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def length_prefixed_path_content_digest(
    entries: Iterable[Tuple[str, bytes]],
) -> str:
    """Digest sorted path/content pairs without concatenation ambiguity."""

    digest = hashlib.sha256()
    previous: str | None = None
    for path, content in sorted(entries, key=lambda pair: pair[0]):
        if previous == path:
            raise CanonicalizationError(f"duplicate canonical path: {path}")
        previous = path
        path_bytes = path.encode("utf-8")
        digest.update(len(path_bytes).to_bytes(8, "big"))
        digest.update(path_bytes)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def iter_tree_entries(
    root: Path | str,
    *,
    excluded_names: Sequence[str] = (),
) -> Iterator[Tuple[str, bytes]]:
    root_path = Path(root).resolve()
    excluded = set(excluded_names)
    for path in sorted(root_path.rglob("*")):
        if not path.is_file() or any(part in excluded for part in path.parts):
            continue
        relative = path.relative_to(root_path).as_posix()
        yield relative, path.read_bytes()


def sha256_tree(
    root: Path | str,
    *,
    excluded_names: Sequence[str] = (),
) -> str:
    return length_prefixed_path_content_digest(
        iter_tree_entries(root, excluded_names=excluded_names)
    )


def load_json(path: Path | str) -> Any:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def atomic_write_bytes(path: Path | str, data: bytes) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    try:
        with os.fdopen(file_descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, destination)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def atomic_write_json(path: Path | str, value: Any) -> None:
    atomic_write_bytes(path, canonical_json_bytes(value))
