from __future__ import annotations

import stat
import zipfile
from pathlib import Path

from .audit import audit_repository, iter_publishable_files
from .canonical import sha256_file


_FIXED_TIMESTAMP = (2020, 1, 1, 0, 0, 0)


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def create_deterministic_zip(root: Path | str, output: Path | str) -> dict[str, object]:
    root_path = Path(root).resolve()
    output_path = Path(output).resolve()
    if _is_relative_to(output_path, root_path):
        raise ValueError("release archive output must be outside the audited project tree")
    passed, errors = audit_repository(root_path)
    if not passed:
        raise ValueError("artifact audit failed: " + "; ".join(errors))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(
        output_path,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for path in iter_publishable_files(root_path):
            relative = path.relative_to(root_path).as_posix()
            info = zipfile.ZipInfo(relative, _FIXED_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, path.read_bytes())
    return {
        "path": output_path.name,
        "sha256": sha256_file(output_path),
        "bytes": output_path.stat().st_size,
    }
