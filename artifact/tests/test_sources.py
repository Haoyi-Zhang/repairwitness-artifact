from __future__ import annotations

import io
import tarfile
from pathlib import Path

from action_suites.sources import LOCKED_PROJECTION_RULES, iter_projected_archive_members, syntax_decodable


def test_go_native_report_is_projected_but_adapter_unsupported(tmp_path: Path) -> None:
    archive = tmp_path / "go.tar.gz"
    with tarfile.open(archive, "w:gz") as handle:
        for name, content in (
            ("repo/data/osv/GO-1.json", b'{"id":"GO-1"}'),
            ("repo/data/reports/GO-1.yaml", b'id: GO-1\n'),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(content)
            handle.addfile(info, io.BytesIO(content))
    rows = list(iter_projected_archive_members(archive, LOCKED_PROJECTION_RULES["C-GOVULNDB"]))
    assert len(rows) == 2
    report = next(row for row in rows if row[0].endswith(".yaml"))
    assert report[2] is False
    assert report[3] == "GO_NATIVE_REPORT_NO_FROZEN_PRIMARY_ADAPTER"


def test_rustsec_syntax_decoder_parses_front_matter() -> None:
    valid = b'```toml\n[advisory]\nid="RUSTSEC-1"\n```\n'
    invalid = b'```toml\nnot toml\n```\n'
    assert syntax_decodable("a.md", valid)
    assert not syntax_decodable("a.md", invalid)
