"""OR-Library set-cover benchmark import and conversion.

The 65 Beasley non-unicost set-cover instances are external algorithmic stress tests.
They do not contribute to security-advisory study denominators.  This module parses the
native token format, converts it into RepairWitness obligations/costs, verifies known
best objective values when available, and records network receipts for downloaded files.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from .canonical import atomic_write_json, canonical_json_bytes, sha256_bytes
from .net import NetworkPolicy, NetworkReceipt, download_to_file
from .oracle import solve_milp_oracle
from .suite import SuiteCertificate, solve_exact, verify_certificate


class OrlibFormatError(ValueError):
    """The input is not a valid bounded OR-Library SCP instance."""


@dataclass(frozen=True)
class OrlibInstance:
    name: str
    row_count: int
    column_count: int
    costs: tuple[int, ...]
    row_columns: tuple[tuple[int, ...], ...]
    source_sha256: str

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("instance name must be non-empty")
        if self.row_count < 1 or self.column_count < 1:
            raise ValueError("instance dimensions must be positive")
        if len(self.costs) != self.column_count:
            raise ValueError("column cost vector length mismatch")
        if len(self.row_columns) != self.row_count:
            raise ValueError("row incidence vector length mismatch")
        if any(cost < 1 for cost in self.costs):
            raise ValueError("OR-Library costs must be positive")
        for row_index, columns in enumerate(self.row_columns, start=1):
            if not columns:
                raise ValueError(f"row {row_index} has no covering columns")
            if tuple(sorted(set(columns))) != columns:
                raise ValueError(f"row {row_index} columns are not unique and sorted")
            if columns[0] < 1 or columns[-1] > self.column_count:
                raise ValueError(f"row {row_index} references an out-of-range column")
        if len(self.source_sha256) != 64:
            raise ValueError("source_sha256 must be a SHA-256 hex digest")

    @property
    def digest(self) -> str:
        return sha256_bytes(
            canonical_json_bytes(
                {
                    "name": self.name,
                    "row_count": self.row_count,
                    "column_count": self.column_count,
                    "costs": list(self.costs),
                    "row_columns": [list(row) for row in self.row_columns],
                    "source_sha256": self.source_sha256,
                }
            )
        )

    def to_problem(self) -> tuple[dict[str, frozenset[str]], dict[str, int]]:
        obligations = {
            f"row-{row_index:05d}": frozenset(f"column-{column:06d}" for column in columns)
            for row_index, columns in enumerate(self.row_columns, start=1)
        }
        costs = {f"column-{index:06d}": cost for index, cost in enumerate(self.costs, start=1)}
        return obligations, costs


@dataclass(frozen=True)
class OrlibManifestEntry:
    name: str
    url: str
    best_known_cost: int

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> OrlibManifestEntry:
        name = str(value.get("name", ""))
        url = str(value.get("url", ""))
        cost = value.get("best_known_cost")
        if isinstance(cost, bool) or not isinstance(cost, int):
            raise ValueError("best_known_cost must be an integer")
        if cost < 1:
            raise ValueError("best_known_cost must be positive")
        return cls(name=name, url=url, best_known_cost=cost)


@dataclass(frozen=True)
class OrlibRunResult:
    name: str
    instance_sha256: str
    certificate_status: str
    lower_bound: int
    upper_bound: int
    best_known_cost: int
    matches_best_known: bool
    certificate_replay: bool
    independent_milp_cost: int | None

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "instance_sha256": self.instance_sha256,
            "certificate_status": self.certificate_status,
            "lower_bound": self.lower_bound,
            "upper_bound": self.upper_bound,
            "best_known_cost": self.best_known_cost,
            "matches_best_known": self.matches_best_known,
            "certificate_replay": self.certificate_replay,
            "independent_milp_cost": self.independent_milp_cost,
        }


def _tokens(content: bytes) -> list[int]:
    try:
        text = content.decode("ascii")
    except UnicodeDecodeError as exc:
        raise OrlibFormatError("OR-Library input must be ASCII") from exc
    values: list[int] = []
    for position, token in enumerate(text.split(), start=1):
        try:
            value = int(token)
        except ValueError as exc:
            raise OrlibFormatError(f"token {position} is not an integer: {token!r}") from exc
        values.append(value)
    return values


def parse_orlib_scp(
    content: bytes,
    *,
    name: str,
    max_rows: int = 100_000,
    max_columns: int = 2_000_000,
    max_incidences: int = 100_000_000,
) -> OrlibInstance:
    """Parse the native Beasley SCP format with explicit resource limits."""

    values = _tokens(content)
    if len(values) < 2:
        raise OrlibFormatError("instance lacks row and column counts")
    cursor = 0

    def take(context: str) -> int:
        nonlocal cursor
        if cursor >= len(values):
            raise OrlibFormatError(f"unexpected end of file while reading {context}")
        value = values[cursor]
        cursor += 1
        return value

    rows = take("row count")
    columns = take("column count")
    if rows < 1 or rows > max_rows:
        raise OrlibFormatError(f"row count {rows} is outside [1, {max_rows}]")
    if columns < 1 or columns > max_columns:
        raise OrlibFormatError(f"column count {columns} is outside [1, {max_columns}]")
    costs = tuple(take(f"cost {index}") for index in range(1, columns + 1))
    if any(cost < 1 for cost in costs):
        raise OrlibFormatError("all column costs must be positive")
    row_columns: list[tuple[int, ...]] = []
    incidence_count = 0
    for row in range(1, rows + 1):
        width = take(f"row {row} incidence count")
        if width < 1 or width > columns:
            raise OrlibFormatError(f"row {row} incidence count {width} is outside [1, {columns}]")
        incidence_count += width
        if incidence_count > max_incidences:
            raise OrlibFormatError(f"incidence count exceeds limit {max_incidences}")
        entries = tuple(take(f"row {row} column") for _ in range(width))
        if any(column < 1 or column > columns for column in entries):
            raise OrlibFormatError(f"row {row} references an out-of-range column")
        if len(set(entries)) != len(entries):
            raise OrlibFormatError(f"row {row} repeats a column")
        row_columns.append(tuple(sorted(entries)))
    if cursor != len(values):
        raise OrlibFormatError(
            f"instance contains {len(values) - cursor} trailing integer token(s)"
        )
    return OrlibInstance(
        name=name,
        row_count=rows,
        column_count=columns,
        costs=costs,
        row_columns=tuple(row_columns),
        source_sha256=sha256_bytes(content),
    )


def load_orlib_manifest(path: Path | str) -> tuple[OrlibManifestEntry, ...]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, Mapping) or not isinstance(raw.get("instances"), list):
        raise ValueError("OR-Library manifest must contain an instances array")
    entries = tuple(OrlibManifestEntry.from_dict(row) for row in raw["instances"])
    names = [entry.name for entry in entries]
    if names != sorted(names) or len(set(names)) != len(names):
        raise ValueError("OR-Library manifest names must be unique and sorted")
    return entries


def download_orlib_instance(
    entry: OrlibManifestEntry,
    destination: Path | str,
) -> NetworkReceipt:
    """Download one public instance and preserve its HTTPS receipt."""

    return download_to_file(
        entry.url,
        destination,
        policy=NetworkPolicy(
            allowed_hosts=frozenset({"people.brunel.ac.uk"}),
            max_bytes=512 * 1024 * 1024,
            timeout_seconds=180,
            attempts=3,
            accepted_media_types=("text/plain", "application/octet-stream"),
        ),
        accept="text/plain, application/octet-stream",
    )


def run_orlib_instance(
    instance: OrlibInstance,
    *,
    best_known_cost: int,
    max_nodes: int | None = None,
    independent_milp: bool = False,
) -> tuple[SuiteCertificate, OrlibRunResult]:
    """Run the primary certified solver and optional independent MILP."""

    obligations, costs = instance.to_problem()
    certificate = solve_exact(obligations, costs=costs, max_nodes=max_nodes)
    replay, _errors = verify_certificate(
        obligations,
        certificate,
        costs=costs,
        verify_optimality=certificate.status == "EXACT" and len(costs) <= 22,
    )
    milp_cost: int | None = None
    if independent_milp:
        milp_cost = solve_milp_oracle(obligations, costs=costs).optimal_cost
    result = OrlibRunResult(
        name=instance.name,
        instance_sha256=instance.digest,
        certificate_status=certificate.status,
        lower_bound=certificate.lower_bound,
        upper_bound=certificate.upper_bound,
        best_known_cost=best_known_cost,
        matches_best_known=certificate.upper_bound == best_known_cost,
        certificate_replay=replay,
        independent_milp_cost=milp_cost,
    )
    return certificate, result


def write_orlib_run_summary(
    path: Path | str,
    rows: Iterable[OrlibRunResult],
) -> None:
    ordered = sorted(rows, key=lambda row: row.name)
    atomic_write_json(
        path,
        {
            "schema_version": 1,
            "benchmark": "OR-LIBRARY-SCP65",
            "scope": "external algorithm benchmark; excluded from advisory-study denominators",
            "instances": [row.to_dict() for row in ordered],
        },
    )
