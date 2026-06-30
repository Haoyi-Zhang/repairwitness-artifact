from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Sequence


class Stage(str, Enum):
    PROJECTED_MEMBERS = "projected_members"
    SYNTAX_DECODED_MEMBERS = "syntax_decoded_members"
    ADAPTER_SUPPORTED_MEMBERS = "frozen_adapter_supported_members"
    RECOGNIZED_ADVISORY_RECORDS = "recognized_advisory_records"
    CLAIM_BEARING_MEMBERS = "claim_bearing_members"
    NORMALIZED_CLAIMS = "normalized_claims"
    ALIAS_PACKAGE_GROUPS = "alias_package_groups"
    QUALIFIED_EDGES = "qualified_edges"
    PACKAGES_WITH_TERMINAL_RELEASE_ROWS = "packages_with_terminal_release_universe_rows"


LOCKED_STAGE_ORDER: tuple[Stage, ...] = tuple(Stage)


@dataclass(frozen=True)
class StageCount:
    stage: Stage
    count: int | None
    status: str
    evidence_sha256: str | None = None

    def __post_init__(self) -> None:
        if self.count is not None and self.count < 0:
            raise ValueError("stage counts cannot be negative")
        if self.status not in {"VERIFIED", "UNVERIFIED", "MISSING"}:
            raise ValueError(f"unsupported stage status: {self.status}")
        if self.status == "VERIFIED" and self.count is None:
            raise ValueError("a verified stage requires a count")


@dataclass(frozen=True)
class Exclusion:
    source_id: str
    from_stage: Stage
    to_stage: Stage
    count: int
    reason_code: str
    outcome_blind: bool

    def __post_init__(self) -> None:
        if self.count <= 0:
            raise ValueError("exclusion counts must be positive")
        if not self.outcome_blind:
            raise ValueError("pre-analysis exclusions must be outcome-blind")
        if LOCKED_STAGE_ORDER.index(self.to_stage) <= LOCKED_STAGE_ORDER.index(
            self.from_stage
        ):
            raise ValueError("exclusion transition must advance through the stage order")


def validate_stage_flow(
    counts: Sequence[StageCount],
    exclusions: Sequence[Exclusion] = (),
) -> tuple[bool, tuple[str, ...]]:
    errors: list[str] = []
    by_stage: Mapping[Stage, StageCount] = {row.stage: row for row in counts}
    if len(by_stage) != len(counts):
        errors.append("duplicate stage rows")
    missing = [stage.value for stage in LOCKED_STAGE_ORDER if stage not in by_stage]
    if missing:
        errors.append(f"missing stages: {missing}")
        return False, tuple(errors)

    for stage in LOCKED_STAGE_ORDER:
        row = by_stage[stage]
        if row.status != "VERIFIED" or row.count is None:
            errors.append(f"stage {stage.value} is not byte-verified")

    if errors:
        return False, tuple(errors)

    p = by_stage[Stage.PROJECTED_MEMBERS].count
    s = by_stage[Stage.SYNTAX_DECODED_MEMBERS].count
    a = by_stage[Stage.ADAPTER_SUPPORTED_MEMBERS].count
    r = by_stage[Stage.RECOGNIZED_ADVISORY_RECORDS].count
    c = by_stage[Stage.CLAIM_BEARING_MEMBERS].count
    n = by_stage[Stage.NORMALIZED_CLAIMS].count
    g = by_stage[Stage.ALIAS_PACKAGE_GROUPS].count
    t = by_stage[Stage.PACKAGES_WITH_TERMINAL_RELEASE_ROWS].count
    assert None not in (p, s, a, r, c, n, g, t)
    if not (p >= s >= a >= r >= c):  # type: ignore[operator]
        errors.append("member-stage counts are not monotonically non-increasing")
    if n < c:  # type: ignore[operator]
        errors.append("normalized claims cannot be fewer than claim-bearing members")
    if g > n:  # type: ignore[operator]
        errors.append("alias-package groups cannot exceed normalized claims")
    if t > g:  # type: ignore[operator]
        errors.append("terminal release packages cannot exceed alias-package groups")

    stage_index = {stage: index for index, stage in enumerate(LOCKED_STAGE_ORDER)}
    for exclusion in exclusions:
        if stage_index[exclusion.to_stage] <= stage_index[exclusion.from_stage]:
            errors.append(f"invalid exclusion transition: {exclusion.reason_code}")

    return not errors, tuple(errors)
