from __future__ import annotations

from action_suites.flow import Exclusion, LOCKED_STAGE_ORDER, Stage, StageCount, validate_stage_flow


def test_complete_stage_flow_passes() -> None:
    values = [10, 10, 9, 9, 8, 12, 3, 4, 2]
    counts = [
        StageCount(stage, value, "VERIFIED", str(index) * 64)
        for index, (stage, value) in enumerate(zip(LOCKED_STAGE_ORDER, values, strict=True), start=1)
    ]
    exclusions = [
        Exclusion(
            "C-GOVULNDB", Stage.SYNTAX_DECODED_MEMBERS, Stage.ADAPTER_SUPPORTED_MEMBERS,
            1, "GO_NATIVE_REPORT_NO_FROZEN_PRIMARY_ADAPTER", True,
        )
    ]
    assert validate_stage_flow(counts, exclusions)[0]


def test_unverified_stage_fails() -> None:
    counts = [StageCount(stage, None, "UNVERIFIED") for stage in LOCKED_STAGE_ORDER]
    passed, errors = validate_stage_flow(counts)
    assert not passed
    assert len(errors) == len(LOCKED_STAGE_ORDER)
