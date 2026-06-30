from __future__ import annotations

import pytest

from action_suites.model import (
    Action, ActionKind, BlockerCode, actions_separate, classify_edge, witness_releases,
)


def test_unknown_is_never_a_witness() -> None:
    unknown = Action(ActionKind.UNKNOWN, blocker=BlockerCode.INDETERMINATE)
    repair = Action(ActionKind.REPAIR_WITHOUT_PUBLIC_TARGET)
    assert not actions_separate(unknown, repair)
    assert witness_releases(("1.0",), {"1.0": unknown}, {"1.0": repair}) == frozenset()
    assert classify_edge(("1.0",), {"1.0": unknown}, {"1.0": repair}) == "INDETERMINATE"


def test_unequal_concrete_actions_separate() -> None:
    left = Action(ActionKind.NO_ACTION)
    right = Action(ActionKind.UPGRADE_TO_ADVISORY_TARGET, targets=("2.0",))
    assert actions_separate(left, right)


def test_action_shape_is_validated() -> None:
    with pytest.raises(ValueError):
        Action(ActionKind.UNKNOWN)
    with pytest.raises(ValueError):
        Action(ActionKind.NO_ACTION, targets=("2.0",))
