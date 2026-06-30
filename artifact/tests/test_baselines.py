from __future__ import annotations

import pytest

from action_suites.adapters import StructuralClaim
from action_suites.baselines import (
    ComparatorDecision,
    action_relation,
    affected_set_equality,
    confusion_counts,
    normalized_structural_equality,
    raw_record_equality,
    universe_affected_equality,
)
from action_suites.model import Action, ActionKind, BlockerCode


def _claim(
    *,
    claim_id: str = "c",
    source_id: str = "C-GHAD",
    record_id: str = "r",
    target: str = "2.0",
    version: str = "",
) -> StructuralClaim:
    return StructuralClaim(
        claim_id=claim_id,
        source_id=source_id,
        record_id=record_id,
        package_ecosystem="PyPI",
        package_name="demo",
        aliases=("CVE-1",),
        withdrawn=False,
        ranges=({"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": target}]},),
        versions=(version,) if version else (),
        advisory_targets=(target,),
        alternative_actions=(),
        source_path=f"{record_id}.json",
    )


def test_comparator_decision_rejects_unknown_labels() -> None:
    with pytest.raises(ValueError, match="invalid comparator"):
        ComparatorDecision("X", "MAYBE", "bad")


def test_raw_and_normalized_equality_cover_equivalent_and_divergent_cases() -> None:
    assert raw_record_equality(b"same", b"same").decision == "EQUIVALENT"
    assert raw_record_equality(b"left", b"right").decision == "DIVERGENT"

    left = _claim(claim_id="left", source_id="S1", record_id="R1")
    right = _claim(claim_id="right", source_id="S2", record_id="R2")
    assert normalized_structural_equality(left, right).decision == "EQUIVALENT"
    changed = _claim(claim_id="right", source_id="S2", record_id="R2", target="3.0")
    assert normalized_structural_equality(left, changed).decision == "DIVERGENT"


def test_affected_set_abstains_on_unknown() -> None:
    decision = affected_set_equality(("1",), {"1": None}, {"1": True})
    assert decision.decision == "ABSTAIN"


def test_affected_set_equivalence_and_divergence() -> None:
    releases = ("1", "2")
    assert affected_set_equality(releases, {"1": True, "2": False}, {"1": True, "2": False}).decision == "EQUIVALENT"
    assert affected_set_equality(releases, {"1": True, "2": False}, {"1": False, "2": False}).decision == "DIVERGENT"


def test_action_relation_distinguishes_missing_unknown_equal_and_divergent() -> None:
    releases = ("1", "2")
    no_action = Action(ActionKind.NO_ACTION)
    upgrade = Action(ActionKind.UPGRADE_TO_ADVISORY_TARGET, targets=("2",))
    unknown = Action(ActionKind.UNKNOWN, blocker=BlockerCode.INDETERMINATE)

    assert action_relation(releases, {"1": no_action}, {"1": no_action, "2": no_action}).decision == "ABSTAIN"
    assert action_relation(("1",), {"1": unknown}, {"1": no_action}).decision == "ABSTAIN"
    assert action_relation(("1",), {"1": no_action}, {"1": no_action}).decision == "EQUIVALENT"
    assert action_relation(("1",), {"1": no_action}, {"1": upgrade}).decision == "DIVERGENT"


def test_confusion_counts_keep_abstentions() -> None:
    counts = confusion_counts(
        ["DIVERGENT", "EQUIVALENT", "DIVERGENT"],
        ["DIVERGENT", "DIVERGENT", "ABSTAIN"],
    )
    assert counts == {"tp": 1, "tn": 0, "fp": 1, "fn": 0, "abstain": 1}


def test_confusion_counts_rejects_mismatched_vectors_and_unknown_pairs() -> None:
    with pytest.raises(ValueError, match="differ in length"):
        confusion_counts(["DIVERGENT"], [])
    assert confusion_counts(["EQUIVALENT", "OTHER"], ["EQUIVALENT", "DIVERGENT"]) == {
        "tp": 0,
        "tn": 1,
        "fp": 0,
        "fn": 0,
        "abstain": 1,
    }


def test_vers_is_range_only_and_ignores_advisory_target() -> None:
    from action_suites.adapters import StructuralClaim
    from action_suites.baselines import vers_equality

    common = dict(
        package_ecosystem="PyPI", package_name="demo", aliases=("CVE-1",),
        withdrawn=False, ranges=({"type": "ECOSYSTEM", "events": [{"introduced": "0"}]},),
        versions=(), alternative_actions=(),
    )
    left = StructuralClaim(
        claim_id="l", source_id="C-GHAD", record_id="a", advisory_targets=("2.0",),
        source_path="a.json", **common,
    )
    right = StructuralClaim(
        claim_id="r", source_id="C-PYPA", record_id="b", advisory_targets=("3.0",),
        source_path="b.yaml", **common,
    )
    assert vers_equality(left, right).decision == "EQUIVALENT"


def test_universe_affected_equality_handles_executable_and_unknown_ranges() -> None:
    left = _claim(target="2.0")
    right = _claim(target="3.0")
    decision = universe_affected_equality(("1.0", "2.5"), left, right)
    assert decision.comparator == "UNIVERS_EQUALITY"
    assert decision.decision == "DIVERGENT"

    unknown = StructuralClaim(
        claim_id="u",
        source_id="C-GHAD",
        record_id="u",
        package_ecosystem="PyPI",
        package_name="demo",
        aliases=(),
        withdrawn=False,
        ranges=({"type": "GIT", "events": []},),
        versions=(),
        advisory_targets=(),
        alternative_actions=(),
        source_path="u.json",
    )
    assert universe_affected_equality(("1.0",), left, unknown).decision == "ABSTAIN"
