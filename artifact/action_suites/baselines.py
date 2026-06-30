from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping, Sequence

from .adapters import StructuralClaim
from .canonical import canonical_json_bytes
from .model import Action, actions_separate


@dataclass(frozen=True)
class ComparatorDecision:
    comparator: str
    decision: str
    detail: str

    def __post_init__(self) -> None:
        if self.decision not in {"EQUIVALENT", "DIVERGENT", "ABSTAIN"}:
            raise ValueError(f"invalid comparator decision: {self.decision}")


def raw_record_equality(left_bytes: bytes, right_bytes: bytes) -> ComparatorDecision:
    return ComparatorDecision(
        "RAW_RECORD_EQUALITY",
        "EQUIVALENT" if left_bytes == right_bytes else "DIVERGENT",
        "byte-for-byte comparison",
    )


def normalized_structural_equality(
    left: StructuralClaim,
    right: StructuralClaim,
) -> ComparatorDecision:
    excluded = {"claim_id", "source_id", "record_id", "source_path"}
    left_value = {key: value for key, value in left.to_dict().items() if key not in excluded}
    right_value = {key: value for key, value in right.to_dict().items() if key not in excluded}
    return ComparatorDecision(
        "NORMALIZED_STRUCTURAL_EQUALITY",
        "EQUIVALENT"
        if canonical_json_bytes(left_value) == canonical_json_bytes(right_value)
        else "DIVERGENT",
        "source-local identifiers removed before canonical comparison",
    )


def affected_set_equality(
    releases: Sequence[str],
    left_affected: Mapping[str, bool | None],
    right_affected: Mapping[str, bool | None],
) -> ComparatorDecision:
    if any(left_affected.get(release) is None or right_affected.get(release) is None for release in releases):
        return ComparatorDecision(
            "AFFECTED_SET_EQUALITY",
            "ABSTAIN",
            "one or more release judgments are indeterminate",
        )
    left_set = {release for release in releases if left_affected[release]}
    right_set = {release for release in releases if right_affected[release]}
    return ComparatorDecision(
        "AFFECTED_SET_EQUALITY",
        "EQUIVALENT" if left_set == right_set else "DIVERGENT",
        f"left={len(left_set)}, right={len(right_set)} affected releases",
    )


def action_relation(
    releases: Sequence[str],
    left_actions: Mapping[str, Action],
    right_actions: Mapping[str, Action],
) -> ComparatorDecision:
    if any(release not in left_actions or release not in right_actions for release in releases):
        return ComparatorDecision("REPAIR_ACTION_RELATION", "ABSTAIN", "trace is not total")
    if any(actions_separate(left_actions[release], right_actions[release]) for release in releases):
        return ComparatorDecision(
            "REPAIR_ACTION_RELATION",
            "DIVERGENT",
            "at least one public release witnesses unequal concrete actions",
        )
    if any(not left_actions[release].concrete or not right_actions[release].concrete for release in releases):
        return ComparatorDecision(
            "REPAIR_ACTION_RELATION",
            "ABSTAIN",
            "UNKNOWN appears in at least one paired action",
        )
    return ComparatorDecision(
        "REPAIR_ACTION_RELATION",
        "EQUIVALENT",
        "all public-release actions are equal and concrete",
    )


def confusion_counts(
    canonical: Sequence[str],
    candidate: Sequence[str],
) -> dict[str, int]:
    if len(canonical) != len(candidate):
        raise ValueError("canonical and candidate vectors differ in length")
    counts = {"tp": 0, "tn": 0, "fp": 0, "fn": 0, "abstain": 0}
    for truth, prediction in zip(canonical, candidate, strict=True):
        if prediction == "ABSTAIN":
            counts["abstain"] += 1
        elif truth == "DIVERGENT" and prediction == "DIVERGENT":
            counts["tp"] += 1
        elif truth == "EQUIVALENT" and prediction == "EQUIVALENT":
            counts["tn"] += 1
        elif truth == "EQUIVALENT" and prediction == "DIVERGENT":
            counts["fp"] += 1
        elif truth == "DIVERGENT" and prediction == "EQUIVALENT":
            counts["fn"] += 1
        else:
            counts["abstain"] += 1
    return counts


def version_expression_signature(claim: StructuralClaim) -> bytes:
    """Canonical VERS signature (version-expression relational structure).

    VERS is a project-local baseline name, not an external standard. It compares
    normalized range/explicit-version structure while intentionally excluding repair
    targets, release availability, and source-local identifiers.
    """

    payload = {
        "package_key": claim.package_key,
        "withdrawn": claim.withdrawn,
        "ranges": list(claim.ranges),
        "versions": list(claim.versions),
    }
    return canonical_json_bytes(payload)


def vers_equality(left: StructuralClaim, right: StructuralClaim) -> ComparatorDecision:
    return ComparatorDecision(
        "VERS_EQUALITY",
        "EQUIVALENT"
        if version_expression_signature(left) == version_expression_signature(right)
        else "DIVERGENT",
        "canonical version-expression relational signatures compared",
    )


def universe_affected_equality(
    releases: Sequence[str],
    left: StructuralClaim,
    right: StructuralClaim,
) -> ComparatorDecision:
    from .semantics import affected_status

    left_values: dict[str, bool | None] = {}
    right_values: dict[str, bool | None] = {}
    for release in releases:
        try:
            left_values[release] = affected_status(left, release)
        except (TypeError, ValueError):
            left_values[release] = None
        try:
            right_values[release] = affected_status(right, release)
        except (TypeError, ValueError):
            right_values[release] = None
    decision = affected_set_equality(releases, left_values, right_values)
    return ComparatorDecision(
        "UNIVERS_EQUALITY",
        decision.decision,
        "release-universe execution; " + decision.detail,
    )
