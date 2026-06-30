from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Mapping, Sequence

from .canonical import canonical_json_bytes, sha256_bytes


class ActionKind(str, Enum):
    NO_ACTION = "NO_ACTION"
    UPGRADE_TO_ADVISORY_TARGET = "UPGRADE_TO_ADVISORY_TARGET"
    ALTERNATIVE_ACTION = "ALTERNATIVE_ACTION"
    REPAIR_WITHOUT_PUBLIC_TARGET = "REPAIR_WITHOUT_PUBLIC_TARGET"
    UNKNOWN = "UNKNOWN"


class BlockerCode(str, Enum):
    EMPTY_RELEASE_UNIVERSE = "EMPTY_RELEASE_UNIVERSE"
    FAILED_RELEASE_UNIVERSE = "FAILED_RELEASE_UNIVERSE"
    UNSUPPORTED_RANGE = "UNSUPPORTED_RANGE"
    UNSUPPORTED_ECOSYSTEM = "UNSUPPORTED_ECOSYSTEM"
    WITHDRAWN_RECORD = "WITHDRAWN_RECORD"
    MISSING_PACKAGE = "MISSING_PACKAGE"
    AMBIGUOUS_TARGET = "AMBIGUOUS_TARGET"
    MALFORMED_RECORD = "MALFORMED_RECORD"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True)
class Action:
    kind: ActionKind
    targets: tuple[str, ...] = ()
    mechanism: str | None = None
    blocker: BlockerCode | None = None

    def __post_init__(self) -> None:
        normalized_targets = tuple(sorted(set(self.targets)))
        object.__setattr__(self, "targets", normalized_targets)

        if self.kind is ActionKind.UPGRADE_TO_ADVISORY_TARGET:
            if not normalized_targets:
                raise ValueError("upgrade action requires at least one advisory target")
        elif normalized_targets:
            raise ValueError(f"{self.kind.value} cannot carry upgrade targets")

        if self.kind is ActionKind.ALTERNATIVE_ACTION:
            if not self.mechanism or not self.mechanism.strip():
                raise ValueError("alternative action requires a mechanism")
        elif self.mechanism is not None:
            raise ValueError(f"{self.kind.value} cannot carry an alternative mechanism")

        if self.kind is ActionKind.UNKNOWN:
            if self.blocker is None:
                raise ValueError("UNKNOWN requires a blocker code")
        elif self.blocker is not None:
            raise ValueError("a concrete action cannot carry an uncertainty blocker")

    @property
    def concrete(self) -> bool:
        return self.kind is not ActionKind.UNKNOWN

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind.value,
            "targets": list(self.targets),
            "mechanism": self.mechanism,
            "blocker": self.blocker.value if self.blocker else None,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "Action":
        blocker_raw = value.get("blocker")
        return cls(
            kind=ActionKind(str(value["kind"])),
            targets=tuple(str(item) for item in value.get("targets", [])),
            mechanism=(
                str(value["mechanism"])
                if value.get("mechanism") is not None
                else None
            ),
            blocker=BlockerCode(str(blocker_raw)) if blocker_raw is not None else None,
        )


@dataclass(frozen=True)
class ReleaseUniverse:
    package_key: str
    releases: tuple[str, ...]
    source_digest: str

    def __post_init__(self) -> None:
        if len(set(self.releases)) != len(self.releases):
            raise ValueError("release universe contains duplicate release identifiers")
        if not self.package_key:
            raise ValueError("release universe requires a package key")
        if len(self.source_digest) != 64:
            raise ValueError("release universe source digest must be SHA-256")

    @property
    def digest(self) -> str:
        return sha256_bytes(
            canonical_json_bytes(
                {
                    "package_key": self.package_key,
                    "releases": list(self.releases),
                    "source_digest": self.source_digest,
                }
            )
        )


@dataclass(frozen=True)
class Edge:
    edge_id: str
    left_claim_id: str
    right_claim_id: str

    def __post_init__(self) -> None:
        if not self.edge_id or not self.left_claim_id or not self.right_claim_id:
            raise ValueError("edge identifiers must be non-empty")
        if self.left_claim_id == self.right_claim_id:
            raise ValueError("an edge must connect distinct claims")


def actions_separate(left: Action, right: Action) -> bool:
    """Return whether two claims prescribe unequal concrete actions.

    UNKNOWN is an abstention and cannot be promoted into an action or a witness.
    """

    return left.concrete and right.concrete and left != right


def witness_releases(
    releases: Sequence[str],
    left_actions: Mapping[str, Action],
    right_actions: Mapping[str, Action],
) -> frozenset[str]:
    missing_left = set(releases) - set(left_actions)
    missing_right = set(releases) - set(right_actions)
    if missing_left or missing_right:
        raise ValueError(
            "action traces must be total over the supplied universe; "
            f"missing_left={sorted(missing_left)}, missing_right={sorted(missing_right)}"
        )
    return frozenset(
        release
        for release in releases
        if actions_separate(left_actions[release], right_actions[release])
    )


def action_trace_digest(trace: Mapping[str, Action]) -> str:
    payload = {
        release: trace[release].to_dict()
        for release in sorted(trace)
    }
    return sha256_bytes(canonical_json_bytes(payload))


def classify_edge(
    releases: Iterable[str],
    left_actions: Mapping[str, Action],
    right_actions: Mapping[str, Action],
) -> str:
    releases_tuple = tuple(releases)
    if witness_releases(releases_tuple, left_actions, right_actions):
        return "RESOLVED_DIVERGENT"
    concrete_pairs = [
        (left_actions[release], right_actions[release])
        for release in releases_tuple
        if left_actions[release].concrete and right_actions[release].concrete
    ]
    if not concrete_pairs:
        return "INDETERMINATE"
    if all(left == right for left, right in concrete_pairs):
        unknown_present = any(
            not left_actions[release].concrete or not right_actions[release].concrete
            for release in releases_tuple
        )
        return "INDETERMINATE" if unknown_present else "RESOLVED_EQUIVALENT"
    return "NON_EXECUTABLE"
