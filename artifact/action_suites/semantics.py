from __future__ import annotations

import re
from dataclasses import dataclass
from functools import cmp_to_key
from typing import Any, Iterable, Mapping, Sequence

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from .adapters import StructuralClaim
from .model import Action, ActionKind, BlockerCode, ReleaseUniverse


class UnsupportedEcosystem(ValueError):
    pass


class UnsupportedVersion(ValueError):
    pass


_SEMVER_ECOSYSTEMS = {
    "npm",
    "crates.io",
    "go",
    "nuget",
    "hex",
    "packagist",
}
_NUMERIC_SUBSET_ECOSYSTEMS = {"rubygems", "maven"}
_SUPPORTED_ECOSYSTEMS = {"pypi", *_SEMVER_ECOSYSTEMS, *_NUMERIC_SUBSET_ECOSYSTEMS}

_SEMVER_RE = re.compile(
    r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_NUMERIC_RE = re.compile(r"^v?(\d+(?:\.\d+)*)$")


def _ecosystem(value: str) -> str:
    return value.strip().lower()


def _semver_parts(raw: str) -> tuple[tuple[int, int, int], tuple[str, ...] | None]:
    match = _SEMVER_RE.fullmatch(raw.strip())
    if not match:
        raise UnsupportedVersion(raw)
    core = (int(match.group(1)), int(match.group(2)), int(match.group(3)))
    prerelease = tuple(match.group(4).split(".")) if match.group(4) else None
    return core, prerelease


def _compare_prerelease(
    left: tuple[str, ...] | None,
    right: tuple[str, ...] | None,
) -> int:
    if left is None and right is None:
        return 0
    if left is None:
        return 1
    if right is None:
        return -1
    for left_id, right_id in zip(left, right):
        if left_id == right_id:
            continue
        left_numeric = left_id.isdigit()
        right_numeric = right_id.isdigit()
        if left_numeric and right_numeric:
            left_number, right_number = int(left_id), int(right_id)
            return -1 if left_number < right_number else 1
        if left_numeric != right_numeric:
            return -1 if left_numeric else 1
        return -1 if left_id < right_id else 1
    return -1 if len(left) < len(right) else 1 if len(left) > len(right) else 0


def _compare_semver(left: str, right: str) -> int:
    left_core, left_pre = _semver_parts(left)
    right_core, right_pre = _semver_parts(right)
    if left_core != right_core:
        return -1 if left_core < right_core else 1
    return _compare_prerelease(left_pre, right_pre)


def _numeric_parts(raw: str) -> tuple[int, ...]:
    match = _NUMERIC_RE.fullmatch(raw.strip())
    if not match:
        raise UnsupportedVersion(raw)
    parts = tuple(int(part) for part in match.group(1).split("."))
    while len(parts) > 1 and parts[-1] == 0:
        parts = parts[:-1]
    return parts


def _compare_numeric(left: str, right: str) -> int:
    left_parts, right_parts = _numeric_parts(left), _numeric_parts(right)
    width = max(len(left_parts), len(right_parts))
    left_padded = left_parts + (0,) * (width - len(left_parts))
    right_padded = right_parts + (0,) * (width - len(right_parts))
    return -1 if left_padded < right_padded else 1 if left_padded > right_padded else 0


def compare_versions(ecosystem: str, left: str, right: str) -> int:
    """Compare two releases under a frozen, ecosystem-specific supported subset.

    Unsupported ecosystems or version forms raise rather than falling back to a
    cross-ecosystem ordering. Callers translate that failure to typed uncertainty.
    """

    eco = _ecosystem(ecosystem)
    if eco == "pypi":
        try:
            left_value, right_value = Version(left), Version(right)
        except InvalidVersion as error:
            raise UnsupportedVersion(str(error)) from error
        return -1 if left_value < right_value else 1 if left_value > right_value else 0
    if eco in _SEMVER_ECOSYSTEMS:
        return _compare_semver(left, right)
    if eco in _NUMERIC_SUBSET_ECOSYSTEMS:
        return _compare_numeric(left, right)
    raise UnsupportedEcosystem(ecosystem)


def _event_interval_affected(
    ecosystem: str,
    release: str,
    events: Sequence[Mapping[str, Any]],
) -> bool:
    affected = False
    seen_boundary = False
    for event in events:
        if "introduced" in event:
            introduced = str(event["introduced"])
            seen_boundary = True
            if introduced == "0" or compare_versions(ecosystem, release, introduced) >= 0:
                affected = True
            else:
                break
        elif "fixed" in event:
            fixed = str(event["fixed"])
            seen_boundary = True
            if compare_versions(ecosystem, release, fixed) >= 0:
                affected = False
            else:
                break
        elif "last_affected" in event:
            last = str(event["last_affected"])
            seen_boundary = True
            if compare_versions(ecosystem, release, last) > 0:
                affected = False
            else:
                break
        elif "limit" in event:
            limit = str(event["limit"])
            seen_boundary = True
            if compare_versions(ecosystem, release, limit) >= 0:
                affected = False
            else:
                break
        else:
            raise UnsupportedVersion(f"unsupported OSV event: {sorted(event)}")
    if not seen_boundary:
        raise UnsupportedVersion("range contains no supported boundary events")
    return affected


def _bump_pessimistic_upper(raw: str) -> str:
    prefix = "v" if raw.startswith("v") else ""
    value = raw[1:] if prefix else raw
    if not re.fullmatch(r"\d+(?:\.\d+)*", value):
        raise UnsupportedVersion(raw)
    parts = [int(part) for part in value.split(".")]
    if len(parts) == 1:
        return prefix + str(parts[0] + 1)
    upper = parts[:-1]
    upper[-1] += 1
    # SemVer ecosystems require three components for the frozen comparator.
    if len(upper) < 3:
        upper.extend([0] * (3 - len(upper)))
    return prefix + ".".join(str(part) for part in upper)


def _bump_caret_upper(raw: str) -> str:
    match = _SEMVER_RE.fullmatch(raw.strip())
    if not match:
        raise UnsupportedVersion(raw)
    major, minor, patch = (int(match.group(index)) for index in range(1, 4))
    if major > 0:
        return f"{major + 1}.0.0"
    if minor > 0:
        return f"0.{minor + 1}.0"
    return f"0.0.{patch + 1}"


def _comparison_term_matches(ecosystem: str, release: str, term: str) -> bool:
    term = term.strip()
    pessimistic = re.fullmatch(r"~>\s*(\S+)", term)
    if pessimistic:
        lower = pessimistic.group(1)
        upper = _bump_pessimistic_upper(lower)
        return (
            compare_versions(ecosystem, release, lower) >= 0
            and compare_versions(ecosystem, release, upper) < 0
        )
    caret = re.fullmatch(r"\^\s*(\S+)", term)
    if caret:
        lower = caret.group(1)
        upper = _bump_caret_upper(lower)
        return (
            compare_versions(ecosystem, release, lower) >= 0
            and compare_versions(ecosystem, release, upper) < 0
        )
    match = re.fullmatch(r"(<=|>=|<|>|==|=|!=)\s*(\S+)", term)
    if not match:
        raise UnsupportedVersion(f"unsupported requirement term: {term}")
    operator, boundary = match.groups()
    comparison = compare_versions(ecosystem, release, boundary)
    return {
        "<": comparison < 0,
        "<=": comparison <= 0,
        ">": comparison > 0,
        ">=": comparison >= 0,
        "=": comparison == 0,
        "==": comparison == 0,
        "!=": comparison != 0,
    }[operator]


def requirement_matches(ecosystem: str, release: str, expression: str) -> bool:
    eco = _ecosystem(ecosystem)
    expression = expression.strip()
    if eco == "pypi":
        try:
            return Version(release) in SpecifierSet(expression.replace(" ", ""))
        except (InvalidSpecifier, InvalidVersion) as error:
            raise UnsupportedVersion(str(error)) from error
    if eco not in _SUPPORTED_ECOSYSTEMS:
        raise UnsupportedEcosystem(ecosystem)
    terms = [term.strip() for term in expression.split(",") if term.strip()]
    if not terms:
        raise UnsupportedVersion("empty requirement")
    return all(_comparison_term_matches(ecosystem, release, term) for term in terms)


def _requirement_union_matches(
    ecosystem: str,
    release: str,
    expressions: Iterable[str],
) -> bool:
    return any(requirement_matches(ecosystem, release, expression) for expression in expressions)


def affected_status(claim: StructuralClaim, release: str) -> bool:
    """Return the claim's affectedness judgment or raise on unsupported semantics."""

    ecosystem = claim.package_ecosystem
    if _ecosystem(ecosystem) not in _SUPPORTED_ECOSYSTEMS:
        raise UnsupportedEcosystem(ecosystem)
    if release in claim.versions:
        return True
    if not claim.ranges:
        if claim.versions:
            return False
        raise UnsupportedVersion("claim has neither executable ranges nor explicit versions")

    decisions: list[bool] = []
    for row in claim.ranges:
        range_type = str(row.get("type", "")).upper()
        if range_type in {"SEMVER", "ECOSYSTEM"}:
            events = row.get("events") or []
            if not isinstance(events, Sequence):
                raise UnsupportedVersion("range events are not a sequence")
            decisions.append(
                _event_interval_affected(
                    ecosystem,
                    release,
                    tuple(event for event in events if isinstance(event, Mapping)),
                )
            )
        elif range_type == "RUSTSEC_REQUIREMENT_SETS":
            patched = tuple(str(value) for value in row.get("patched") or [])
            unaffected = tuple(str(value) for value in row.get("unaffected") or [])
            if _requirement_union_matches(ecosystem, release, unaffected):
                decisions.append(False)
            elif _requirement_union_matches(ecosystem, release, patched):
                decisions.append(False)
            else:
                decisions.append(True)
        elif range_type == "RUBYGEMS_REQUIREMENT_SETS":
            patched = tuple(str(value) for value in row.get("patched") or [])
            unaffected = tuple(str(value) for value in row.get("unaffected") or [])
            vulnerable = tuple(str(value) for value in row.get("vulnerable") or [])
            if unaffected and _requirement_union_matches(ecosystem, release, unaffected):
                decisions.append(False)
            elif patched and _requirement_union_matches(ecosystem, release, patched):
                decisions.append(False)
            elif vulnerable:
                decisions.append(_requirement_union_matches(ecosystem, release, vulnerable))
            else:
                decisions.append(True)
        elif range_type == "GIT":
            raise UnsupportedVersion("GIT ranges require commit reachability")
        else:
            raise UnsupportedVersion(f"unsupported range type: {range_type or '<missing>'}")
    return any(decisions)


def _eligible_targets(
    claim: StructuralClaim,
    release: str,
    universe: ReleaseUniverse,
) -> tuple[str, ...]:
    public = set(universe.releases)
    eligible: list[str] = []
    for target in claim.advisory_targets:
        candidates: list[str]
        if target in public:
            candidates = [target]
        else:
            candidates = [
                candidate
                for candidate in universe.releases
                if requirement_matches(claim.package_ecosystem, candidate, target)
            ]
        candidates = [
            candidate
            for candidate in candidates
            if compare_versions(claim.package_ecosystem, candidate, release) > 0
        ]
        candidates.sort(
            key=cmp_to_key(
                lambda left, right: compare_versions(
                    claim.package_ecosystem, left, right
                )
            )
        )
        if candidates:
            eligible.append(candidates[0])
    return tuple(
        sorted(
            set(eligible),
            key=cmp_to_key(
                lambda left, right: compare_versions(
                    claim.package_ecosystem, left, right
                )
            ),
        )
    )


def evaluate_claim(
    claim: StructuralClaim,
    release: str,
    universe: ReleaseUniverse,
) -> Action:
    if claim.package_key != universe.package_key:
        return Action(ActionKind.UNKNOWN, blocker=BlockerCode.MISSING_PACKAGE)
    if release not in universe.releases:
        return Action(ActionKind.UNKNOWN, blocker=BlockerCode.MISSING_PACKAGE)
    if claim.withdrawn:
        return Action(ActionKind.UNKNOWN, blocker=BlockerCode.WITHDRAWN_RECORD)
    try:
        affected = affected_status(claim, release)
    except UnsupportedEcosystem:
        return Action(ActionKind.UNKNOWN, blocker=BlockerCode.UNSUPPORTED_ECOSYSTEM)
    except (InvalidVersion, UnsupportedVersion, ValueError, TypeError):
        return Action(ActionKind.UNKNOWN, blocker=BlockerCode.UNSUPPORTED_RANGE)
    if not affected:
        return Action(ActionKind.NO_ACTION)
    try:
        targets = _eligible_targets(claim, release, universe)
    except UnsupportedEcosystem:
        return Action(ActionKind.UNKNOWN, blocker=BlockerCode.UNSUPPORTED_ECOSYSTEM)
    except (InvalidVersion, UnsupportedVersion, ValueError, TypeError):
        return Action(ActionKind.UNKNOWN, blocker=BlockerCode.AMBIGUOUS_TARGET)
    if targets:
        return Action(ActionKind.UPGRADE_TO_ADVISORY_TARGET, targets=targets)
    if claim.alternative_actions:
        return Action(
            ActionKind.ALTERNATIVE_ACTION,
            mechanism=" | ".join(sorted(set(claim.alternative_actions))),
        )
    return Action(ActionKind.REPAIR_WITHOUT_PUBLIC_TARGET)


def action_trace(claim: StructuralClaim, universe: ReleaseUniverse) -> dict[str, Action]:
    return {
        release: evaluate_claim(claim, release, universe)
        for release in universe.releases
    }


@dataclass(frozen=True)
class EvaluationGuard:
    project_root: str

    def evaluate(
        self,
        claim: StructuralClaim,
        release: str,
        universe: ReleaseUniverse,
    ) -> Action:
        # Imported lazily so semantics can be unit-tested without a project tree.
        from pathlib import Path

        from .runtime_guard import require_authorized

        require_authorized(Path(self.project_root))
        return evaluate_claim(claim, release, universe)
