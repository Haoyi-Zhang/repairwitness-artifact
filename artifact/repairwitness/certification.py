"""Cross-paradigm certification for action-separating suites.

The primary optimizer, the LP-dual checker, and the independent oracle intentionally
use different encodings.  A :class:`CertifiedSuiteBundle` binds their evidence to the
same canonical problem digest.  The checker never accepts an objective merely because
it appears in a JSON file: primal feasibility, dual feasibility, integer costs, and
(optional) independent optimization are replayed from the supplied problem.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Literal

from .duality import (
    DualCertificate,
    strongest_dual_certificate,
    verify_dual_certificate,
)
from .oracle import OracleResult, solve_exhaustive_oracle, solve_milp_oracle
from .suite import (
    SuiteCertificate,
    obligation_digest,
    solve_exact,
    verify_certificate,
)

VerificationProfile = Literal["structural", "cross-check", "strict"]


@dataclass(frozen=True)
class OracleAttestation:
    """Serializable output of an independently encoded exact optimizer."""

    problem_sha256: str
    backend: str
    selected_releases: tuple[str, ...]
    optimal_cost: int
    explored_units: int

    @classmethod
    def from_result(cls, problem_sha256: str, result: OracleResult) -> OracleAttestation:
        return cls(
            problem_sha256=problem_sha256,
            backend=result.backend,
            selected_releases=result.selected_releases,
            optimal_cost=result.optimal_cost,
            explored_units=result.explored_subsets,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "problem_sha256": self.problem_sha256,
            "backend": self.backend,
            "selected_releases": list(self.selected_releases),
            "optimal_cost": self.optimal_cost,
            "explored_units": self.explored_units,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> OracleAttestation:
        selected = value.get("selected_releases")
        if not isinstance(selected, list) or not all(isinstance(row, str) for row in selected):
            raise ValueError("oracle selected_releases must be a string array")
        cost = _strict_nonnegative_int(value.get("optimal_cost"), "oracle optimal_cost")
        explored = _strict_nonnegative_int(value.get("explored_units"), "oracle explored_units")
        return cls(
            problem_sha256=_digest(value.get("problem_sha256"), "oracle problem_sha256"),
            backend=_nonempty_string(value.get("backend"), "oracle backend"),
            selected_releases=tuple(selected),
            optimal_cost=cost,
            explored_units=explored,
        )


@dataclass(frozen=True)
class CertifiedSuiteBundle:
    """Digest-bound primal, dual, and independent-oracle evidence."""

    problem_sha256: str
    suite: SuiteCertificate
    dual: DualCertificate
    oracle: OracleAttestation | None
    combined_lower_bound: int
    upper_bound: int
    status: str
    closure_kind: str
    proof_channels: tuple[str, ...]

    @property
    def optimality_gap(self) -> int:
        return self.upper_bound - self.combined_lower_bound

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "problem_sha256": self.problem_sha256,
            "suite": self.suite.to_dict(),
            "dual": self.dual.to_dict(),
            "oracle": None if self.oracle is None else self.oracle.to_dict(),
            "combined_lower_bound": self.combined_lower_bound,
            "upper_bound": self.upper_bound,
            "optimality_gap": self.optimality_gap,
            "status": self.status,
            "closure_kind": self.closure_kind,
            "proof_channels": list(self.proof_channels),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> CertifiedSuiteBundle:
        suite_raw = value.get("suite")
        dual_raw = value.get("dual")
        oracle_raw = value.get("oracle")
        channels_raw = value.get("proof_channels")
        if not isinstance(suite_raw, Mapping):
            raise ValueError("suite must be a JSON object")
        if not isinstance(dual_raw, Mapping):
            raise ValueError("dual must be a JSON object")
        if oracle_raw is not None and not isinstance(oracle_raw, Mapping):
            raise ValueError("oracle must be null or a JSON object")
        if not isinstance(channels_raw, list) or not all(
            isinstance(channel, str) and channel for channel in channels_raw
        ):
            raise ValueError("proof_channels must be a non-empty string array")
        bundle = cls(
            problem_sha256=_digest(value.get("problem_sha256"), "problem_sha256"),
            suite=SuiteCertificate.from_dict(suite_raw),
            dual=DualCertificate.from_dict(dual_raw),
            oracle=(None if oracle_raw is None else OracleAttestation.from_dict(oracle_raw)),
            combined_lower_bound=_strict_nonnegative_int(
                value.get("combined_lower_bound"), "combined_lower_bound"
            ),
            upper_bound=_strict_nonnegative_int(value.get("upper_bound"), "upper_bound"),
            status=_nonempty_string(value.get("status"), "status"),
            closure_kind=_nonempty_string(value.get("closure_kind"), "closure_kind"),
            proof_channels=tuple(channels_raw),
        )
        serialized_gap = value.get("optimality_gap")
        if serialized_gap is not None:
            expected = _strict_nonnegative_int(serialized_gap, "optimality_gap")
            if expected != bundle.optimality_gap:
                raise ValueError("optimality_gap is inconsistent with the bounds")
        return bundle


def _strict_nonnegative_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


def _nonempty_string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _digest(value: object, field: str) -> str:
    text = _nonempty_string(value, field)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return text


def _normalise_maps(
    obligations: Mapping[str, Iterable[str]],
    demands: Mapping[str, int] | None,
    costs: Mapping[str, int] | None,
) -> tuple[dict[str, frozenset[str]], dict[str, int], dict[str, int]]:
    rows = {
        str(edge): frozenset(str(release) for release in witnesses)
        for edge, witnesses in obligations.items()
    }
    releases = sorted({release for witnesses in rows.values() for release in witnesses})
    demand_map = {edge: 1 if demands is None else demands.get(edge, 1) for edge in rows}
    cost_map = {release: 1 if costs is None else costs.get(release, 1) for release in releases}
    return rows, demand_map, cost_map


def _attestation_errors(
    rows: Mapping[str, frozenset[str]],
    demands: Mapping[str, int],
    costs: Mapping[str, int],
    attestation: OracleAttestation,
) -> list[str]:
    errors: list[str] = []
    selected = attestation.selected_releases
    if tuple(sorted(set(selected))) != selected:
        errors.append("oracle selection is not unique and canonically sorted")
    unknown = set(selected) - set(costs)
    if unknown:
        errors.append(f"oracle selection contains unknown releases: {sorted(unknown)}")
    replay_cost = sum(costs.get(release, 0) for release in selected)
    if replay_cost != attestation.optimal_cost:
        errors.append("oracle objective does not equal the selected-release cost")
    selected_set = set(selected)
    for edge, witnesses in rows.items():
        if len(selected_set & witnesses) < demands[edge]:
            errors.append(f"oracle selection does not satisfy obligation {edge}")
    if attestation.backend not in {"EXHAUSTIVE", "SCIPY_HIGHS_MILP"}:
        errors.append(f"unsupported oracle backend: {attestation.backend}")
    return errors


def _run_declared_oracle(
    obligations: Mapping[str, Iterable[str]],
    demands: Mapping[str, int] | None,
    costs: Mapping[str, int] | None,
    attestation: OracleAttestation,
) -> OracleResult:
    if attestation.backend == "EXHAUSTIVE":
        release_count = len({release for values in obligations.values() for release in values})
        return solve_exhaustive_oracle(
            obligations,
            demands=demands,
            costs=costs,
            release_limit=max(26, release_count),
        )
    if attestation.backend == "SCIPY_HIGHS_MILP":
        return solve_milp_oracle(obligations, demands=demands, costs=costs)
    raise ValueError(f"unsupported oracle backend: {attestation.backend}")


def solve_certified(
    obligations: Mapping[str, Iterable[str]],
    *,
    demands: Mapping[str, int] | None = None,
    costs: Mapping[str, int] | None = None,
    max_nodes: int | None = None,
    use_highs_dual: bool = True,
    independent_oracle: bool = True,
    exhaustive_release_limit: int = 22,
) -> CertifiedSuiteBundle:
    """Produce a suite with mutually independent proof channels.

    A bounded primary search may still be closed as exact when an independently checked
    dual reaches the incumbent or the independent oracle proves the same objective.
    """

    digest = obligation_digest(obligations, demands=demands, costs=costs)
    suite = solve_exact(
        obligations,
        demands=demands,
        costs=costs,
        max_nodes=max_nodes,
    )
    dual = strongest_dual_certificate(
        obligations,
        demands=demands,
        costs=costs,
        use_highs=use_highs_dual,
    )
    oracle_attestation: OracleAttestation | None = None
    oracle_bound: int | None = None
    if independent_oracle:
        release_count = len({str(release) for values in obligations.values() for release in values})
        oracle_result = (
            solve_exhaustive_oracle(
                obligations,
                demands=demands,
                costs=costs,
                release_limit=max(exhaustive_release_limit, release_count),
            )
            if release_count <= exhaustive_release_limit
            else solve_milp_oracle(obligations, demands=demands, costs=costs)
        )
        oracle_attestation = OracleAttestation.from_result(digest, oracle_result)
        oracle_bound = oracle_result.optimal_cost

    lower_candidates = [suite.lower_bound, dual.integer_lower_bound]
    if oracle_bound is not None:
        lower_candidates.append(oracle_bound)
    combined_lower = max(lower_candidates)
    if combined_lower > suite.upper_bound:
        raise RuntimeError(
            "independent proof channel produced a lower bound above the primal incumbent"
        )
    channels = ["PRIMARY_SEARCH_REPLAY", "EXACT_RATIONAL_LP_DUAL"]
    if oracle_attestation is not None:
        channels.append(f"INDEPENDENT_{oracle_attestation.backend}")
    if combined_lower == suite.upper_bound:
        status = "EXACT_CROSS_CHECKED"
        if dual.integer_lower_bound == suite.upper_bound:
            closure = "PRIMAL_DUAL_EQUALITY"
        elif oracle_bound == suite.upper_bound:
            closure = "INDEPENDENT_ORACLE_EQUALITY"
        else:
            closure = "PRIMARY_SEARCH_EQUALITY"
    else:
        status = "BOUNDED_CROSS_CHECKED"
        closure = "OPEN_OPTIMALITY_INTERVAL"
    return CertifiedSuiteBundle(
        problem_sha256=digest,
        suite=suite,
        dual=dual,
        oracle=oracle_attestation,
        combined_lower_bound=combined_lower,
        upper_bound=suite.upper_bound,
        status=status,
        closure_kind=closure,
        proof_channels=tuple(channels),
    )


def _digest_binding_errors(bundle: CertifiedSuiteBundle, digest: str) -> list[str]:
    bindings = (
        (bundle.problem_sha256, "bundle problem digest mismatch"),
        (bundle.suite.obligation_sha256, "suite problem digest mismatch"),
        (bundle.dual.problem_sha256, "dual problem digest mismatch"),
    )
    return [message for actual, message in bindings if actual != digest]


def _proof_errors(
    obligations: Mapping[str, Iterable[str]],
    bundle: CertifiedSuiteBundle,
    demands: Mapping[str, int] | None,
    costs: Mapping[str, int] | None,
    *,
    replay_primary: bool,
) -> list[str]:
    suite_ok, suite_errors = verify_certificate(
        obligations,
        bundle.suite,
        demands=demands,
        costs=costs,
        verify_optimality=replay_primary,
    )
    dual_ok, dual_errors = verify_dual_certificate(
        obligations,
        bundle.dual,
        demands=demands,
        costs=costs,
    )
    errors: list[str] = []
    if not suite_ok:
        errors.extend(f"suite: {error}" for error in suite_errors)
    if not dual_ok:
        errors.extend(f"dual: {error}" for error in dual_errors)
    return errors


def _verify_oracle_attestation(
    obligations: Mapping[str, Iterable[str]],
    bundle: CertifiedSuiteBundle,
    demands: Mapping[str, int] | None,
    costs: Mapping[str, int] | None,
    rows: Mapping[str, frozenset[str]],
    demand_map: Mapping[str, int],
    cost_map: Mapping[str, int],
    digest: str,
    *,
    replay: bool,
) -> tuple[list[str], int | None]:
    attestation = bundle.oracle
    if attestation is None:
        return [], None
    errors: list[str] = []
    if attestation.problem_sha256 != digest:
        errors.append("oracle problem digest mismatch")
    errors.extend(
        f"oracle: {error}" for error in _attestation_errors(rows, demand_map, cost_map, attestation)
    )
    if not replay or errors:
        return errors, None
    try:
        result = _run_declared_oracle(obligations, demands, costs, attestation)
    except Exception as exc:
        errors.append(f"independent oracle replay failed: {type(exc).__name__}: {exc}")
        return errors, None
    if result.optimal_cost != attestation.optimal_cost:
        errors.append("independent oracle objective does not replay")
    if result.selected_releases != attestation.selected_releases:
        errors.append("independent oracle canonical optimum does not replay")
    return errors, result.optimal_cost


def _verified_lower_bound(
    bundle: CertifiedSuiteBundle,
    profile: VerificationProfile,
    oracle_replay_cost: int | None,
) -> int:
    verified = [bundle.dual.integer_lower_bound]
    if profile in {"cross-check", "strict"}:
        verified.append(bundle.suite.lower_bound)
    if profile == "strict" and oracle_replay_cost is not None:
        verified.append(oracle_replay_cost)
    return max(verified, default=0)


def _bundle_interval_errors(
    bundle: CertifiedSuiteBundle,
    verified_lower: int,
) -> list[str]:
    errors: list[str] = []
    if bundle.combined_lower_bound != verified_lower:
        errors.append("combined lower bound does not equal the strongest verified proof channel")
    if bundle.upper_bound != bundle.suite.upper_bound:
        errors.append("bundle upper bound does not match the primal certificate")
    if bundle.combined_lower_bound > bundle.upper_bound:
        errors.append("bundle has a negative optimality interval")
    return errors


def _bundle_metadata_errors(bundle: CertifiedSuiteBundle) -> list[str]:
    errors: list[str] = []
    expected_channels = ["PRIMARY_SEARCH_REPLAY", "EXACT_RATIONAL_LP_DUAL"]
    if bundle.oracle is not None:
        expected_channels.append(f"INDEPENDENT_{bundle.oracle.backend}")
    if bundle.proof_channels != tuple(expected_channels):
        errors.append("proof channel list is incomplete or non-canonical")

    exact = bundle.combined_lower_bound == bundle.upper_bound
    expected_status = "EXACT_CROSS_CHECKED" if exact else "BOUNDED_CROSS_CHECKED"
    if bundle.status != expected_status:
        errors.append("bundle status is inconsistent with its verified interval")
    allowed_closures = (
        {"PRIMAL_DUAL_EQUALITY", "INDEPENDENT_ORACLE_EQUALITY", "PRIMARY_SEARCH_EQUALITY"}
        if exact
        else {"OPEN_OPTIMALITY_INTERVAL"}
    )
    if bundle.closure_kind not in allowed_closures:
        errors.append("closure kind is inconsistent with the verified interval")
    return errors


def verify_certified_bundle(
    obligations: Mapping[str, Iterable[str]],
    bundle: CertifiedSuiteBundle,
    *,
    demands: Mapping[str, int] | None = None,
    costs: Mapping[str, int] | None = None,
    profile: VerificationProfile = "strict",
) -> tuple[bool, tuple[str, ...]]:
    """Verify a bundle without trusting its producer.

    ``structural`` validates primal feasibility and exact-rational dual evidence.
    ``cross-check`` additionally replays the primary optimality proof. ``strict`` also
    reruns the declared independent optimizer. A lower bound is accepted only from a
    proof channel executed by the selected profile.
    """

    if profile not in {"structural", "cross-check", "strict"}:
        raise ValueError(f"unknown verification profile: {profile}")
    try:
        digest = obligation_digest(obligations, demands=demands, costs=costs)
        rows, demand_map, cost_map = _normalise_maps(obligations, demands, costs)
    except Exception as exc:
        return False, (f"problem normalization failed: {type(exc).__name__}: {exc}",)

    errors = _digest_binding_errors(bundle, digest)
    errors.extend(
        _proof_errors(
            obligations,
            bundle,
            demands,
            costs,
            replay_primary=profile in {"cross-check", "strict"},
        )
    )
    oracle_errors, oracle_replay_cost = _verify_oracle_attestation(
        obligations,
        bundle,
        demands,
        costs,
        rows,
        demand_map,
        cost_map,
        digest,
        replay=profile == "strict",
    )
    errors.extend(oracle_errors)
    verified_lower = _verified_lower_bound(bundle, profile, oracle_replay_cost)
    errors.extend(_bundle_interval_errors(bundle, verified_lower))
    errors.extend(_bundle_metadata_errors(bundle))
    return not errors, tuple(errors)
