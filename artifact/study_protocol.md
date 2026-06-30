# RepairWitness Frozen Study Protocol

## Research object

A security-advisory claim is interpreted as a partial function from a digest-bound package release universe to a developer-facing repair action. Two claims are equivalent only when every jointly concrete release produces the same action. `UNKNOWN` is an abstention and cannot witness divergence.

## Primary questions

1. **Action disagreement:** How often do repeated advisory claims induce different concrete actions, and which syntactic comparators misclassify the action relation?
2. **Witness compression:** How small can a real-release suite be while witnessing every concrete claim-pair divergence in a group?
3. **Certification:** Do exact, bounded, interval, exhaustive, and independent MILP paths agree on the optimization problem induced by the canonical action relation, and can every certificate be replayed by a simpler checker?
4. **Structure and evolution:** When do ordered release histories admit interval algorithms, and what overhead is required for resilience or stable incremental maintenance?

## Semantics

The five outcomes are `NO_ACTION`, `UPGRADE_TO_ADVISORY_TARGET`, `ALTERNATIVE_ACTION`, `REPAIR_WITHOUT_PUBLIC_TARGET`, and typed `UNKNOWN`. Fixed or patched versions are source-supported anchors only. Unsupported syntax, invalid ordering, withdrawal ambiguity, empty or failed universes, and unrealizable anchors abstain.

## Optimization

The primary advisory estimand uses unit cost and unit demand. The generalized registered problem allows positive integer costs and demands. Exact results require an accepted independent certificate with matching lower and upper bounds. Bounded results report both bounds. Greedy is always labeled heuristic even when it matches the exact objective.

## Frozen evidence layers

### Reviewer-facing scope gates

The SafetyDB case study is locked to the historical SafetyDB 2021.7.17 snapshot and is used without claiming current ecosystem prevalence. `scripts/verify_safetydb_historical_scope.py` checks that the README, protocol, and frozen summaries preserve that boundary, including the digest-bound input summaries and the fail-closed authorized observational rerun path. The default reproduction is not a live network fetch.

Optimization impact is checked separately from prevalence. `scripts/verify_optimization_impact.py` requires historical SafetyDB witness compression, public-overlap construct replay, independent HiGHS agreement, controlled certificate replay, OR-Library quality, mutation rejection, redistributable synthetic controls, ordered 100,000-release scalability evidence, and dense-overlap scalability evidence. `scripts/verify_baseline_fairness.py` checks that comparators are locked before outcomes, preserve abstentions, disclose release-universe and repair-target access, report synthetic comparator decision/abstention rates, replay the public-overlap affected-set-equal/action-divergent witness, and avoid post-hoc effect thresholds. `scripts/verify_temporal_scope.py` checks that the 2026-06-22 public advisory-source commits in `source_manifest.csv` and `config/resource_lock.json` are provenance boundaries rather than current-prevalence evidence. `scripts/verify_coverage_contract.py` turns branch-aware coverage into a release gate rather than a static appendix number.

### Historical advisory benchmark

SafetyDB 2021.7.17 is the real-claim benchmark. Package/CVE grouping, release-universe acquisition, semantic evaluation, and suite synthesis are deterministic and digest-bound. Terminal empty and failed universe rows remain in inventory accounting. The benchmark is interpreted as historical PyPI evidence, not a universal prevalence sample.

The default artifact does not redistribute mutable registry response bytes or source-level recovery rows. It validates frozen summaries and certificate witnesses offline. A separate source-level rerun is available through `scripts/run_observational_actions.py` for evaluators who supply the non-redistributed claim, edge, and release-universe JSONL inputs together with an analysis gate bound to their digests; the evaluator exits before loading inputs if that predicate fails. Consequently, SafetyDB is reported as a digest-bound historical case study, not as a fully source-reproducible benchmark.

### Redistributable synthetic advisory benchmark

`benchmarks/synthetic_advisory/` contains source-level JSONL fixtures that can be redistributed and independently replayed by default. They include known-equivalent negative controls, divergent target-shift controls, alternative-action controls, and typed-abstention controls. `scripts/verify_synthetic_advisory_benchmark.py` recomputes action traces, comparator decisions, false-divergence counts, and suite certificates from these inputs. These controls validate the formal semantics and implementation behavior; they are not mixed into the SafetyDB prevalence denominator.

### Controlled validation

Seeded generators cover general weighted multicover, interval multicover, weighted interval primal-dual certificates, cross-certification, cost robustness, failure resilience, and minimum augmentation. Generation rules are fixed before outcome comparison. Exhaustive and MILP oracles are independently encoded.

### External optimization benchmark

The 50 OR-Library SCP instances in sets 4-6 and A-E test generic optimization on established, non-author-designed structures with known optima. They do not measure advisory semantics.

## Baselines

- Raw serialized equality.
- Normalized structural equality.
- Affected-set equality.
- All witnesses.
- Per-edge-first witness selection.
- Deterministic greedy multicover.
- SetCoverPy greedy and Lagrangian methods on SafetyDB groups.
- Independent SciPy/HiGHS MILP.
- LP-guided rounding and bounded HiGHS on OR-Library.

The baseline fairness gate treats `ACTION` as the canonical action relation under the project semantics, not as an imported vulnerability-truth label. Comparator baselines report `EQUIVALENT`, `DIVERGENT`, or `ABSTAIN`; abstentions and non-executable units stay in the denominator. Synthetic controls report per-comparator decided and abstained counts. Optimization baselines use the same OR-Library instances and known optima, and their ratios are replayed from row-level costs.

## Canonical relation and comparator provenance

The decision relations in `config/baseline_lock.json` are study definitions, not imported ground-truth labels. `RAW`, `STRUCTURAL`, `AFFECTED_SET`, `VERS`, and `UNIVERS` are comparator baselines that expose what changes when records, normalized fields, version expressions, or digest-bound release universes are compared. `ACTION` is the canonical action relation: two claims diverge only when the project-defined partial repair-action semantics produce different concrete non-`UNKNOWN` actions for at least one jointly evaluated release. Method independence is established through separate implementation paths and checks: source-specific adapters construct claims, ecosystem semantics evaluate actions, baseline comparators are implemented separately, suite certificates replay obligations, redistributable synthetic controls exercise known outcomes, and SciPy/HiGHS plus exhaustive generators check the optimization layer. Semantic validity relies on the documented action model and version-ordering semantics; no external repair-action ground-truth label set is claimed.

## Metrics

Edge dispositions, decided coverage, false equivalence/divergence, suite cost, union-of-witnesses cost, compression, witness reuse, exact/heuristic objective ratio, lower/upper gap, certificate replay, runtime, explored nodes or states, resilience feasibility/overhead, augmentation churn, input/report digests, and terminal failure counts.

## Integrity controls

- Canonical JSON and SHA-256 bind every problem and certificate.
- Replay checks original obligations rather than trusting reductions.
- Proof kind selects a distinct verification predicate.
- Mutation controls alter identity, selections, assignments, costs, demands, bounds, kernels, components, interval steps, dual variables, and base-suite bindings.
- Result summaries are independently regenerated from row-level files when bundled.
- Packaging is deterministic and safe extraction is verified in a clean directory.

## Stopping and reporting rules

No minimum divergence, compression, effect, or significance threshold is used. Failed acquisitions and abstentions are retained. Negative or equivalent results are reported under the same metrics. No method is tuned using OR-Library known optima or the SafetyDB test outcomes; algorithm choices are fixed by problem structure and certificate requirements.

## Scope

RepairWitness compares source-relative advisory actions. It does not establish exploitability, compatibility, maintainer support, or that a target removes every vulnerability. Shared curation lineage is not interpreted as independent consensus.
