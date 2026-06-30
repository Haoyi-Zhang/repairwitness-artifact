# RepairWitness: Anonymous Reproduction Artifact

RepairWitness identifies when security-advisory claims prescribe different developer actions for concrete published releases, then synthesizes a minimum-cost or certified-bounded set of releases that witnesses every source-level repair-action divergence.

This directory is the code-only repository payload. The release tree keeps `paper/` and `artifact/` as the only top-level directories.

Scope boundary: the SafetyDB layer is a digest-bound historical PyPI case study from the 2021.7.17 snapshot. Its source-level inputs are not redistributed, so SafetyDB evidence supports the frozen case-study and optimization replay rather than a full source-level reproduction or current-prevalence claim. Fully redistributed source-level semantic controls live in `benchmarks/synthetic_advisory/`. A small `benchmarks/public_advisory_overlap/` fixture contains selected public GHAD/PyPA records that witness the construct on real curated advisories without estimating prevalence. The optional observational rerun is fail-closed for evaluators who separately possess inputs matching the published digests.

## What is included

- Partial repair-action semantics with `NO_ACTION`, source-supported `UPGRADE`, `ALTERNATIVE`, `REPAIR_NO_TARGET`, and typed `UNKNOWN`; unknown outcomes never witness divergence.
- Source-specific advisory adapters, nine ecosystem version/requirement semantics, registry response receipts, and terminal success/empty/failure accounting.
- Weighted redundant action-separating multicover with signature quotienting, forced propagation, demand-aware domination, component decomposition, demand-state DP, deterministic best-first branch-and-bound, and harmonic greedy construction.
- Polynomial unit-cost interval synthesis using a Fenwick tree and predecessor disjoint-set, plus weighted interval primal-dual certificates based on consecutive-ones structure.
- Failure-resilient suites and digest-bound minimum-augmentation certificates for evolving advisories and release histories.
- Independent exhaustive and HiGHS MILP oracles, certificate mutation controls, deterministic packaging, safe extraction, and anonymity auditing.
- Historical SafetyDB case study frozen at the 2021.7.17 snapshot: 1,246 CVE-tagged claims and 570 divergent edges used to demonstrate the optimization method on real advisory divergence without claiming current ecosystem prevalence.
- Redistributable synthetic advisory benchmark with source-level JSONL claims, edges, release universes, 56 known-equivalent negative controls, divergent controls, and comparator abstention rates. The synthetic benchmark validates action-semantics implementation behavior on 12 packages; it is not a sample of real-world advisory diversity and does not support prevalence claims.
- Redistributable public advisory overlap fixture with six upstream GHAD/PyPA records, three paired edges, and two frozen PyPI release universes. Each edge has equal affected-release sets but different repair actions, so it checks the specific construct that affected-set equality cannot express.
- 50 complete OR-Library set-cover instances and results, controlled differential validation, mutation reports, and 100,000-release scalability evidence.

## One-command offline reproduction

From this directory with CPython 3.10 or newer:

```bash
python -m pip install -r requirements.txt
python -m pip install --no-index --no-deps .
python scripts/reproduce.py
```

The package-install line is an offline contract check for this artifact's in-tree build backend; it does not fetch build requirements from a package index. The full reproduction command repeats that contract, compiles all Python modules, runs the branch-aware test suite, executes deterministic cross-oracle smoke validation, checks every bundled result file, verifies the SafetyDB historical-scope boundary, verifies the public advisory overlap fixture, verifies the 2026-06-22 temporal-source boundary, verifies baseline-fairness evidence, verifies optimization-impact evidence, verifies anonymity and package conformance, produces the combined and code-only archives twice outside the project tree, compares them byte-for-byte, and performs clean-extraction replay.

Expected status:

```text
REPAIRWITNESS_REPRODUCTION=PASS
```

## Fast checks

```bash
python scripts/verify_offline_install_contract.py
python -m pytest -q -p no:cacheprovider
python scripts/run_method_smoke.py
python scripts/validate_results.py
python scripts/audit_artifact.py --root ..
```

## Evidence summary

- SafetyDB: historical 2021.7.17 PyPI-specific case study with 1,246 CVE-tagged claims, 602 claim-pair edges, 570 concrete divergent edges, 97 divergent groups, median exact suite size 2, maximum 5, and 97/97 agreement with independent HiGHS. The source-level SafetyDB inputs are not redistributed; this evidence is a digest-bound historical case study, not a full source-level reproduction or current-prevalence claim.
- Synthetic advisory benchmark: redistributable JSONL fixtures under `benchmarks/synthetic_advisory/` replay 96 claim-pair controls across 12 synthetic packages, including 56 known-equivalent negative controls, 32 divergent controls, and 8 typed-abstention controls. `scripts/verify_synthetic_advisory_benchmark.py` recomputes action traces, comparator decisions, suite certificates, fixture hashes, and false-divergence counts from those inputs. These fixtures check implementation correctness and semantic edge cases, not real-world prevalence or complete ecosystem diversity.
- Public advisory overlap: `benchmarks/public_advisory_overlap/` contains selected GHAD/PyPA source records for three real overlap edges across Plone and rembg, plus frozen PyPI release universes. `scripts/verify_public_advisory_overlap.py` reparses the records, recomputes affected sets and repair actions, and confirms that all three edges are `AFFECTED_SET` equivalent but action divergent. This is a construct witness, not a prevalence estimate.
- Controlled validation: 192 exhaustive general instances, 32 independent MILP instances, 160 unit-cost interval instances, 96 weighted interval primal-dual instances, and 64 cross-certification bundles with no objective disagreement.
- Mutation analysis: all 35 semantic certificate corruptions rejected.
- Scalability: the ordered right-endpoint interval workload reaches 100,000 releases and 100,000 obligations in 1.480 s solve time and 0.644 s replay time on the recorded environment; the broader interval scalability validator reports a maximum 6.913 s solve time. `scripts/verify_adversarial_scalability.py` also checks a dense-overlap 20,000-obligation control over 10,000 releases.
- OR-Library: all 50 instances completed; four-second bounded HiGHS reaches 49 known optima with mean ratio 1.00032 and maximum ratio 1.01613. OR-Library validates generic set-cover optimization behavior, not advisory-divergence detection quality.
- Baseline fairness: `scripts/verify_baseline_fairness.py` checks the locked comparator domain, abstention-preserving denominator policy, no post-hoc thresholds, independent comparator implementation, synthetic comparator decision/abstention rates, and replayable OR-Library baseline ratios. On the synthetic controls, the `AFFECTED_SET` comparator records eight false equivalences: it treats some action-divergent repairs as equivalent because it ignores repair-action type and target distinctions. This is reported as evidence that action-level semantics are not reducible to affected-version set equality.
- Temporal scope: `scripts/verify_temporal_scope.py` checks that SafetyDB remains a historical 2021.7.17 case study while `source_manifest.csv` and `config/resource_lock.json` pin five public advisory-source commits accessed on 2026-06-22; these sources document current-source boundaries without turning SafetyDB into a current prevalence claim.
- Coverage contract: `scripts/run_tests_with_coverage.py` refreshes `verification/coverage.json`, `coverage.txt`, and `test_attestation.json`; `scripts/verify_coverage_contract.py` fails the release if overall branch coverage regresses below 70%, branch-aware evidence regresses below the release floor, or any core method file falls below its per-file floor.

Machine-readable values and digests are under `verification/`, `benchmarks/orlib50/`, `benchmarks/synthetic_advisory/`, and `benchmarks/public_advisory_overlap/`. The end-to-end reproduction run writes evaluator-local package archives and replay summaries to an output directory outside the project tree; release archives intentionally exclude those run-local files while keeping the frozen verification evidence.

## Authorized observational rerun

The default reproduction command is offline: it validates the frozen SafetyDB summaries, replays certificates, checks input/report digests, and reruns deterministic smoke campaigns. The source-level observational evaluator is `scripts/run_observational_actions.py`. It is fail-closed and exits before reading any observational input unless the static qualification, package-audit gates, and analysis gate recompute against the exact supplied input digests. This path is for evaluators who separately possess the non-redistributed claim, edge, and release-universe JSONL inputs; it is not a live network fetch and is not needed for the one-command offline artifact check.

## Repository map

- `repairwitness/`: certified optimization, interval algorithms, oracles, network boundary, audit, and release packaging.
- `action_suites/`: advisory normalization, release semantics, grouping, comparator, source reconstruction, and optional authorization workflow.
- `tests/`: deterministic unit, differential, tamper, archive, and semantic tests.
- `scripts/reproduce.py`: full reproduction entry point.
- `scripts/validate_results.py`: independent result-file validator.
- `benchmarks/orlib50/`: 50 raw OR-Library inputs, row-level results, and hashes.
- `verification/`: frozen SafetyDB, controlled, mutation, evolution, scalability, coverage, replay, and release attestations.
- `source_manifest.csv`, `external_resources.csv`, and `reference_ledger.csv`: provenance ledgers.

## Anonymity and claims

Project-authored files contain no author identity, affiliation, personal email, local path, private correspondence, or workflow notes. Public upstream benchmark and advisory bytes retain their own provenance as external evidence.

A repair anchor is reported only as source-supported guidance. RepairWitness does not claim that an anchor is compatible, maintained, exploitable, or universally safe. The reported SafetyDB prevalence is historical and PyPI-specific; the artifact does not claim current ecosystem prevalence. OR-Library evaluates optimization, not advisory semantics.

## License

Project-authored code is distributed under the license in `LICENSE.txt`. Bundled external data retain the provenance and terms recorded in `external_resources.csv`.
