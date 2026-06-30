# Deterministic Reproduction

## 1. Environment

Supported interpreter: CPython 3.10 or newer. Install the pinned runtime/test dependencies recorded in `requirements.txt`, then verify that the artifact package itself installs without build-time index access:

```bash
cd artifact
python -m pip install -r requirements.txt
python -m pip install --no-index --no-deps .
```

Offline reproduction does not require registry or advisory-network access.

## 2. Full artifact reproduction

```bash
OUTDIR=$(mktemp -d)
python scripts/reproduce.py --outdir "$OUTDIR"
```

The command performs, in order:

1. Python bytecode compilation without importing network resources.
2. Offline package installation in a fresh virtual environment with `python -m pip install --no-index --no-deps .`.
3. The deterministic branch-aware test suite and refreshed coverage attestation.
4. A seeded cross-oracle method smoke campaign.
5. Independent validation of SafetyDB, controlled, scalability, mutation, OR-Library, redistributable synthetic advisory controls, dense-overlap scalability, coverage-contract, SafetyDB historical-scope, temporal-scope, baseline-fairness, and optimization-impact result files.
6. Anonymity and release-tree conformance checks.
7. Two independent creations of the combined and code-only ZIP archives and byte equality checks.
8. Safe extraction of the combined archive into a fresh directory.
9. Reproduction smoke checks inside the extracted copy.
10. Emission of run-local package archives, clean-extraction evidence, release attestation, and reproduction summary into an output directory outside the project tree. These evaluator-local files are intentionally excluded from deterministic release archives. The in-tree release attestation is a pre-package subject summary; the packaged-release attestation in the evaluator output directory records archive byte equality, clean extraction replay, and transport hashes without embedding a self-referential archive digest.

No paper number is accepted from a stored summary unless the corresponding validator passes.

## 3. Targeted reproduction

### Tests

```bash
python scripts/run_tests_with_coverage.py
```

### Controlled solver validation

```bash
python scripts/run_method_smoke.py
python scripts/validate_results.py
```

The full frozen campaigns are represented by `verification/method_validation.json`, `verification/method_validation_release.json`, `mutation_crosscheck.json`, `evolutionary.json`, `verification/interval_scalability.json`, and `verification/ordered_interval_scalability.json`. The smoke command is a short independent rerun; the validator checks the frozen reports.

### OR-Library

All raw inputs are in `benchmarks/orlib50/inputs/`. Validate the 50 hashes, known-optimum ratios, CSV, and canonical report digest:

```bash
python scripts/validate_results.py
```

The release report uses deterministic greedy plus reverse deletion, LP-guided rounding, and SciPy/HiGHS MILP with a four-second per-instance limit.

### SafetyDB

`verification/safetydb/summary.json` and `verification/safetydb_external_summary.json` bind the historical input and release-universe digests, inventory, edge dispositions, baseline results, certificate validity, and runtime. The release archive includes the summary and acquisition/provenance recipe rather than redistributing mutable registry response bytes or source-level recovery rows. The SafetyDB layer is therefore a digest-bound historical case study, not a full source-level reproduction claim, live registry query, or current-prevalence claim. `verification/safetydb/README.md` records this boundary at the case-study directory itself.

### Redistributable synthetic advisory controls

`benchmarks/synthetic_advisory/claims.jsonl`, `edges.jsonl`, and `release_universes.jsonl` are fully redistributed source-level inputs. They exercise known-equivalent negative controls, divergent action controls, typed abstentions, comparator decision rates, and suite certificates:

```bash
python scripts/verify_synthetic_advisory_benchmark.py
```

The output `verification/synthetic_advisory_benchmark.json` records fixture hashes, action-trace digest, 56 known-equivalent controls with zero false divergences, and per-comparator decided/abstained counts. These controls test the formal action semantics and implementation behavior across 12 synthetic packages; they do not claim real-world semantic diversity and do not enter the SafetyDB prevalence denominator. `benchmarks/synthetic_advisory/CONSTRUCTION.md` describes the construction dimensions and overfitting boundary.

`verification/public_advisory_overlap.json` records the replay of the redistributed GHAD/PyPA overlap fixture. Its purpose is narrower than SafetyDB prevalence and stronger than a synthetic control: it checks that included source-level public records can have equal affected-release sets while inducing different repair actions.

### Dense-overlap scalability control

```bash
python scripts/verify_adversarial_scalability.py
```

This reruns a dense-overlap interval instance with 20,000 obligations over 10,000 releases and records `verification/adversarial_scalability.json`.

### Authorized observational rerun

The offline command above is the artifact's default reproduction path. For evaluators with the non-redistributed claim, edge, and release-universe JSONL inputs, the source-level action evaluator can be run only after the authorization predicate recomputes successfully against the exact input digests:

```bash
OUTDIR=$(mktemp -d)
python scripts/run_observational_actions.py \
  --project-root .. \
  --claims <claims.jsonl> \
  --edges <edges.jsonl> \
  --release-universes <release_universes.jsonl> \
  --output-dir "$OUTDIR/observational"
```

If the static qualification, package-audit gates, or analysis gate are missing or do not bind to those inputs, the script returns `{"status": "BLOCKED"}` before creating the output directory. This fail-closed behavior prevents accidental outcome-dependent reruns while leaving a concrete rerun path for authorized source-level replication.

## 4. Paper build

The paper uses the unmodified IEEE conference class. From `paper/`:

```bash
latexmk -pdf -interaction=nonstopmode -halt-on-error main.tex
latexmk -pdf -interaction=nonstopmode -halt-on-error supplement.tex
```

The main PDF has 12 pages: pages 1-10 contain the paper and pages 11-12 contain references only. Figures are generated from TikZ/PGFPlots and `paper/data/*.dat`; no screenshots are used.

## 5. Packaging

From `artifact/`:

```bash
OUTDIR=$(mktemp -d)
python scripts/package_release.py \
  --project-root .. \
  --combined "$OUTDIR/RepairWitness.zip" \
  --code "$OUTDIR/RepairWitness-Code.zip"
```

The combined archive contains exactly `paper/` and `artifact/`. ZIP timestamps and permissions are fixed. Repeating the command over unchanged release bytes must produce identical SHA-256 values. The packaging command rejects archive outputs inside the audited project tree so a manual package run cannot pollute the release directory.

## 6. Clean extraction

```bash
python scripts/clean_replay.py "$OUTDIR/RepairWitness.zip" \
  --output "$OUTDIR/clean_replay.json"
```

Extraction rejects traversal and writes only below a fresh temporary root. The extracted tree is checked and the reproduction smoke command is executed there.
