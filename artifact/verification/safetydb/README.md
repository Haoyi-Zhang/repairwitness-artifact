# SafetyDB Historical Case Study

This directory contains digest-bound summary evidence for a frozen SafetyDB 2021.7.17 PyPI case study. It does not redistribute the source-level claim, edge, or release-universe inputs.

The default artifact reproduction validates the bundled summaries, certificates, inventory counts, comparator results, and input digests offline. This supports the historical case-study and optimization replay claims only; it is not a live registry fetch, current-prevalence study, or full source-level SafetyDB reproduction.

For source-level semantic reproduction, use the fully redistributed controls under `benchmarks/synthetic_advisory/`. For evaluators who separately possess the original SafetyDB-derived inputs, `scripts/run_observational_actions.py` provides a fail-closed rerun path that checks the expected digests before reading the supplied files.
