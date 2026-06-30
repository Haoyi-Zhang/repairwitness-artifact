# Synthetic Advisory Benchmark Construction

This benchmark is a redistributable source-level control layer for RepairWitness. It is designed to exercise the action-semantics implementation, comparator accounting, abstention handling, and witness-certificate replay without contributing to SafetyDB prevalence estimates.

The fixtures are generated deterministically by `scripts/verify_synthetic_advisory_benchmark.py`. The script materializes `claims.jsonl`, `edges.jsonl`, and `release_universes.jsonl` from explicit semantic cases, then reloads the files and verifies that the on-disk rows exactly match the expected construction. This prevents hand-edited fixtures from silently drifting away from the declared design.

Design dimensions:

- repair-action outcomes: `NO_ACTION`, source-supported upgrade, alternative action, repair without public target, and typed abstention;
- comparator behavior: canonical ACTION decisions plus raw-record, affected-set, target, type, and action-family comparators;
- control labels: known-equivalent negative controls, divergent controls, and abstention controls;
- release topology: short and longer release histories, overlapping affected ranges, changed target releases, withdrawn or unsupported claims, and mixed concrete/unknown outcomes;
- certificate replay: each divergent group receives a witness suite whose certificate is replayed independently by the verifier.

Scale boundary: the suite covers 12 synthetic packages, 192 claims, and 96 claim-pair controls. It is intended as a deterministic implementation and semantic-control benchmark, not as a representative sample of real-world advisory diversity. Real-claim optimization behavior is assessed separately through the digest-bound historical SafetyDB case study; neither layer is used to claim current ecosystem prevalence.

Overfitting boundary: the fixture generator is keyed to semantic requirements rather than observed method failures. The verifier checks expected fixture hashes, action traces, false-divergence counts, divergent-control misses, comparator decision and abstention rates, and suite-certificate replay from the redistributed JSONL inputs.
