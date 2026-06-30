# Public Advisory Overlap Benchmark

This small fixture is not a prevalence sample. It is a redistributable source-level check that public GHAD/PyPA overlap records can have identical affected-release sets while prescribing different repair actions. The verifier reparses the included records, rebuilds action traces over the frozen PyPI release universes, and checks that the affected-set comparator returns `EQUIVALENT` while the repair-action relation returns `DIVERGENT` for all three edges.

Files:
- `records/`: selected upstream advisory records.
- `records.jsonl`: provenance and digests for the records.
- `claims.jsonl`: normalized claims expected from the records.
- `edges.jsonl`: paired overlap edges and witness actions.
- `release_universes.jsonl`: frozen package release histories used for replay.
