# MLG-004 — baseline vs optimized proof-server containers, 2026-09-15

Raw output of `proof-server/bench/container_matrix.py` and `throughput.py`
against two images built on Linux from this repository's history:

| label | image tag (local) | image id | source |
|---|---|---|---|
| baseline | `mlg004/proof-server:baseline-0d364eb9` | `sha256:801475aa8b1deba19538205c065e61bc2c9248c6a8faf8626b7f6df584ae8dea` | unpatched `ledger-9` base `0d364eb9`, published `midnight-proofs 0.8.2` |
| candidate | `mlg004/proof-server:candidate-70e9d9b5` | `sha256:ae324bbc91038ebd832e6058e8c0f9f53e5dcad5a15e1accbf4a8674c92a8095` | `ledger-9-patched` at `70e9d9b5`, `proofs-0.8-patched` at `535dd7b9` |

Host: Docker Desktop VM, 8 GiB / 12 vCPU, arm64. Host load averaged 20–53
on 12 cores throughout (another workload); `hostload.log` has the samples and
`report.md` flags every cell that ran above load 12. All latencies are upper
bounds from a busy host; the two images were measured minutes apart under the
same conditions.

- `matrix.jsonl` — one row per fresh container, failures included. Rows with
  `spill_backing: bind-mount` and `first-proof-failed` are the seven spill
  cells that hit F-029 (a bind-mounted spill directory); they are not prover
  results and are kept as what they were.
- `burst-summaries.jsonl` / `bursts-per-request.jsonl` — `throughput.py`
  output for 5/10 simultaneous clients at 1/2 workers, k=14, heap.
- `container-logs/` — the server's own log for every cell and burst container.
- `payload-manifests/` — the request payloads' sizes and digests (the payloads
  themselves are regenerated with `payload-gen gen --k N`).
- `report.md` — the tables, rendered by `proof-server/bench/report.py`.

Interpretation, caveats and the recommendation live in the task note
(`MLG-004`) in the project vault, not here.
