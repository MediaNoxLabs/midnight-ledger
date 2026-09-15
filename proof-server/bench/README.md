# Proof-server benchmarks

Two tools, one input format.

- `container_matrix.py` — the baseline-vs-optimized **container comparison**
  (MLG-004): a fresh container per cell (image × storage profile × `k`),
  start-to-ready, one cold proof and N warm proofs, external verification of
  the first and a sampled warm response, peak memory (cgroup `memory.peak`
  and `docker stats`), CPU, spill high-water, OOM events. One JSON line per
  cell, failures included.
- `throughput.py` — the **simultaneous burst** driver (below).

Both send the request bodies that `payload-gen` produces.

## Request payloads at a chosen `k`

```sh
cargo build -p prover-core --bin payload-gen
target/debug/payload-gen gen --k 14 --out results/payloads   # also 19, 20 …
```

`payload-gen` keys the minimal zkir circuit at `k` (`IrSource::v2_keygen_at`
pads it to `2^k` rows, exactly as the in-process benchmark's
`MIDNIGHT_BENCH_K` does) and writes `k<k>-request.bin` — the exact `/prove`
body — plus `k<k>-vk.bin` and a manifest. The body carries the proving-key
material, because the server resolves keys only for the four published
zswap/dust circuits; so every image under test receives byte-identical input
and no image needs a key volume. Sizes grow with `k` (the gzipped proving key
dominates): about 4 MB at k=14, 67 MB at k=18, 135 MB at k=19, ~270 MB at
k=20. A ten-request burst at k=20 is therefore ~2.7 GB of request bodies —
say so in any result that includes it.

What such a payload measures is the prover **at a size** — FFTs over `2^k`
rows, MSMs of `2^k` points, the coset working set — not a real circuit's
content. That is the question the container comparison asks; it is not a
substitute for a real k=20 contract, and the results must not be presented
as one.

Verify a response outside any container:

```sh
target/debug/payload-gen verify --vk results/payloads/k14-vk.bin --proof response.bin
```

## Container comparison

```sh
python3 proof-server/bench/container_matrix.py \
  --image <candidate image> --label candidate \
  --payload-dir results/payloads --k 14,19,20 \
  --profiles heap,pk-mmap,threshold,forced-spill --warm 5 \
  --out results/matrix.jsonl
python3 proof-server/bench/container_matrix.py \
  --image <baseline image> --label baseline \
  --payload-dir results/payloads --k 14,19,20 --profiles heap --warm 5 \
  --out results/matrix.jsonl
```

Profiles are the `MIDNIGHT_SPILL_*` environment the optimized image reads
(`heap`: all off; `pk-mmap`: key mapped; `threshold`: key mapped, cosets
spilled at k ≥ 18; `forced-spill`: cosets spilled at every `k` — a diagnostic,
not a proposed default). An unpatched baseline ignores those variables, so run
it with `--profiles heap` only.

Cold and warm are separate numbers and stay separate: `first_proof_s` is the
first request after `/ready` on a fresh container with the params volume
already populated (the deploy/restart number); `warm_median_s` is over N
sequential requests after one unmeasured warm-up. `--cold-empty` omits the
params volume so the server fetches over the network — a third, separate
number. `--memory 6g` runs the cell under a cgroup limit; an OOM kill is a
row with `outcome: oom-killed`, never a missing row. Every cell records
`log_mentions_fallback`: a spill profile whose container log says "falling
back to heap" is not a spill result.

# Burst throughput

`throughput.py` sends every HTTP request at the same time. The proof server,
not the client, controls active proving concurrency through
`MIDNIGHT_PROOF_SERVER_NUM_WORKERS`; excess requests remain in its bounded job
queue. This distinction makes a 5- or 10-request burst safe to test with one
active `k=20` prover.

Start the optimized image with an explicitly sized writable spill volume and
an explicit worker count. For the first `k=20` qualification, use one worker
and a queue capacity of ten:

```sh
MIDNIGHT_PROOF_SERVER_NUM_WORKERS=1
MIDNIGHT_PROOF_SERVER_JOB_CAPACITY=10
MIDNIGHT_PROOF_SERVER_JOB_TIMEOUT=1800
MIDNIGHT_SPILL_PK=1
MIDNIGHT_SPILL_COSETS=1
MIDNIGHT_SPILL_FLOOR_K=18
MIDNIGHT_SPILL_DIR=/spill
```

Then run separate 5- and 10-client bursts with the exact binary `/prove`
payload under test:

```sh
python3 proof-server/bench/throughput.py \
  --payload results/k20-request.bin \
  --requests 5 \
  --label optimized-k20-workers1-burst5 \
  --output results/optimized-k20-workers1-burst5.jsonl \
  --save-responses results/optimized-k20-workers1-burst5/
```

Repeat with `--requests 10`. Repeat the pair with two workers only after the
one-worker run has measured the container's idle/shared footprint, incremental
per-proof memory, and spill high-water. The conservative admission bound is:

```text
workers <= min(
  floor((memory_limit - idle_shared - safety_margin) / per_proof_increment),
  floor(free_spill_bytes / per_active_proof_spill_bytes),
  allocated_cpu_parallelism
)
```

The laptop's current one-proof `k=20` spill observation was 6.04 GiB physical
footprint and 9.89 GiB spill high-water. Those are starting bounds, not a
multi-worker model: shared SRS/PK mappings mean the incremental second worker
must be measured. Until it is, budget at least 12 GiB RAM and 12 GiB free spill
space for one active worker and keep the queue bounded. The current local Docker
VM has only 8 GiB assigned, so it must be enlarged before this run.

The 1,800-second server timeout is intentional: timeout is measured from job
submission, including time in the queue. At the observed one-worker rate, the
tail of a ten-request `k=20` burst exceeds the default 600 seconds. If the
deployment cannot grant a longer deadline, reject requests that cannot finish
inside the remaining deadline instead of accepting and later discarding them.

Record `docker stats`, cgroup `memory.peak`/`memory.events`, spill volume usage,
CPU allocation, `RAYON_NUM_THREADS`, server worker count, queue capacity, image
digest, and payload hash alongside the JSONL.

## Verifying the proofs

HTTP 200 is not proof correctness, and a byte count is not a proof. With
`--save-responses DIR` every successful body is written to
`DIR/<label>-<nn>.bin`, and each JSONL `request` record carries
`response_sha256` and `response_path`; the `summary` record carries
`payload_sha256`. That is enough to verify after the fact, on another machine,
against the exact bytes the server returned:

1. Take the `.bin` for every first response of a burst (`-00`) and at least one
   warm sample from later in the same burst.
2. Verify each with the external verifier used for the MLG-004 latency
   comparison, against the same `payload_sha256` payload.
3. Recompute `sha256(<file>)` and confirm it equals the record's
   `response_sha256` — this ties the verified bytes to the latency you report.

A run whose first response does not verify is a failed run, whatever its
latency. Keep the `.bin` files with the JSONL; they are the evidence.
