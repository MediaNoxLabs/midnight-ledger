# Proof-server burst throughput

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
  --output results/optimized-k20-workers1-burst5.jsonl
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
digest, payload hash, and proof verification alongside the JSONL. HTTP success
is not proof correctness; verify every first response and a warm sample with
the same external verifier used for the latency comparison in MLG-004.
