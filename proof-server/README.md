# midnight-proof-server

An HTTP wrapper around proving. `POST /prove` takes a tagged
`(ProofPreimageVersioned, Option<ProvingKeyMaterial>, Option<Fr>)` and returns
a tagged `ProofVersioned`; `/health`, `/ready`, `/version` and the job
endpoints are described in `src/endpoints.rs`.

## Configuration

| Variable | Meaning | Default |
|---|---|---|
| `MIDNIGHT_PROOF_SERVER_PORT` / `--port` | listen port | `6300` |
| `MIDNIGHT_PROOF_SERVER_NUM_WORKERS` | concurrent proving workers (they share one Rayon pool) | `2` |
| `MIDNIGHT_PROOF_SERVER_JOB_CAPACITY` | bounded queue depth (admission is atomic) | `10` |
| `MIDNIGHT_PROOF_SERVER_JOB_TIMEOUT` | seconds from *submission* to completion | `600` |
| `MIDNIGHT_PROOF_SERVER_NO_FETCH_PARAMS` | `true` to skip fetching the published keys at start | `false` |
| `MIDNIGHT_PROOF_SERVER_MAX_REQUEST_BYTES` | largest request body the server will buffer | `536870912` (512 MiB) |
| `MIDNIGHT_PP` | directory holding `bls_midnight_2p<k>` params | `~/.cache/midnight/zk-params` |

The prover's memory policy comes from the `midnight-proofs` crate and is read
from the same environment:

| Variable | Meaning |
|---|---|
| `MIDNIGHT_SPILL_PK` | `1`: map the proving key from a spill file instead of holding it on the heap |
| `MIDNIGHT_SPILL_COSETS` | `1`: spill the extended-domain cosets to disk during proving |
| `MIDNIGHT_SPILL_FLOOR_K` | spill only at `k ≥` this (default `18`); `0` forces it at every `k` |
| `MIDNIGHT_SPILL_DIR` | directory for spill files; the OS temp dir when unset |

Measured trade-offs (one host, `proof-server/bench/results/mlg004-2026-09-15/`):
below the floor the flags cost nothing; at `k=19`, where heap proving fits in
~5 GiB, spilling is 28–39 % slower; at `k=20` heap proving needs ~14 GiB and
is OOM-killed in an 8 GiB container, while `SPILL_PK=1 SPILL_COSETS=1`
completes in **6 GiB** (peak 5.9 GiB) writing ~7 GB of temporary data per
proof. A profile that is a sensible production default: spill on, floor `18`.

## Where to put the spill directory

- A **named Docker volume** or a VM-local disk. Not a **Docker Desktop bind
  mount** of a host directory: the prover's temp-file creation fails there
  with `ENOENT` even though the directory exists, every request that needs
  the key fails, and until this was fixed the failure read as a client error.
- Not `tmpfs`: it works, but it is memory-backed, which defeats what spill is
  for.
- Budget ~10 GB of free space per active `k=20` worker.

## What the status codes mean

- **400** — the request is at fault: malformed key material, an IR of a
  circuit class this prover does not handle (`version.minor` 0/1 is the
  legacy v1 prover; 2 is the current one), a failing constraint.
- **500** — the server's environment is at fault: a spill directory that
  cannot take a temp file, a full or read-only volume, an unsupported
  filesystem. The body and the server log both name the operation and the
  directory (`Could not init pk: create spill temp file in /spill: No such
  file or directory`). A 500 from a valid request means the deployment, not
  the client, needs fixing.
- **429** — the bounded queue is full; **412** — the job id is unknown;
  **400** also for a job that is no longer pending.
- **413** — the request body is larger than
  `MIDNIGHT_PROOF_SERVER_MAX_REQUEST_BYTES`. A declared `Content-Length` over
  the bound is refused before a byte is read; a body that arrives chunked, or
  lies about its length, is cut off at the same bound while streaming.

### What bounds what

`JOB_CAPACITY` bounds proving. `MAX_REQUEST_BYTES` bounds a single request's
memory, and the 429 is now answered **before** the body is read rather than
after it has been buffered, deserialised and its proving-key material copied —
a `/prove` body carries the whole key material inline, on the order of 269 MB
at k=20, so a queue-full server used to hold one of those per in-flight
request. The time bound is the server's `client_request_timeout` (60 s to send
a complete request) and `client_disconnect_timeout`.

## Benchmarks

`bench/README.md`: the in-process ZSwap benchmark, request payloads at a
chosen `k`, the container comparison runner, the burst driver and the report
renderer.
