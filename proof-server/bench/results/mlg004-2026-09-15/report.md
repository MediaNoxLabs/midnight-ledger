## Images

- `mlg004/proof-server:candidate-70e9d9b5` — `sha256:ae324bbc91038ebd832e6058e8c0f9f53e5dcad5a15e1accbf4a8674c92a8095`
- `mlg004/proof-server:baseline-0d364eb9` — `sha256:801475aa8b1deba19538205c065e61bc2c9248c6a8faf8626b7f6df584ae8dea`

## Cells (one fresh container each; every row kept)

| image | profile | spill backing | k | mode | outcome | start→ready s | first proof s | verified | warm median s (n) | warm min–max s | peak MiB (docker stats) | spill high-water MiB | OOM | host load 1m |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| candidate | heap | bind-mount | 14 | cold-preseeded | ok | 0.017 | 0.97 | yes / warm yes | 0.640 (30) | 0.610–0.990 | 296 | — | no | — |
| candidate | pk-mmap | bind-mount | 14 | cold-preseeded | first-proof-failed (bad input: `Could not init pk: No such file or directory (os) | 0.003 | 0.20 | — | — | — | — | — | no | — |
| candidate | threshold | bind-mount | 14 | cold-preseeded | first-proof-failed (bad input: `Could not init pk: No such file or directory (os) | 0.007 | 0.19 | — | — | — | — | — | no | — |
| candidate | forced-spill | bind-mount | 14 | cold-preseeded | first-proof-failed (bad input: `Could not init pk: No such file or directory (os) | 0.003 | 0.18 | — | — | — | — | — | no | — |
| baseline | heap | bind-mount | 14 | cold-preseeded | ok | 0.016 | 0.98 | yes / warm yes | 0.718 (30) | 0.671–0.933 | 305 | — | no | — |
| candidate | heap | bind-mount | 14 | cold-empty | ok | 20.178 | 0.83 | yes / warm yes | 0.617 (3) | 0.616–0.634 | 218 | — | no | 30–30 ⚠ |
| baseline | heap | bind-mount | 14 | cold-empty | ok | 29.706 | 0.90 | yes / warm yes | 0.689 (3) | 0.688–0.690 | 199 | — | no | 30–30 ⚠ |
| candidate | threshold | bind-mount | 19 | cold-preseeded | first-proof-failed (bad input: `Could not init pk: No such file or directory (os) | 0.016 | 4.53 | — | — | — | 1,426 | — | no | 30–43 ⚠ |
| candidate | forced-spill | bind-mount | 19 | cold-preseeded | first-proof-failed (bad input: `Could not init pk: No such file or directory (os) | 0.002 | 4.20 | — | — | — | 994 | — | no | 30–43 ⚠ |
| candidate | threshold | bind-mount | 20 | cold-preseeded | first-proof-failed (bad input: `Could not init pk: No such file or directory (os) | 0.003 | 9.52 | — | — | — | 3,038 | — | no | 43–53 ⚠ |
| candidate | forced-spill | bind-mount | 20 | cold-preseeded | first-proof-failed (bad input: `Could not init pk: No such file or directory (os) | 0.002 | 9.08 | — | — | — | 3,135 | — | no | 43–53 ⚠ |
| candidate | heap | bind-mount | 19 | cold-preseeded | ok | 0.026 | 25.75 | yes / warm yes | 17.671 (3) | 16.874–18.235 | 5,044 | — | no | 38–53 ⚠ |
| candidate | pk-mmap | bind-mount | 19 | cold-preseeded | first-proof-failed (bad input: `Could not init pk: No such file or directory (os) | 0.003 | 4.31 | — | — | — | 1,475 | — | no | 27–38 ⚠ |
| candidate | heap | bind-mount | 20 | cold-preseeded | oom-killed (Remote end closed connection without response) | 0.003 | 20.30 | — | — | — | 5,539 | — | yes | 27–29 ⚠ |
| candidate | pk-mmap | bind-mount | 20 | cold-preseeded | first-proof-failed (bad input: `Could not init pk: No such file or directory (os) | 0.113 | 9.62 | — | — | — | 3,086 | — | no | 27–29 ⚠ |
| candidate | pk-mmap | docker-volume | 14 | cold-preseeded | ok | 0.015 | 0.85 | yes / warm yes | 0.685 (30) | 0.656–0.830 | 374 | 0 | no | 20–30 ⚠ |
| candidate | threshold | docker-volume | 14 | cold-preseeded | ok | 0.003 | 0.82 | yes / warm yes | 0.667 (30) | 0.653–0.778 | 364 | 0 | no | 24–30 ⚠ |
| candidate | forced-spill | docker-volume | 14 | cold-preseeded | ok | 0.003 | 1.12 | yes / warm yes | 0.814 (30) | 0.775–0.973 | 234 | 0 | no | 24–30 ⚠ |
| baseline | heap | docker-volume | 19 | cold-preseeded | ok | 0.016 | 26.00 | yes / warm yes | 18.569 (3) | 18.124–18.765 | 5,177 | 0 | no | 24–52 ⚠ |
| baseline | heap | docker-volume | 20 | cold-preseeded | oom-killed (Remote end closed connection without response) | 0.003 | 28.48 | — | — | — | 5,606 | 0 | yes | 46–46 ⚠ |
| candidate | threshold | docker-volume | 19 | cold-preseeded | ok | 0.124 | 27.42 | yes / warm yes | 24.606 (3) | 24.008–25.145 | 5,039 | 0 | no | 22–46 ⚠ |
| candidate | forced-spill | docker-volume | 19 | cold-preseeded | ok | 0.003 | 27.18 | yes / warm yes | 22.844 (3) | 22.600–23.708 | 5,026 | 0 | no | 21–34 ⚠ |
| candidate | pk-mmap | docker-volume | 19 | cold-preseeded | ok | 0.003 | 23.97 | yes / warm yes | 22.557 (3) | 21.241–24.473 | 5,259 | 0 | no | 33–43 ⚠ |
| candidate | threshold | docker-volume | 20 | cold-preseeded | ok | 0.004 | 72.97 | yes / warm yes | 65.167 (3) | 61.227–71.283 | 7,361 | 0 | no | 33–45 ⚠ |
| candidate | forced-spill | docker-volume | 20 | cold-preseeded | ok | 0.108 | 74.76 | yes / warm yes | 67.219 (3) | 62.136–71.543 | 7,175 | 0 | no | 24–41 ⚠ |
| candidate | pk-mmap | docker-volume | 20 | cold-preseeded | ok | 0.108 | 62.27 | yes / warm yes | 55.388 (3) | 52.859–61.255 | 7,543 | 0 | no | 24–34 ⚠ |
| candidate | heap | docker-volume | 14 | cold-preseeded | ok | 0.020 | 0.90 | yes / warm yes | 0.661 (30) | 0.642–0.800 | 360 | 0 | no | 13–14 ⚠ |
| candidate | pk-mmap | docker-volume | 14 | cold-preseeded | ok | 0.003 | 0.90 | yes / warm yes | 0.731 (30) | 0.690–0.870 | 318 | 0 | no | 13–13 ⚠ |
| candidate | threshold | docker-volume | 14 | cold-preseeded | ok | 0.003 | 0.86 | yes / warm yes | 0.699 (30) | 0.674–0.813 | 387 | 0 | no | 11–13 ⚠ |
| candidate | forced-spill | docker-volume | 14 | cold-preseeded | ok | 0.003 | 1.05 | yes / warm yes | 0.868 (30) | 0.816–0.985 | 274 | 0 | no | 10–11 |
| baseline | heap | docker-volume | 14 | cold-preseeded | ok | 0.124 | 0.97 | yes / warm yes | 0.736 (30) | 0.698–1.029 | 269 | 0 | no | 9–10 |
| candidate | heap | docker-volume | 14 | cold-preseeded | ok | 0.022 | 0.98 | yes / warm yes | 0.673 (30) | 0.641–0.871 | 350 | 0 | no | 9–9 |
| candidate | pk-mmap | docker-volume | 14 | cold-preseeded | ok | 0.003 | 0.88 | yes / warm yes | 0.726 (30) | 0.662–1.398 | 362 | 0 | no | 9–12 |
| candidate | threshold | docker-volume | 14 | cold-preseeded | ok | 0.002 | 0.84 | yes / warm yes | 0.692 (30) | 0.670–0.823 | 280 | 0 | no | 9–12 |
| candidate | forced-spill | docker-volume | 14 | cold-preseeded | ok | 0.003 | 0.99 | yes / warm yes | 0.868 (30) | 0.820–1.028 | 297 | 0 | no | 11–12 |
| baseline | heap | docker-volume | 14 | cold-preseeded | ok | 0.017 | 0.98 | yes / warm yes | 0.736 (30) | 0.700–0.851 | 323 | 0 | no | 11–13 ⚠ |
| candidate | heap | docker-volume | 19 | cold-preseeded | ok | 0.017 | 27.10 | yes / warm yes | 18.963 (3) | 18.516–19.634 | 5,008 | 0 | no | 13–17 ⚠ |
| candidate | threshold | docker-volume | 19 | cold-preseeded | ok | 0.003 | 30.98 | yes / warm yes | 26.935 (3) | 26.273–27.801 | 5,003 | 0 | no | 13–20 ⚠ |
| candidate | pk-mmap | docker-volume | 19 | cold-preseeded | ok | 0.006 | 24.10 | yes / warm yes | 23.081 (3) | 21.701–24.510 | 5,177 | 0 | no | 19–22 ⚠ |
| baseline | heap | docker-volume | 19 | cold-preseeded | ok | 0.020 | 30.73 | yes / warm yes | 20.632 (3) | 19.730–21.517 | 5,159 | 0 | no | 20–24 ⚠ |
| candidate | threshold | docker-volume | 20 | cold-preseeded | ok | 0.018 | 77.89 | yes / warm yes | 62.064 (1) | 62.064–62.064 | 6,062 | 0 | no | 14–23 ⚠ |
| candidate | pk-mmap | docker-volume | 20 | cold-preseeded | oom-killed (Remote end closed connection without response) | 0.003 | 23.56 | — | — | — | 5,572 | 0 | yes | 14–18 ⚠ |
| candidate | threshold | docker-volume | 20 | cold-preseeded | ok | 0.018 | 69.40 | yes / warm yes | 62.232 (1) | 62.232–62.232 | 6,812 | 0 | no | 11–22 ⚠ |

⚠ = sampled 1-minute host load above 12 during the cell; the latency is not the image's.

## Bursts (k=14, heap, simultaneous clients)

| run | requests | failed | mean s | p50 s | p95 s | p99 s | makespan s | req/s | max processing | max pending |
|---|---|---|---|---|---|---|---|---|---|---|
| candidate-k14-w1-n5 | 5 | 0 | 2.27 | 2.26 | 3.49 | 3.49 | 3.49 | 1.431 | 1 | 4 |
| candidate-k14-w1-n10 | 10 | 0 | 3.73 | 3.43 | 6.39 | 6.39 | 6.39 | 1.565 | 1 | 9 |
| candidate-k14-w2-n5 | 5 | 0 | 1.92 | 2.15 | 2.72 | 2.72 | 2.72 | 1.836 | 2 | 3 |
| candidate-k14-w2-n10 | 10 | 0 | 2.83 | 2.82 | 4.49 | 4.49 | 4.49 | 2.227 | 2 | 8 |
| baseline-k14-w1-n5 | 5 | 0 | 2.44 | 2.46 | 3.75 | 3.75 | 3.75 | 1.332 | 1 | 4 |
| baseline-k14-w1-n10 | 10 | 0 | 4.11 | 3.71 | 7.16 | 7.16 | 7.16 | 1.397 | 1 | 9 |
| baseline-k14-w2-n5 | 5 | 0 | 2.05 | 2.22 | 2.91 | 2.91 | 2.91 | 1.717 | 2 | 3 |
| baseline-k14-w2-n10 | 10 | 0 | 3.29 | 3.29 | 5.36 | 5.36 | 5.36 | 1.866 | 2 | 8 |
