#!/usr/bin/env python3
"""Send a simultaneous request burst to a running Midnight proof server.

The client count is deliberately independent from the server's worker count:
all clients connect together, while MIDNIGHT_PROOF_SERVER_NUM_WORKERS controls
how many proofs become active and the remaining requests stay queued.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class RequestResult:
    request: int
    started_s: float
    finished_s: float
    latency_s: float
    status: int
    response_bytes: int
    error: str | None


def positive_request_count(value: str) -> int:
    count = int(value)
    if not 1 <= count <= 100:
        raise argparse.ArgumentTypeError("requests must be in 1..=100")
    return count


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(len(ordered) * fraction + 0.999999) - 1))
    return ordered[index]


def fetch_ready(url: str, timeout: float) -> dict[str, Any] | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return json.loads(response.read())
    except (OSError, ValueError, urllib.error.URLError):
        return None


def run(args: argparse.Namespace) -> int:
    payload = args.payload.read_bytes()
    ready_url = args.ready_url or args.url.rsplit("/", 1)[0] + "/ready"
    gate = threading.Barrier(args.requests + 1)
    stop_sampling = threading.Event()
    ready_samples: list[dict[str, Any]] = []
    ready_lock = threading.Lock()
    burst_origin = time.perf_counter()

    def sample_ready() -> None:
        while not stop_sampling.wait(args.ready_interval):
            sample = fetch_ready(ready_url, min(args.timeout, 2.0))
            if sample is not None:
                sample["observed_s"] = time.perf_counter() - burst_origin
                with ready_lock:
                    ready_samples.append(sample)

    sampler = threading.Thread(target=sample_ready, name="ready-sampler", daemon=True)
    sampler.start()

    def request_once(request_id: int) -> RequestResult:
        gate.wait()
        started = time.perf_counter()
        request = urllib.request.Request(
            args.url,
            data=payload,
            headers={"Content-Type": "application/octet-stream"},
            method="POST",
        )
        status = 0
        body = b""
        error = None
        try:
            with urllib.request.urlopen(request, timeout=args.timeout) as response:
                status = response.status
                body = response.read()
        except urllib.error.HTTPError as exc:
            status = exc.code
            body = exc.read()
            error = str(exc)
        except (OSError, urllib.error.URLError) as exc:
            error = str(exc)
        finished = time.perf_counter()
        return RequestResult(
            request=request_id,
            started_s=started - burst_origin,
            finished_s=finished - burst_origin,
            latency_s=finished - started,
            status=status,
            response_bytes=len(body),
            error=error,
        )

    with ThreadPoolExecutor(max_workers=args.requests) as executor:
        futures = [executor.submit(request_once, request) for request in range(args.requests)]
        gate.wait()
        results = sorted((future.result() for future in futures), key=lambda item: item.request)

    stop_sampling.set()
    sampler.join(timeout=3)
    makespan = max(result.finished_s for result in results) - min(
        result.started_s for result in results
    )
    successful = [result for result in results if 200 <= result.status < 300]
    latencies = [result.latency_s for result in successful]
    summary: dict[str, Any] = {
        "type": "summary",
        "label": args.label,
        "url": args.url,
        "requests": args.requests,
        "payload_bytes": len(payload),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "successful": len(successful),
        "failed": len(results) - len(successful),
        "makespan_s": makespan,
        "throughput_requests_s": len(successful) / makespan if makespan else None,
        "latency_mean_s": statistics.fmean(latencies) if latencies else None,
        "latency_p50_s": percentile(latencies, 0.50) if latencies else None,
        "latency_p95_s": percentile(latencies, 0.95) if latencies else None,
        "latency_p99_s": percentile(latencies, 0.99) if latencies else None,
        "ready_samples": len(ready_samples),
        "max_jobs_processing": max(
            (sample.get("jobsProcessing", 0) for sample in ready_samples), default=None
        ),
        "max_jobs_pending": max(
            (sample.get("jobsPending", 0) for sample in ready_samples), default=None
        ),
    }
    lines = [json.dumps({"type": "request", **asdict(result)}, sort_keys=True) for result in results]
    lines.extend(
        json.dumps({"type": "ready", **sample}, sort_keys=True) for sample in ready_samples
    )
    lines.append(json.dumps(summary, sort_keys=True))
    output = "\n".join(lines) + "\n"
    print(output, end="")
    if args.output is not None:
        args.output.write_text(output)
    return 0 if len(successful) == len(results) else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:6300/prove")
    parser.add_argument("--ready-url")
    parser.add_argument("--payload", required=True, type=Path)
    parser.add_argument("--requests", type=positive_request_count, default=5)
    parser.add_argument("--timeout", type=float, default=1800.0)
    parser.add_argument("--ready-interval", type=float, default=0.25)
    parser.add_argument("--label", default="unlabelled")
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


if __name__ == "__main__":
    raise SystemExit(run(parse_args()))
