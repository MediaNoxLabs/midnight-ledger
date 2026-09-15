#!/usr/bin/env python3
"""Run the proof-server container comparison (MLG-004) one cell at a time.

A cell is (image, profile, k). For each cell this script starts a *fresh*
container, measures start-to-ready, sends one cold proof and N warm proofs,
verifies the first and a sampled warm response outside the container with
`payload-gen verify`, samples memory/CPU/spill while proving, and appends one
JSON line per cell to the results file. A cell that fails — OOM kill, timeout,
HTTP error, verification failure — is still a row; the denominator is never
trimmed.

Cold/warm are kept separate, as MLG-004 requires:
  cold-preseeded   params volume already populated (this script's default);
                   the number reported as `first_proof_s` is the deploy/restart
                   number, not a cache-miss number.
  warm             sequential proofs against the same ready container after
                   one unmeasured warm-up.
Cold-empty (params fetched over the network) is `--cold-empty`, separate rows.

The request bodies come from `payload-gen gen --k N` and carry the
proving-key material, so every image receives byte-identical input.

Usage (one image, three sizes, all four profiles):
  python3 proof-server/bench/container_matrix.py \
    --image ghcr.io/midnight-ntwrk/proof-server:9.0.0-rc.7-arm64 --label candidate \
    --payload-dir /tmp/mlg004/payloads --k 14,19,20 \
    --profiles heap,pk-mmap,threshold,forced-spill --warm 5 \
    --out /tmp/mlg004/results.jsonl
  # baseline: an unpatched image ignores the MIDNIGHT_SPILL_* variables, so
  # run it with --profiles heap only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import statistics
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

PROFILES: dict[str, dict[str, str]] = {
    # name: environment the candidate image reads (config::ProverConfig::from_env)
    "heap": {"MIDNIGHT_SPILL_PK": "0", "MIDNIGHT_SPILL_COSETS": "0", "MIDNIGHT_SPILL_FLOOR_K": "18"},
    "pk-mmap": {"MIDNIGHT_SPILL_PK": "1", "MIDNIGHT_SPILL_COSETS": "0", "MIDNIGHT_SPILL_FLOOR_K": "18"},
    "threshold": {"MIDNIGHT_SPILL_PK": "1", "MIDNIGHT_SPILL_COSETS": "1", "MIDNIGHT_SPILL_FLOOR_K": "18"},
    "forced-spill": {"MIDNIGHT_SPILL_PK": "1", "MIDNIGHT_SPILL_COSETS": "1", "MIDNIGHT_SPILL_FLOOR_K": "0"},
}


def sh(*args: str, check: bool = True, timeout: float | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(args), check=check, capture_output=True, text=True, timeout=timeout)


def docker_exec(name: str, *cmd: str) -> str | None:
    try:
        return sh("docker", "exec", name, *cmd, check=False, timeout=10).stdout
    except subprocess.TimeoutExpired:
        return None


def read_int(text: str | None) -> int | None:
    if text is None:
        return None
    text = text.strip()
    return int(text) if text.isdigit() else None


def cgroup_peak_and_events(name: str) -> dict[str, Any]:
    """cgroup v2 memory.peak and memory.events (oom / oom_kill counts)."""
    out: dict[str, Any] = {}
    out["cgroup_memory_peak_bytes"] = read_int(docker_exec(name, "cat", "/sys/fs/cgroup/memory.peak"))
    events = docker_exec(name, "cat", "/sys/fs/cgroup/memory.events") or ""
    for line in events.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit():
            out[f"memory_events_{parts[0]}"] = int(parts[1])
    return out


def wait_http(url: str, timeout_s: float) -> tuple[bool, float]:
    started = time.perf_counter()
    deadline = started + timeout_s
    while time.perf_counter() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2.0) as r:
                if 200 <= r.status < 300:
                    return True, time.perf_counter() - started
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.1)
    return False, time.perf_counter() - started


class Sampler(threading.Thread):
    """Samples `docker stats` and spill-directory size until stopped."""

    def __init__(self, name: str, spill_dir: Path | None, interval: float = 0.5) -> None:
        super().__init__(daemon=True)
        self.name, self.spill_dir, self.interval = name, spill_dir, interval
        self.stop = threading.Event()
        self.mem_max = 0
        self.cpu_max = 0.0
        self.spill_max = 0
        self.samples = 0

    @staticmethod
    def _bytes(s: str) -> int:
        s = s.strip().split("/")[0].strip()
        units = {"B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3, "kB": 1000, "MB": 1000**2, "GB": 1000**3}
        for u, m in sorted(units.items(), key=lambda kv: -len(kv[0])):
            if s.endswith(u):
                return int(float(s[: -len(u)]) * m)
        return 0

    def run(self) -> None:
        while not self.stop.wait(self.interval):
            try:
                r = sh("docker", "stats", "--no-stream", "--format", "{{json .}}", self.name, check=False, timeout=5)
                if r.stdout.strip():
                    d = json.loads(r.stdout.strip().splitlines()[-1])
                    self.mem_max = max(self.mem_max, self._bytes(d.get("MemUsage", "0B")))
                    self.cpu_max = max(self.cpu_max, float(d.get("CPUPerc", "0%").rstrip("%") or 0))
                    self.samples += 1
            except (subprocess.TimeoutExpired, ValueError, json.JSONDecodeError):
                pass
            if self.spill_dir is not None and self.spill_dir.exists():
                total = sum(p.stat().st_size for p in self.spill_dir.rglob("*") if p.is_file())
                self.spill_max = max(self.spill_max, total)


def post(url: str, body: bytes, timeout: float) -> tuple[int, bytes, float, str | None]:
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/octet-stream"}, method="POST")
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(), time.perf_counter() - started, None
    except urllib.error.HTTPError as e:
        return e.code, e.read(), time.perf_counter() - started, str(e)
    except (OSError, urllib.error.URLError) as e:
        return 0, b"", time.perf_counter() - started, str(e)


def verify(payload_gen: str, vk: Path, response: bytes, scratch: Path) -> bool | None:
    scratch.write_bytes(response)
    r = sh(payload_gen, "verify", "--vk", str(vk), "--proof", str(scratch), check=False, timeout=600)
    if r.returncode == 0 and "verified" in r.stdout:
        return True
    if "NOT VERIFIED" in r.stdout:
        return False
    return None  # malformed response / verifier error — recorded as such


def image_digest(image: str) -> str | None:
    r = sh("docker", "inspect", "--format", "{{.Id}}", image, check=False)
    return r.stdout.strip() or None


def run_cell(a: argparse.Namespace, k: int, profile: str) -> dict[str, Any]:
    payload_dir = Path(a.payload_dir)
    request = (payload_dir / f"k{k}-request.bin").read_bytes()
    vk = payload_dir / f"k{k}-vk.bin"
    name = f"mlg004-{a.label}-{profile}-k{k}-{int(time.time())}"
    run_dir = Path(a.work_dir) / name
    spill = run_dir / "spill"
    spill.mkdir(parents=True, exist_ok=True)
    port = a.port

    row: dict[str, Any] = {
        "type": "cell",
        "label": a.label,
        "image": a.image,
        "image_digest": image_digest(a.image),
        "profile": profile,
        "profile_env": PROFILES[profile],
        "k": k,
        "payload_sha256": hashlib.sha256(request).hexdigest(),
        "payload_bytes": len(request),
        "workers": a.workers,
        "job_capacity": a.job_capacity,
        "job_timeout_s": a.job_timeout,
        "memory_limit": a.memory or "unconstrained",
        "cold_mode": "cold-empty" if a.cold_empty else "cold-preseeded",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    env = {
        "PORT": str(port),
        "MIDNIGHT_PROOF_SERVER_NUM_WORKERS": str(a.workers),
        "MIDNIGHT_PROOF_SERVER_JOB_CAPACITY": str(a.job_capacity),
        "MIDNIGHT_PROOF_SERVER_JOB_TIMEOUT": str(a.job_timeout),
        "MIDNIGHT_SPILL_DIR": "/spill",
        "RUST_LOG": "info",
        **PROFILES[profile],
    }
    cmd = ["docker", "run", "-d", "--name", name, "-p", f"{port}:{port}", "-v", f"{spill}:/spill"]
    if not a.cold_empty:
        # Pre-seeded params: mount them and tell the server not to fetch the
        # published zswap/dust keys at start — the request carries its own
        # keys, and a network fetch inside "start-to-ready" would be measuring
        # the network. clap's boolean env flag wants `true`, not `1`.
        env["MIDNIGHT_PP"] = "/params"
        env["MIDNIGHT_PROOF_SERVER_NO_FETCH_PARAMS"] = "true"
        cmd += ["-v", f"{a.params_dir}:/params:ro"]
    if a.memory:
        cmd += ["--memory", a.memory, "--memory-swap", a.memory]
    if a.cpus:
        cmd += ["--cpus", str(a.cpus)]
    for kv in env.items():
        cmd += ["-e", "=".join(kv)]
    cmd += [a.image]

    t0 = time.perf_counter()
    started = sh(*cmd, check=False)
    if started.returncode != 0:
        row.update(outcome="container-start-failed", error=started.stderr.strip()[-500:])
        return row
    row["container_start_s"] = time.perf_counter() - t0

    sampler = Sampler(name, spill)
    sampler.start()
    try:
        ok, t_health = wait_http(f"http://127.0.0.1:{port}/health", a.ready_timeout)
        row["start_to_health_s"] = t_health if ok else None
        ok2, t_ready = wait_http(f"http://127.0.0.1:{port}/ready", a.ready_timeout)
        row["start_to_ready_s"] = (t_health + t_ready) if ok2 else None
        if not ok2:
            logs = sh("docker", "logs", "--tail", "40", name, check=False).stderr + sh("docker", "logs", "--tail", "40", name, check=False).stdout
            row.update(outcome="never-ready", logs_tail=logs[-1500:])
            return row

        url = f"http://127.0.0.1:{port}/prove"
        scratch = run_dir / "response.bin"

        # First proof after ready: the deploy/restart number.
        status, body, lat, err = post(url, request, a.request_timeout)
        row["first_proof_s"] = lat
        row["first_status"] = status
        if status != 200:
            row.update(outcome="first-proof-failed", error=(err or "")[:300], body_head=body[:200].decode("utf-8", "replace"))
            return row
        row["first_verified"] = verify(a.payload_gen, vk, body, scratch)
        row["first_response_bytes"] = len(body)

        # One unmeasured warm-up, then N warm samples.
        post(url, request, a.request_timeout)
        warm: list[float] = []
        warm_status: list[int] = []
        sampled_verified: bool | None = None
        for i in range(a.warm):
            status, body, lat, err = post(url, request, a.request_timeout)
            warm_status.append(status)
            if status == 200:
                warm.append(lat)
                if i == a.warm // 2:
                    sampled_verified = verify(a.payload_gen, vk, body, scratch)
        row["warm_n"] = len(warm)
        row["warm_failed"] = sum(1 for s in warm_status if s != 200)
        if warm:
            row["warm_median_s"] = statistics.median(warm)
            row["warm_min_s"] = min(warm)
            row["warm_max_s"] = max(warm)
            if len(warm) >= 2:
                row["warm_stdev_s"] = statistics.stdev(warm)
        row["warm_sampled_verified"] = sampled_verified

        outcome = "ok"
        if row["first_verified"] is not True or (a.warm and sampled_verified is not True):
            outcome = "verification-failed"
        if row["warm_failed"]:
            outcome = "warm-requests-failed"
        row["outcome"] = outcome
    finally:
        sampler.stop.set()
        sampler.join(timeout=5)
        row["peak_mem_bytes_docker_stats"] = sampler.mem_max
        row["peak_cpu_percent_docker_stats"] = sampler.cpu_max
        row["stats_samples"] = sampler.samples
        row["spill_high_water_bytes"] = sampler.spill_max
        row.update(cgroup_peak_and_events(name))
        inspect = sh("docker", "inspect", "--format", "{{.State.OOMKilled}} {{.State.ExitCode}} {{.State.Status}}", name, check=False).stdout.split()
        if len(inspect) == 3:
            row["oom_killed"] = inspect[0] == "true"
            row["container_status"] = inspect[2]
            if inspect[0] == "true":
                row["outcome"] = "oom-killed"
        logs = sh("docker", "logs", name, check=False)
        text = logs.stderr + logs.stdout
        # The arm that actually ran, from the server's own log lines.
        row["log_mentions_spill"] = ("spill" in text.lower())
        row["log_mentions_fallback"] = ("falling back to heap" in text)
        (run_dir / "container.log").write_text(text)
        sh("docker", "rm", "-f", name, check=False)
        if not a.keep_spill:
            shutil.rmtree(spill, ignore_errors=True)
    return row


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--image", required=True)
    p.add_argument("--label", required=True, help="baseline | candidate | …")
    p.add_argument("--payload-dir", required=True)
    p.add_argument("--params-dir", default=os.path.expanduser("~/.cache/midnight/zk-params"))
    p.add_argument("--payload-gen", default="target/debug/payload-gen")
    p.add_argument("--k", default="14", help="comma-separated")
    p.add_argument("--profiles", default="heap", help="comma-separated subset of " + ",".join(PROFILES))
    p.add_argument("--warm", type=int, default=5)
    p.add_argument("--workers", type=int, default=1)
    p.add_argument("--job-capacity", type=int, default=10)
    p.add_argument("--job-timeout", type=float, default=1800.0)
    p.add_argument("--memory", default=None, help="docker --memory limit, e.g. 6g; default unconstrained")
    p.add_argument("--cpus", type=float, default=None)
    p.add_argument("--port", type=int, default=6311)
    p.add_argument("--ready-timeout", type=float, default=900.0)
    p.add_argument("--request-timeout", type=float, default=1800.0)
    p.add_argument("--cold-empty", action="store_true", help="do not mount params; the server fetches them")
    p.add_argument("--keep-spill", action="store_true")
    p.add_argument("--work-dir", default="/tmp/mlg004/runs")
    p.add_argument("--out", required=True, help="JSONL, appended")
    a = p.parse_args()

    ks = [int(x) for x in a.k.split(",") if x]
    profiles = [x for x in a.profiles.split(",") if x]
    unknown = [x for x in profiles if x not in PROFILES]
    if unknown:
        print(f"unknown profiles: {unknown}", file=sys.stderr)
        return 2
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    failures = 0
    for k in ks:
        for profile in profiles:
            print(f"== {a.label} {profile} k={k}", flush=True)
            row = run_cell(a, k, profile)
            with open(a.out, "a", encoding="utf-8") as f:
                f.write(json.dumps(row, sort_keys=True) + "\n")
            print(f"   {row.get('outcome')} first={row.get('first_proof_s')} warm_median={row.get('warm_median_s')} "
                  f"peak={row.get('cgroup_memory_peak_bytes') or row.get('peak_mem_bytes_docker_stats')} spill={row.get('spill_high_water_bytes')}", flush=True)
            if row.get("outcome") != "ok":
                failures += 1
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
