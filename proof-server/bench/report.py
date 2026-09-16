#!/usr/bin/env python3
"""Render MLG-004 results (container_matrix.py JSONL + throughput.py summaries)
as Markdown tables, with the host load that was sampled alongside each cell.

    python3 proof-server/bench/report.py --cells results.jsonl \
        --bursts burst-summaries.jsonl --hostload hostload.log > report.md

Every row is printed, failures included; nothing is averaged across cells.
Cells that ran while the sampled host load exceeded --quiet-load are marked,
because a latency measured on a loaded host is not the image's number.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def load_hostload(path: Path | None) -> list[tuple[datetime, float]]:
    """`<iso-utc> <1m> <5m> <15m> | <context>` lines → (time, 1-minute load)."""
    if path is None or not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            t = datetime.strptime(parts[0], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            out.append((t, float(parts[1].rstrip(","))))
        except ValueError:
            continue
    return out


def load_during(samples: list[tuple[datetime, float]], started: str | None, span_s: float) -> str:
    if not samples or not started:
        return "—"
    t0 = datetime.strptime(started, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    window = [l for t, l in samples if 0 <= (t - t0).total_seconds() <= max(span_s, 30) + 30]
    if not window:
        return "—"
    return f"{min(window):.0f}–{max(window):.0f}"


def s(v: object, nd: int = 2) -> str:
    if v is None:
        return "—"
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, float):
        return f"{v:.{nd}f}"
    return str(v)


def mib(v: object) -> str:
    return "—" if not isinstance(v, (int, float)) or v == 0 else f"{v / 2**20:,.0f}"


def cell_span(r: dict) -> float:
    total = (r.get("start_to_ready_s") or 0) + (r.get("first_proof_s") or 0)
    if r.get("warm_n") and r.get("warm_median_s"):
        total += (r["warm_n"] + 1) * r["warm_median_s"]
    return total


def render_cells(rows: list[dict], samples, quiet_load: float) -> str:
    rows = [r for r in rows if r.get("type") == "cell" and r.get("label") != "smoke"]
    head = ("| image | profile | spill backing | k | mode | outcome | start→ready s | first proof s | verified | "
            "warm median s (n) | warm min–max s | peak MiB (docker stats) | spill high-water MiB | OOM | host load 1m |")
    sep = "|" + "---|" * (head.count("|") - 1)
    out = [head, sep]
    for r in rows:
        load = load_during(samples, r.get("started_at"), cell_span(r))
        loaded = ""
        try:
            if load != "—" and float(load.split("–")[-1]) > quiet_load:
                loaded = " ⚠"
        except ValueError:
            pass
        warm = "—"
        if r.get("warm_n"):
            warm = f"{s(r.get('warm_median_s'), 3)} ({r['warm_n']})"
        rng = "—"
        if r.get("warm_min_s") is not None:
            rng = f"{s(r.get('warm_min_s'), 3)}–{s(r.get('warm_max_s'), 3)}"
        verified = r.get("first_verified")
        if r.get("warm_sampled_verified") is not None:
            verified = f"{s(verified)} / warm {s(r.get('warm_sampled_verified'))}"
        outcome = r.get("outcome", "?")
        if r.get("error") and outcome != "ok":
            outcome += f" ({str(r.get('body_head') or r.get('error'))[:60]})"
        out.append(
            f"| {r.get('label')} | {r.get('profile')} | {r.get('spill_backing', 'bind-mount')} | {r.get('k')} | "
            f"{r.get('cold_mode', '')} | {outcome} | {s(r.get('start_to_ready_s'), 3)} | {s(r.get('first_proof_s'))} | "
            f"{s(verified)} | {warm} | {rng} | {mib(r.get('peak_mem_bytes_docker_stats'))} | "
            f"{mib(r.get('spill_high_water_bytes'))} | {s(r.get('oom_killed'))} | {load}{loaded} |"
        )
    return "\n".join(out)


def render_bursts(rows: list[dict]) -> str:
    rows = [r for r in rows if r.get("type") == "summary"]
    if not rows:
        return "_no burst summaries_"
    head = "| run | requests | failed | mean s | p50 s | p95 s | p99 s | makespan s | req/s | max processing | max pending |"
    out = [head, "|" + "---|" * (head.count("|") - 1)]
    for r in rows:
        out.append(
            f"| {r.get('label')} | {r.get('requests')} | {r.get('failed')} | {s(r.get('latency_mean_s'))} | "
            f"{s(r.get('latency_p50_s'))} | {s(r.get('latency_p95_s'))} | {s(r.get('latency_p99_s'))} | "
            f"{s(r.get('makespan_s'))} | {s(r.get('throughput_requests_s'), 3)} | {r.get('max_jobs_processing')} | "
            f"{r.get('max_jobs_pending')} |"
        )
    return "\n".join(out)


def render_images(rows: list[dict]) -> str:
    seen: dict[str, str] = {}
    for r in rows:
        if r.get("type") == "cell" and r.get("image") and r.get("image_digest"):
            seen.setdefault(r["image"], r["image_digest"])
    return "\n".join(f"- `{img}` — `{dig}`" for img, dig in seen.items()) or "_none_"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--cells", required=True, type=Path)
    p.add_argument("--bursts", type=Path)
    p.add_argument("--hostload", type=Path)
    p.add_argument("--quiet-load", type=float, default=12.0, help="1-minute load above which a cell is flagged")
    a = p.parse_args()
    cells = load_jsonl(a.cells)
    bursts = load_jsonl(a.bursts) if a.bursts else []
    samples = load_hostload(a.hostload)
    print("## Images\n")
    print(render_images(cells))
    print("\n## Cells (one fresh container each; every row kept)\n")
    print(render_cells(cells, samples, a.quiet_load))
    print(f"\n⚠ = sampled 1-minute host load above {a.quiet_load:.0f} during the cell; the latency is not the image's.")
    print("\n## Bursts (k=14, heap, simultaneous clients)\n")
    print(render_bursts(bursts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
