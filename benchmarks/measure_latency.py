#!/usr/bin/env python3
"""Connect to a certstream-server WebSocket endpoint and measure broadcast
latency as (arrival_time - data.seen) per message. Emits a JSON summary
with p50/p95/p99 (and full sample distribution).

"Broadcast latency" here is the wall-clock gap between the server marking
a cert as seen (set immediately after dedup + cache push, before the JSON
serialize-and-broadcast call) and the client receiving the resulting
WebSocket frame. On localhost it measures the full serialize → tx send
queue → kernel loopback → client recv → JSON parse pipeline. Over a real
network, add the RTT.

Outliers > 30 s and negative values (clock skew) are dropped, with a count
in the summary so wild measurements don't quietly skew the percentiles.

Early-exit safe: SIGINT/SIGTERM stops sampling, writes the summary, and
returns 0 with whatever was collected.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import signal
import statistics
import sys
import time
from typing import Optional

try:
    import websockets
except ImportError:
    sys.stderr.write(
        "error: 'websockets' python module not installed.\n"
        "  install: python3 -m pip install --user websockets\n"
    )
    sys.exit(1)


SAMPLES: list[float] = []
DROPPED_NEGATIVE = 0
DROPPED_HUGE = 0
DROPPED_NO_SEEN = 0
STOP = asyncio.Event()


async def sample_loop(url: str, duration: float) -> None:
    """Sample for up to `duration` seconds or until STOP fires."""
    global DROPPED_NEGATIVE, DROPPED_HUGE, DROPPED_NO_SEEN
    deadline = time.monotonic() + duration
    while not STOP.is_set() and time.monotonic() < deadline:
        try:
            async with websockets.connect(
                url,
                max_size=8 * 1024 * 1024,
                open_timeout=10,
                ping_interval=20,
                ping_timeout=20,
            ) as ws:
                while not STOP.is_set() and time.monotonic() < deadline:
                    try:
                        msg = await asyncio.wait_for(ws.recv(), timeout=5.0)
                    except asyncio.TimeoutError:
                        continue
                    arrival = time.time()
                    try:
                        obj = json.loads(msg)
                    except json.JSONDecodeError:
                        continue
                    seen = _extract_seen(obj)
                    if seen is None:
                        DROPPED_NO_SEEN += 1
                        continue
                    latency_ms = (arrival - seen) * 1000.0
                    if latency_ms < -10.0:
                        DROPPED_NEGATIVE += 1
                        continue
                    if latency_ms > 30_000.0:
                        DROPPED_HUGE += 1
                        continue
                    SAMPLES.append(latency_ms)
        except asyncio.CancelledError:
            return
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"connection error: {exc!r}; retry in 2s\n")
            try:
                await asyncio.wait_for(STOP.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                continue


def _extract_seen(obj: dict) -> Optional[float]:
    """Pull `data.seen` (float seconds since epoch) from any of the three
    output variants. domains_only has no `seen` field — those frames are
    silently skipped."""
    data = obj.get("data")
    if isinstance(data, dict):
        seen = data.get("seen")
        if isinstance(seen, (int, float)):
            return float(seen)
    return None


def _pct(sorted_samples: list[float], frac: float) -> Optional[float]:
    n = len(sorted_samples)
    if n == 0:
        return None
    idx = min(int(n * frac), n - 1)
    return sorted_samples[idx]


def summarize(out_path: str, started_iso: str, duration: float, url: str) -> None:
    samples = sorted(SAMPLES)
    n = len(samples)
    summary = {
        "kind": "latency",
        "url": url,
        "started_at": started_iso,
        "duration_seconds": duration,
        "samples": n,
        "dropped_negative": DROPPED_NEGATIVE,
        "dropped_above_30s": DROPPED_HUGE,
        "dropped_no_seen_field": DROPPED_NO_SEEN,
        "min_ms": round(samples[0], 3) if n else None,
        "max_ms": round(samples[-1], 3) if n else None,
        "mean_ms": round(statistics.fmean(samples), 3) if n else None,
        "p50_ms": round(_pct(samples, 0.50), 3) if n else None,
        "p95_ms": round(_pct(samples, 0.95), 3) if n >= 20 else None,
        "p99_ms": round(_pct(samples, 0.99), 3) if n >= 100 else None,
    }
    out = json.dumps(summary, indent=2)
    if out_path == "-":
        print(out)
    else:
        with open(out_path, "w") as f:
            f.write(out)
            f.write("\n")
        sys.stderr.write(f"wrote {out_path}\n")


async def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--url", required=True, help="ws:// URL")
    p.add_argument("--duration", type=float, default=1800.0, help="seconds (default 1800)")
    p.add_argument("--output", default="-", help="output path or '-' for stdout")
    args = p.parse_args()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, STOP.set)

    started_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    sys.stderr.write(
        f"measure_latency: url={args.url} duration={args.duration}s\n"
    )
    try:
        await sample_loop(args.url, args.duration)
    finally:
        summarize(args.output, started_iso, args.duration, args.url)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        sys.exit(0)
