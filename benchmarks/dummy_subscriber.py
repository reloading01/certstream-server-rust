#!/usr/bin/env python3
"""Open N concurrent WebSocket connections to a certstream-server endpoint
and drain messages. Used by the comparison harness to simulate broadcast
fanout pressure (--mode loaded). Reconnects on failure so a transient
disconnect during a long run doesn't drop our load below the target.

Output: status lines to stderr only (so this can be piped or backgrounded
without polluting other consumers). Quiet by default — pass --verbose for
per-connection events.
"""
from __future__ import annotations

import argparse
import asyncio
import signal
import sys
import time

try:
    import websockets
except ImportError:
    sys.stderr.write(
        "error: 'websockets' python module not installed.\n"
        "  install: python3 -m pip install --user websockets\n"
    )
    sys.exit(1)


STOP = asyncio.Event()


async def drain(url: str, idx: int, verbose: bool) -> None:
    """Connect, drain, reconnect-on-error. Runs until STOP is set."""
    while not STOP.is_set():
        try:
            async with websockets.connect(
                url,
                max_size=8 * 1024 * 1024,
                open_timeout=10,
                ping_interval=20,
                ping_timeout=20,
            ) as ws:
                if verbose:
                    sys.stderr.write(f"sub#{idx:02d}: connected\n")
                async for _msg in ws:
                    if STOP.is_set():
                        break
        except asyncio.CancelledError:
            return
        except Exception as exc:  # noqa: BLE001 — reconnect on anything
            if verbose:
                sys.stderr.write(f"sub#{idx:02d}: {exc!r}; reconnect in 2s\n")
            try:
                await asyncio.wait_for(STOP.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                continue


async def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--url", required=True, help="ws:// URL (e.g. ws://localhost:18080/full-stream)")
    p.add_argument("--count", type=int, default=10, help="concurrent subscribers (default 10)")
    p.add_argument("--verbose", action="store_true", help="log per-connection events")
    args = p.parse_args()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, STOP.set)

    started = time.monotonic()
    sys.stderr.write(f"dummy_subscriber: {args.count} subs -> {args.url}\n")
    tasks = [
        asyncio.create_task(drain(args.url, i, args.verbose))
        for i in range(args.count)
    ]
    try:
        await STOP.wait()
    finally:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    elapsed = time.monotonic() - started
    sys.stderr.write(f"dummy_subscriber: stopped after {elapsed:.1f}s\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        sys.exit(0)
