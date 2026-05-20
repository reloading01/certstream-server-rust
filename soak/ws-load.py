#!/usr/bin/env python3
"""
WS load generator. Spawns N concurrent WebSocket clients against a server,
each subscribing and consuming all messages until duration elapses.

Usage:
    python3 soak/ws-load.py --port 18081 --path / --clients 100 --duration 700
    python3 soak/ws-load.py --port 18082 --path /full-stream --clients 100 --duration 700
"""
import argparse, asyncio, sys, time
try:
    import websockets
except ImportError:
    print("install: pip3 install websockets", file=sys.stderr)
    sys.exit(2)


async def client(idx: int, uri: str, duration: float, counter: list[int]):
    deadline = time.monotonic() + duration
    try:
        async with websockets.connect(uri, ping_interval=20, ping_timeout=20, max_size=2**22) as ws:
            local = 0
            while time.monotonic() < deadline:
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=5.0)
                    local += 1
                    counter[0] += 1
                except asyncio.TimeoutError:
                    pass
    except Exception as e:
        print(f"[client {idx:03d}] disconnected: {e}", file=sys.stderr)


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=18081)
    ap.add_argument("--path", default="/")
    ap.add_argument("--clients", type=int, default=100)
    ap.add_argument("--duration", type=float, default=600)
    args = ap.parse_args()

    uri = f"ws://127.0.0.1:{args.port}{args.path}"
    counter = [0]
    start = time.monotonic()
    print(f"spawning {args.clients} clients → {uri} for {args.duration}s", flush=True)
    tasks = [
        asyncio.create_task(client(i, uri, args.duration, counter))
        for i in range(args.clients)
    ]
    await asyncio.gather(*tasks, return_exceptions=True)
    elapsed = time.monotonic() - start
    print(f"done: {counter[0]} msgs in {elapsed:.1f}s = {counter[0]/elapsed:.0f} msg/s aggregate", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
