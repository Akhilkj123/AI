#!/usr/bin/env python3
# proxy.py
# OCPP 1.6 Security Proxy with Blocking + Performance Metrics

import asyncio
import websockets
import json
import logging
import time
import hmac
import hashlib
from collections import defaultdict, deque

# ================= CONFIG =================

PROXY_HOST = "0.0.0.0"
PROXY_PORT = 9090
CENTRAL_URI = "ws://localhost:9000"
SECRET_KEY = b"SuperSecretKey123"

HEARTBEAT_TIMEOUT = 30       # suppression detection (seconds)
FLOOD_LIMIT = 5
FLOOD_WINDOW = 2

EXPECTED_ORDER = [
    "BootNotification",
    "Heartbeat",
    "StartTransaction",
    "StopTransaction",
]

# ================= LOGGING =================

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("proxy")

# ================= STATE =================

seen_nonces = set()
last_action = {}
last_message_time = {}
message_times = defaultdict(deque)
active_connections = {}

metrics = {
    "total": 0,
    "forwarded": 0,
    "blocked": 0,
    "replay": 0,
    "tamper": 0,
    "reorder": 0,
    "flood": 0,
    "suppress": 0,
    "latencies": [],
}

# ================= SECURITY =================

def verify_signature(payload, nonce, ts, signature):
    msg = f"{payload}{nonce}{ts}".encode()
    expected = hmac.new(SECRET_KEY, msg, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)

# ================= METRICS =================

def print_metrics():
    if metrics["latencies"]:
        avg = sum(metrics["latencies"]) / len(metrics["latencies"])
        mn = min(metrics["latencies"])
        mx = max(metrics["latencies"])
    else:
        avg = mn = mx = 0.0

    logger.info("========== PERFORMANCE METRICS ==========")
    logger.info(
        "total=%d forwarded=%d blocked=%d | replay=%d tamper=%d reorder=%d flood=%d suppress=%d",
        metrics["total"],
        metrics["forwarded"],
        metrics["blocked"],
        metrics["replay"],
        metrics["tamper"],
        metrics["reorder"],
        metrics["flood"],
        metrics["suppress"],
    )
    logger.info(
        "latency: avg=%.2fms min=%.2fms max=%.2fms",
        avg, mn, mx
    )
    logger.info("========================================")

# ================= SUPPRESSION WATCHDOG =================

async def heartbeat_watchdog():
    while True:
        now = time.time()
        for cp_id, last_seen in list(last_message_time.items()):
            if now - last_seen > HEARTBEAT_TIMEOUT:
                logger.error(
                    "[SECURITY] Heartbeat SUPPRESSION detected for %s (%.1fs silent)",
                    cp_id,
                    now - last_seen,
                )
                metrics["blocked"] += 1
                metrics["suppress"] += 1

                ws = active_connections.get(cp_id)
                if ws:
                    await ws.close(code=4001, reason="Heartbeat suppression")

                last_message_time.pop(cp_id, None)
                active_connections.pop(cp_id, None)
                print_metrics()

        await asyncio.sleep(5)

# ================= CLIENT HANDLER =================

async def handle_client(ws):
    cp_id = "UNKNOWN"
    last_action[cp_id] = None
    last_message_time[cp_id] = time.time()
    active_connections[cp_id] = ws

    logger.info("Proxy: CP connected id=%s", cp_id)

    try:
        async with websockets.connect(
            CENTRAL_URI,
            subprotocols=["ocpp-envelope"]
        ) as central_ws:

            async for msg in ws:
                metrics["total"] += 1
                now = time.time()
                last_message_time[cp_id] = now

                # ---------- FLOOD ----------
                q = message_times[cp_id]
                q.append(now)
                while q and now - q[0] > FLOOD_WINDOW:
                    q.popleft()

                if len(q) > FLOOD_LIMIT:
                    logger.error("[SECURITY] Flood detected")
                    metrics["blocked"] += 1
                    metrics["flood"] += 1
                    await ws.close(code=4002, reason="Flood")
                    print_metrics()
                    return

                # ---------- PARSE ----------
                try:
                    data = json.loads(msg)
                except Exception:
                    logger.error("[SECURITY] Invalid JSON")
                    metrics["blocked"] += 1
                    print_metrics()
                    return

                # ---------- ENVELOPE ----------
                if isinstance(data, dict) and "payload" in data:
                    payload = data["payload"]
                    nonce = data["nonce"]
                    ts = data["timestamp"]
                    sig = data["signature"]

                    if nonce in seen_nonces:
                        logger.error("[SECURITY] Replay detected")
                        metrics["blocked"] += 1
                        metrics["replay"] += 1
                        await ws.close(code=4004, reason="Replay")
                        print_metrics()
                        return

                    if not verify_signature(payload, nonce, ts, sig):
                        logger.error("[SECURITY] Tampering detected")
                        metrics["blocked"] += 1
                        metrics["tamper"] += 1
                        await ws.close(code=4005, reason="Tampering")
                        print_metrics()
                        return

                    seen_nonces.add(nonce)
                    inner = json.loads(payload)
                else:
                    inner = data

                # ---------- REORDER ----------
                if isinstance(inner, list) and len(inner) >= 3:
                    action = inner[2]
                    prev = last_action.get(cp_id)

                    if prev and action in EXPECTED_ORDER and prev in EXPECTED_ORDER:
                        if EXPECTED_ORDER.index(action) < EXPECTED_ORDER.index(prev):
                            logger.error(
                                "[SECURITY] Reordering detected: %s -> %s",
                                prev, action
                            )
                            metrics["blocked"] += 1
                            metrics["reorder"] += 1
                            await ws.close(code=4006, reason="Reordering")
                            print_metrics()
                            return

                    last_action[cp_id] = action

                # ---------- FORWARD + LATENCY ----------
                start = time.time()
                await central_ws.send(msg)

                try:
                    response = await asyncio.wait_for(central_ws.recv(), timeout=2)
                    await ws.send(response)
                except asyncio.TimeoutError:
                    pass

                latency = (time.time() - start) * 1000
                metrics["latencies"].append(latency)
                metrics["forwarded"] += 1

                print_metrics()

    except websockets.exceptions.ConnectionClosed:
        logger.info("Proxy: connection closed")

    finally:
        active_connections.pop(cp_id, None)
        last_message_time.pop(cp_id, None)

# ================= MAIN =================

async def main():
    logger.info("Proxy running on ws://%s:%s", PROXY_HOST, PROXY_PORT)
    server = await websockets.serve(handle_client, PROXY_HOST, PROXY_PORT)
    asyncio.create_task(heartbeat_watchdog())
    await server.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())
