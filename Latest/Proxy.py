#!/usr/bin/env python3
# proxy.py
# Secure OCPP 1.6 Proxy with attack detection & mitigation

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

HEARTBEAT_TIMEOUT = 30        # seconds (suppression detection)
FLOOD_LIMIT = 5              # messages
FLOOD_WINDOW = 2             # seconds

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
active_connections = {}   # <---- REQUIRED FOR SUPPRESSION MITIGATION

# ================= SECURITY UTILS =================

def verify_signature(payload, nonce, ts, signature):
    msg = f"{payload}{nonce}{ts}".encode()
    expected = hmac.new(SECRET_KEY, msg, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)

# ================= HEARTBEAT WATCHDOG =================

async def heartbeat_watchdog():
    while True:
        now = time.time()
        for cp_id, last_seen in list(last_message_time.items()):
            if now - last_seen > HEARTBEAT_TIMEOUT:
                logger.error(
                    "[SECURITY] Heartbeat SUPPRESSION detected for %s (%.1fs silent) – closing connection",
                    cp_id,
                    now - last_seen,
                )

                ws = active_connections.get(cp_id)
                if ws:
                    await ws.close(code=4001, reason="Heartbeat suppression detected")

                last_message_time.pop(cp_id, None)
                active_connections.pop(cp_id, None)

        await asyncio.sleep(5)

# ================= CLIENT HANDLER =================

async def handle_client(ws, *args):
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

            async def cp_to_cs():
                async for msg in ws:
                    now = time.time()
                    last_message_time[cp_id] = now

                    # -------- FLOOD DETECTION --------
                    q = message_times[cp_id]
                    q.append(now)
                    while q and now - q[0] > FLOOD_WINDOW:
                        q.popleft()

                    if len(q) > FLOOD_LIMIT:
                        logger.error("[SECURITY] Flooding detected from %s", cp_id)
                        await ws.close(code=4002, reason="Flood detected")
                        return

                    try:
                        data = json.loads(msg)
                    except Exception:
                        logger.error("[SECURITY] Invalid JSON")
                        await ws.close(code=4003, reason="Invalid JSON")
                        return

                    # -------- ENVELOPE CHECK --------
                    if isinstance(data, dict) and "payload" in data:
                        payload = data["payload"]
                        nonce = data["nonce"]
                        ts = data["timestamp"]
                        sig = data["signature"]

                        # Replay
                        if nonce in seen_nonces:
                            logger.error("[SECURITY] Replay detected (nonce reused)")
                            await ws.close(code=4004, reason="Replay detected")
                            return
                        seen_nonces.add(nonce)

                        # Tampering
                        if not verify_signature(payload, nonce, ts, sig):
                            logger.error("[SECURITY] Tampering detected (bad signature)")
                            await ws.close(code=4005, reason="Tampering detected")
                            return

                        inner = json.loads(payload)
                    else:
                        inner = data

                    # -------- REORDERING DETECTION --------
                    if isinstance(inner, list) and len(inner) >= 3:
                        action = inner[2]
                        prev = last_action.get(cp_id)

                        if prev:
                            try:
                                if EXPECTED_ORDER.index(action) < EXPECTED_ORDER.index(prev):
                                    logger.error(
                                        "[SECURITY] Message reordering detected: last=%s incoming=%s",
                                        prev,
                                        action,
                                    )
                            except ValueError:
                                pass

                        last_action[cp_id] = action

                    logger.info("[CP->CS] %s", inner)
                    await central_ws.send(msg)

            async def cs_to_cp():
                async for msg in central_ws:
                    logger.info("[CS->CP] %s", msg)
                    await ws.send(msg)

            await asyncio.gather(cp_to_cs(), cs_to_cp())

    except websockets.exceptions.ConnectionClosed:
        logger.info("Proxy: connection closed for %s", cp_id)

    finally:
        active_connections.pop(cp_id, None)
        last_message_time.pop(cp_id, None)

# ================= MAIN =================

async def main():
    logger.info("Proxy running on ws://%s:%s", PROXY_HOST, PROXY_PORT)

    server = await websockets.serve(
        handle_client,
        PROXY_HOST,
        PROXY_PORT,
        subprotocols=["ocpp1.6"]
    )

    asyncio.create_task(heartbeat_watchdog())
    await server.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())
