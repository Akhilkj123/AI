#!/usr/bin/env python3
# replay_attack.py
# Demonstrates a replay attack by resending the SAME valid envelope twice
# Requires central system running on localhost:9000

import asyncio
import websockets
import json
import logging
import time
import hmac
import hashlib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("replay")

CENTRAL_URI = "ws://localhost:9000/CP-1-UUID"
SECRET_KEY = b"SuperSecretKey123"


def sign(payload, nonce, ts):
    msg = f"{payload}{nonce}{ts}".encode()
    return hmac.new(SECRET_KEY, msg, hashlib.sha256).hexdigest()


async def main():
    # Valid inner OCPP BootNotification
    inner_msg = [
        2,
        "CP-1-UUID",
        "BootNotification",
        {
            "chargePointModel": "DemoModel-1000",
            "chargePointVendor": "DemoVendor",
        },
    ]

    # Canonical payload
    payload = json.dumps(inner_msg, separators=(",", ":"), sort_keys=True)

    # FIXED nonce → intentional replay
    nonce = "REPLAY_NONCE_1234567890"
    ts = int(time.time())
    sig = sign(payload, nonce, ts)

    envelope = {
        "envelope_version": "1.0",
        "payload": payload,
        "nonce": nonce,
        "timestamp": ts,
        "signature": sig,
    }

    async with websockets.connect(
        CENTRAL_URI, subprotocols=["ocpp-envelope"]
    ) as ws:
        logger.info("=== Sending first message (should be ACCEPTED) ===")
        await ws.send(json.dumps(envelope))
        try:
            resp = await ws.recv()
            logger.info("Central response: %s", resp)
        except Exception:
            pass

        await asyncio.sleep(1)

        logger.info("=== Sending SAME message again (REPLAY) ===")
        await ws.send(json.dumps(envelope))

        try:
            await ws.recv()
        except Exception:
            logger.info("Central closed connection (replay detected)")

if __name__ == "__main__":
    asyncio.run(main())
