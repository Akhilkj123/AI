#!/usr/bin/env python3
# replay_direct_to_central.py
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
logger = logging.getLogger("replay_direct")

CENTRAL_URI = "ws://localhost:9000/CP-1-UUID"
SECRET_KEY = b"SuperSecretKey123"


def sign(payload, nonce, ts):
    msg = f"{payload}{nonce}{ts}".encode()
    return hmac.new(SECRET_KEY, msg, hashlib.sha256).hexdigest()


async def send_envelope(ws, envelope, label):
    logger.info("Sending %s", label)
    await ws.send(json.dumps(envelope))
    try:
        resp = await asyncio.wait_for(ws.recv(), timeout=3.0)
        logger.info("Central responded: %s", resp)
    except asyncio.TimeoutError:
        logger.info("No response (timeout)")
    except websockets.exceptions.ConnectionClosed:
        logger.info("Connection closed by central (replay detected)")


async def main():
    # Valid inner OCPP message
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

    # Fixed nonce → intentional replay
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

        logger.info("=== First send (should be ACCEPTED) ===")
        await send_envelope(ws, envelope, "FIRST MESSAGE")

        await asyncio.sleep(1)

        logger.info("=== Second send (REPLAY – should be REJECTED) ===")
        await send_envelope(ws, envelope, "REPLAY MESSAGE")


if __name__ == "__main__":
    asyncio.run(main())
