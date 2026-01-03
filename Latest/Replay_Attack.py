#!/usr/bin/env python3
# replay_attack.py
# Replay attack THROUGH PROXY (correct architecture)

import asyncio
import websockets
import json
import logging
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("replay")

PROXY_URI = "ws://localhost:9090"
SUBPROTOCOL = "ocpp1.6"


async def main():
    # Normal OCPP BootNotification (no envelope here!)
    msg = [
        2,
        "CP-1-UUID",
        "BootNotification",
        {
            "chargePointModel": "DemoModel-1000",
            "chargePointVendor": "DemoVendor",
        },
    ]

    async with websockets.connect(PROXY_URI, subprotocols=[SUBPROTOCOL]) as ws:
        logger.info("=== Sending first message (should be ACCEPTED) ===")
        await ws.send(json.dumps(msg))

        try:
            resp = await ws.recv()
            logger.info("Proxy/Central response: %s", resp)
        except Exception:
            pass

        await asyncio.sleep(1)

        logger.info("=== Replaying SAME message ===")
        await ws.send(json.dumps(msg))

        try:
            await ws.recv()
        except websockets.exceptions.ConnectionClosed:
            logger.info("Connection closed by proxy (REPLAY detected)")


if __name__ == "__main__":
    asyncio.run(main())
                            
