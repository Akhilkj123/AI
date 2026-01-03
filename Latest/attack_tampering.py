#!/usr/bin/env python3
# attack_tamper.py
# Tampering attack against proxy

import asyncio
import websockets
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("tamper")

PROXY_URI = "ws://localhost:9090"
SUBPROTOCOL = "ocpp1.6"


async def main():
    legit_msg = [
        2,
        "1",
        "BootNotification",
        {
            "chargePointModel": "LegitModel",
            "chargePointVendor": "LegitVendor",
        },
    ]

    tampered_msg = [
        2,
        "1",
        "BootNotification",
        {
            "chargePointModel": "HackedModel",
            "chargePointVendor": "LegitVendor",
        },
    ]

    async with websockets.connect(PROXY_URI, subprotocols=[SUBPROTOCOL]) as ws:
        logger.info("=== Sending legitimate message ===")
        await ws.send(json.dumps(legit_msg))
        await ws.recv()

        logger.info("=== Sending tampered message ===")
        await ws.send(json.dumps(tampered_msg))

        try:
            await ws.recv()
        except websockets.exceptions.ConnectionClosed:
            logger.info("Connection closed by proxy (TAMPERING detected)")


if __name__ == "__main__":
    asyncio.run(main())
