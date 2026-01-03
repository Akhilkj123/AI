#!/usr/bin/env python3
import asyncio
import websockets
import json
import logging
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("attacker")

PROXY_URI = "ws://localhost:9090/ATTACKER-CP"

# Legitimate OCPP BootNotification
boot_notification = [
    2,
    "1",
    "BootNotification",
    {
        "chargePointModel": "EvilModel-X",
        "chargePointVendor": "EvilVendor",
    },
]

# Illegally reordered StopTransaction
stop_transaction = [
    2,
    "2",
    "StopTransaction",
    {
        "transactionId": 999,
        "meterStop": 12345,
        "timestamp": "2026-01-01T10:00:00Z",
    },
]


async def main():
    async with websockets.connect(
        PROXY_URI, subprotocols=["ocpp1.6"]
    ) as ws:
        logger.info("[ATTACK] Sending BootNotification")
        await ws.send(json.dumps(boot_notification))

        # Small delay to mimic real network timing
        await asyncio.sleep(0.5)

        logger.info("[ATTACK] Sending StopTransaction (REORDERED)")
        await ws.send(json.dumps(stop_transaction))

        # Try receiving response (should fail / connection closed)
        try:
            resp = await ws.recv()
            logger.info("[ATTACK] Received response: %s", resp)
        except Exception as e:
            logger.info("[ATTACK] Connection closed by proxy: %s", e)


if __name__ == "__main__":
    asyncio.run(main())
