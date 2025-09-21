#!/usr/bin/env python3
# attack_replay.py
import asyncio
import websockets
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("attack_replay")

PROXY_URI = "ws://localhost:9090/CP-1-UUID"
SUBPROT = ["ocpp1.6"]

# A simple raw OCPP BootNotification message (same as the CP sends)
payload = json.dumps([2, "CP-1-UUID", "BootNotification", {"chargePointModel": "DemoModel-1000", "chargePointVendor": "DemoVendor"}])

async def main():
    async with websockets.connect(PROXY_URI, subprotocols=SUBPROT) as ws:
        # send the same payload twice (simulate replay from attacker or buggy client)
        logger.info("Sending payload (1/2)")
        await ws.send(payload)
        # small pause
        await asyncio.sleep(0.5)
        logger.info("Sending payload (2/2) - replay")
        await ws.send(payload)

        # Read responses (if any)
        try:
            while True:
                msg = await asyncio.wait_for(ws.recv(), timeout=2)
                logger.info("Received: %s", msg)
        except Exception:
            logger.info("Done receiving / connection idle")

if __name__ == "__main__":
    asyncio.run(main())
