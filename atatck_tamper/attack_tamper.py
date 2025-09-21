import asyncio
import websockets
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("attack_tamper")

PROXY_URI = "ws://localhost:9090"

# Original (valid) BootNotification payload
original_payload = [
    2,
    "CP-1-UUID",
    "BootNotification",
    {
        "chargePointModel": "DemoModel-1000",
        "chargePointVendor": "DemoVendor"
    }
]

# Tampered payload (e.g., modified model/vendor)
tampered_payload = [
    2,
    "CP-1-UUID",
    "BootNotification",
    {
        "chargePointModel": "HackedModel-999",
        "chargePointVendor": "EvilVendor"
    }
]

async def send_payload(ws, payload, label="Payload"):
    logger.info(f"Sending {label}")
    await ws.send(json.dumps(payload))
    try:
        response = await ws.recv()
        logger.info(f"Received response for {label}: {response}")
    except websockets.exceptions.ConnectionClosedError as e:
        logger.error(f"Connection closed while sending {label}: {e}")

async def main():
    async with websockets.connect(PROXY_URI, subprotocols=["ocpp1.6"]) as ws:
        # Send valid payload
        await send_payload(ws, original_payload, "original payload")

        # Send tampered payload
        await send_payload(ws, tampered_payload, "tampered payload")

if __name__ == "__main__":
    asyncio.run(main())
