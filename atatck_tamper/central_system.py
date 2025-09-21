import asyncio
import logging
import json
import hashlib
import hmac
import time
from websockets.legacy.server import serve

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("central")

# Replay attack protection
seen_payloads = {}  # payload hash -> timestamp

# HMAC secret key for tamper detection
HMAC_KEY = b"supersecretkey"

# Function to compute HMAC
def compute_hmac(payload: str) -> str:
    return hmac.new(HMAC_KEY, payload.encode(), hashlib.sha256).hexdigest()

# Function to verify replay
def is_replay(payload_hash: str) -> bool:
    if payload_hash in seen_payloads:
        return True
    seen_payloads[payload_hash] = time.time()
    return False

# Function to process incoming message
async def process_message(websocket, message):
    try:
        # If message is an envelope, unwrap it
        if isinstance(message, str):
            try:
                msg_dict = json.loads(message)
                if "envelope_version" in msg_dict:
                    payload_str = msg_dict.get("payload")
                    payload_hash = hashlib.sha256(payload_str.encode()).hexdigest()

                    # Replay detection
                    if is_replay(payload_hash):
                        logger.warning(f"Envelope replay detected for hash {payload_hash}")
                        raise Exception("Replay detected")

                    # HMAC verification
                    signature = msg_dict.get("signature")
                    computed_hmac = compute_hmac(payload_str)
                    if signature != computed_hmac:
                        logger.warning("Tampered envelope detected")
                        raise Exception("Tampered payload")

                    # Replace message with unwrapped payload
                    message = json.loads(payload_str)
            except Exception as e:
                logger.error(f"Error unwrapping envelope: {e}")

        # Expecting OCPP message as list: [messageTypeId, uniqueId, action, payload]
        if not isinstance(message, list):
            raise Exception(f"Invalid OCPP message format: {type(message)}")

        message_type, unique_id, action, payload = message
        logger.info(f"Central: {action} from {payload.get('chargePointModel')} vendor={payload.get('chargePointVendor')}")

        # Respond to BootNotification
        if action == "BootNotification":
            response = [
                3,  # CALLRESULT
                unique_id,
                {
                    "currentTime": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
                    "interval": 10,
                    "status": "Accepted"
                }
            ]
            await websocket.send(json.dumps(response))
            logger.info(f"Central: BootNotification response sent to {unique_id}")

    except Exception as e:
        logger.error(f"Central: error processing message: {e}")
        await websocket.close()

# WebSocket handler
async def handle_charge_point(websocket, path):
    logger.info(f"Central: new connection path={path} subprotocol={websocket.subprotocol}")
    try:
        async for message in websocket:
            await process_message(websocket, message)
    except Exception as e:
        logger.error(f"Central: connection closed with exception: {e}")

# Main entry point
async def main():
    async with serve(handle_charge_point, "0.0.0.0", 9000, subprotocols=["ocpp-envelope"]):
        logger.info("Central system listening on ws://0.0.0.0:9000 (ocpp-envelope)")
        await asyncio.Future()  # run forever

if __name__ == "__main__":
    asyncio.run(main())
