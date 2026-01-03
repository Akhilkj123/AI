#!/usr/bin/env python3
# central_system.py
import asyncio
import logging
import json
import hashlib
import hmac
import time
import os
from collections import OrderedDict
from websockets.legacy.server import serve

# --- Configuration (use same SECRET_KEY in proxy) ---
SECRET_KEY = os.getenv("SECRET_KEY", "SuperSecretKey123").encode()
ALLOWED_SKEW_SECONDS = int(os.getenv("ALLOWED_SKEW_SECONDS", "60"))
NONCE_TTL_SECONDS = int(os.getenv("NONCE_TTL_SECONDS", "300"))
NONCE_CACHE_MAX = int(os.getenv("NONCE_CACHE_MAX", "10000"))

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("central")

# Nonce cache: OrderedDict to preserve insertion order for eviction
nonce_cache = OrderedDict()  # nonce -> first_seen_timestamp

# --- Helpers ---
def canonicalize_payload(payload_str: str) -> str:
    """
    Deterministic JSON serialization for HMAC input.
    If payload_str is JSON text, parse and re-dump with sorted keys and compact separators.
    Otherwise, return payload_str unchanged.
    """
    try:
        obj = json.loads(payload_str)
        return json.dumps(obj, separators=(",", ":"), sort_keys=True)
    except Exception:
        return payload_str

def sign_payload(payload: str, nonce: str, timestamp: int) -> str:
    payload_canon = canonicalize_payload(payload)
    mac = hmac.new(SECRET_KEY, f"{payload_canon}{nonce}{timestamp}".encode(), hashlib.sha256)
    return mac.hexdigest()

def prune_and_check_nonce(nonce: str, now: int):
    """
    Prune stale nonces and ensure the nonce is not seen before.
    Raises ValueError on replay.
    """
    # Remove stale entries (older than TTL)
    cutoff = now - NONCE_TTL_SECONDS
    stale = [n for n, t in nonce_cache.items() if t < cutoff]
    for n in stale:
        nonce_cache.pop(n, None)

    # Enforce size limit
    while len(nonce_cache) > NONCE_CACHE_MAX:
        nonce_cache.popitem(last=False)

    # Check replay
    if nonce in nonce_cache:
        raise ValueError("Replay detected (nonce seen before)")
    nonce_cache[nonce] = now

def verify_envelope(envelope: dict, path: str = "unknown"):
    """
    Validate envelope fields, timestamp skew, nonce replay, and HMAC.
    Returns the inner payload string if valid; raises ValueError on failure.
    """
    for field in ("payload", "nonce", "timestamp", "signature", "envelope_version"):
        if field not in envelope:
            raise ValueError(f"Missing envelope field: {field}")

    payload = envelope["payload"]
    nonce = envelope["nonce"]
    try:
        timestamp = int(envelope["timestamp"])
    except Exception:
        raise ValueError("Invalid timestamp format")

    signature = envelope["signature"]
    now = int(time.time())

    # Timestamp freshness
    if abs(now - timestamp) > ALLOWED_SKEW_SECONDS:
        raise ValueError(f"Timestamp skew too large: now={now} ts={timestamp}")

    # Nonce replay check (prune stale & check)
    prune_and_check_nonce(nonce, now)

    # HMAC verification (use canonicalized payload)
    expected = sign_payload(payload, nonce, timestamp)
    if not hmac.compare_digest(expected, signature):
        raise ValueError("HMAC mismatch (tampered payload or wrong key)")

    return payload  # still a JSON string representation of OCPP message

# --- OCPP processing ---
async def process_unwrapped_message(websocket, message):
    """
    message: Python object (parsed JSON) representing the inner OCPP list
    """
    try:
        if not isinstance(message, list) or len(message) < 3:
            raise ValueError("Invalid OCPP message format")

        # OCPP shorthand: [messageTypeId, uniqueId, action, payload?]
        message_type = message[0]
        unique_id = message[1] if len(message) > 1 else "unknown"
        action = message[2] if len(message) > 2 else "unknown"
        payload = message[3] if len(message) > 3 else {}

        logger.info(f"Central: Received action={action} unique_id={unique_id} vendor={payload.get('chargePointVendor')} model={payload.get('chargePointModel')}")

        # Respond to BootNotification
        if action == "BootNotification":
            response_inner = [
                3,  # CALLRESULT
                unique_id,
                {
                    "currentTime": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
                    "interval": 10,
                    "status": "Accepted"
                }
            ]
            # Wrap response into envelope before sending
            payload_str = json.dumps(response_inner, separators=(",", ":"), sort_keys=True)
            nonce = hashlib.sha256(f"{unique_id}{time.time()}".encode()).hexdigest()[:32]
            ts = int(time.time())
            signature = sign_payload(payload_str, nonce, ts)
            envelope = {
                "envelope_version": "1.0",
                "nonce": nonce,
                "timestamp": ts,
                "signature": signature,
                "payload": payload_str
            }
            await websocket.send(json.dumps(envelope))
            logger.info(f"Central: BootNotification CALLRESULT wrapped and sent for {unique_id}")

    except Exception as e:
        logger.error(f"Central processing error: {e}")
        try:
            await websocket.close()
        except Exception:
            pass

async def process_message(websocket, message, path):
    """
    Entry point for incoming messages.
    Accepts envelope JSON (from proxy) and raw OCPP (legacy) gracefully.
    """
    try:
        if isinstance(message, str):
            # Try parse JSON; if envelope, verify and unwrap
            try:
                obj = json.loads(message)
                if isinstance(obj, dict) and obj.get("envelope_version"):
                    try:
                        payload_str = verify_envelope(obj, path)
                    except ValueError as ve:
                        logger.warning(f"Envelope verification failed for path={path} nonce={obj.get('nonce')} : {ve}")
                        # On verification failure, close connection to signal rejection
                        try:
                            await websocket.close()
                        except Exception:
                            pass
                        return
                    # parse inner payload (OCPP) and process
                    try:
                        inner = json.loads(payload_str)
                    except Exception:
                        logger.error("Central: inner payload not JSON; closing")
                        try:
                            await websocket.close()
                        except Exception:
                            pass
                        return
                    await process_unwrapped_message(websocket, inner)
                    return
            except json.JSONDecodeError:
                # not JSON - fall through to legacy handling
                pass

        # Legacy raw OCPP handling (if any)
        try:
            inner = json.loads(message)
            await process_unwrapped_message(websocket, inner)
        except Exception:
            logger.error("Central: received unrecognized/non-json message; closing")
            try:
                await websocket.close()
            except Exception:
                pass

    except Exception as e:
        logger.error(f"Central: error processing message: {e}")
        try:
            await websocket.close()
        except Exception:
            pass

async def handle_charge_point(websocket, path):
    logger.info(f"Central: new connection path={path} subprotocol={websocket.subprotocol}")
    try:
        async for message in websocket:
            await process_message(websocket, message, path)
    except Exception as e:
        logger.error(f"Central: connection closed with exception: {e}")

async def main():
    async with serve(handle_charge_point, "0.0.0.0", 9000, subprotocols=["ocpp-envelope"]):
        logger.info("Central system listening on ws://0.0.0.0:9000 (ocpp-envelope)")
        await asyncio.Future()  # run forever

if __name__ == "__main__":
    asyncio.run(main())
                                     
