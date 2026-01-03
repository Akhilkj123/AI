#!/usr/bin/env python3
# proxy.py
import asyncio
import json
import logging
import time
import hmac
import hashlib
import secrets
import os

import websockets

# === Config (match central SECRET_KEY) ===
PROXY_HOST = os.getenv("PROXY_HOST", "0.0.0.0")
PROXY_PORT = int(os.getenv("PROXY_PORT", "9090"))
SUBPROT_CP = "ocpp1.6"
SUBPROT_TO_CS = "ocpp-envelope"
CENTRAL_HOST = os.getenv("CENTRAL_HOST", "localhost")
CENTRAL_PORT = int(os.getenv("CENTRAL_PORT", "9000"))
SECRET_KEY = os.getenv("SECRET_KEY", "SuperSecretKey123").encode()
ALLOWED_SKEW_SECONDS = int(os.getenv("ALLOWED_SKEW_SECONDS", "60"))

# logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("proxy")

# --- Helpers (canonical JSON)
def canonicalize_payload(payload_str: str) -> str:
    try:
        obj = json.loads(payload_str)
        return json.dumps(obj, separators=(",", ":"), sort_keys=True)
    except Exception:
        return payload_str

def sign_payload(payload: str, nonce: str, timestamp: int) -> str:
    payload_canon = canonicalize_payload(payload)
    mac = hmac.new(SECRET_KEY, f"{payload_canon}{nonce}{timestamp}".encode(), hashlib.sha256)
    return mac.hexdigest()

def verify_envelope(envelope_json: str):
    obj = json.loads(envelope_json)
    for f in ("payload", "nonce", "timestamp", "signature", "envelope_version"):
        if f not in obj:
            raise ValueError(f"Missing {f} in envelope")
    payload = obj["payload"]
    nonce = obj["nonce"]
    ts = int(obj["timestamp"])
    sig = obj["signature"]

    now = int(time.time())
    if abs(now - ts) > ALLOWED_SKEW_SECONDS:
        raise ValueError("Timestamp skew too large")

    expected = sign_payload(payload, nonce, ts)
    if not hmac.compare_digest(expected, sig):
        raise ValueError("HMAC mismatch")
    return payload

async def relay_cp_to_cs(cp_ws, cs_ws, client_id):
    """
    Read raw messages from CP (OCPP text) -> wrap with canonical envelope -> forward to central
    """
    try:
        async for msg in cp_ws:
            logger.info("[CP->CS] %s", msg)
            # canonicalize payload for consistent HMAC
            payload_str = canonicalize_payload(msg)
            nonce = secrets.token_hex(16)
            ts = int(time.time())
            sig = sign_payload(payload_str, nonce, ts)
            envelope = {
                "envelope_version": "1.0",
                "nonce": nonce,
                "timestamp": ts,
                "signature": sig,
                "payload": payload_str,
            }
            await cs_ws.send(json.dumps(envelope))
    except websockets.exceptions.ConnectionClosedOK:
        logger.info("[CP->CS] CP closed connection normally")
    except Exception as e:
        logger.exception("[CP->CS] error: %s", e)

async def relay_cs_to_cp(cs_ws, cp_ws, client_id):
    """
    Read envelope messages from Central -> verify -> forward inner payload to CP.
    If verification fails, close both connections (block tampering).
    """
    try:
        async for wrapped in cs_ws:
            logger.info("[CS->CP] received envelope: %s", wrapped)
            try:
                inner_payload = verify_envelope(wrapped)
            except Exception as e:
                logger.error("[CS->CP] verification failed for client %s: %s", client_id, e)
                # Block tampered connection: close both sides.
                try:
                    await cs_ws.close()
                except Exception:
                    pass
                try:
                    await cp_ws.close()
                except Exception:
                    pass
                return
            await cp_ws.send(inner_payload)
    except websockets.exceptions.ConnectionClosedOK:
        logger.info("[CS->CP] central closed connection normally")
    except Exception as e:
        logger.exception("[CS->CP] error: %s", e)
        try:
            await cp_ws.close()
        except Exception:
            pass

# --- Handler (compat with different websockets versions) ---
async def handle_client(*args):
    # Unpack args
    if len(args) == 1:
        client_ws = args[0]
        path = getattr(client_ws, "path", None)
    elif len(args) >= 2:
        client_ws, path = args[0], args[1]
    else:
        raise RuntimeError("handle_client called with unexpected args")

    cp_id = (path or "").lstrip("/") or "UNKNOWN"
    logger.info("Proxy: CP connected id=%s remote=%s subprotocol=%s", cp_id, getattr(client_ws, "remote_address", None), getattr(client_ws, "subprotocol", None))

    central_uri = f"ws://{CENTRAL_HOST}:{CENTRAL_PORT}/{cp_id}"
    try:
        async with websockets.connect(central_uri, subprotocols=[SUBPROT_TO_CS]) as central_ws:
            logger.info("Proxy: connected to central %s (negotiated=%s)", central_uri, central_ws.subprotocol)
            t1 = asyncio.create_task(relay_cp_to_cs(client_ws, central_ws, cp_id))
            t2 = asyncio.create_task(relay_cs_to_cp(central_ws, client_ws, cp_id))
            done, pending = await asyncio.wait([t1, t2], return_when=asyncio.FIRST_EXCEPTION)
            for p in pending:
                p.cancel()
    except Exception as e:
        logger.exception("Proxy: connection to central failed: %s", e)
    finally:
        try:
            await client_ws.close()
        except Exception:
            pass
        logger.info("Proxy: closed for client %s", cp_id)

async def main():
    logger.info("Proxy starting on ws://%s:%s (accepts %s from CPs)", PROXY_HOST, PROXY_PORT, SUBPROT_CP)
    server = await websockets.serve(handle_client, PROXY_HOST, PROXY_PORT, subprotocols=[SUBPROT_CP])
    await server.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())
