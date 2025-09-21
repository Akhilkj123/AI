# proxy.py
#!/usr/bin/env python3
import asyncio
import json
import logging
import time
import hmac
import hashlib
import secrets

import websockets

# === Config ===
PROXY_HOST = "0.0.0.0"
PROXY_PORT = 9090
SUBPROT_CP = "ocpp1.6"         # proxy accepts CPs as ocpp1.6
SUBPROT_TO_CS = "ocpp-envelope"  # proxy connects to Central with this subprotocol
CENTRAL_HOST = "localhost"
CENTRAL_PORT = 9000
SECRET_KEY = b"SuperSecretKey123"  # MUST match central's key
ALLOWED_SKEW_SECONDS = 60

# logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("proxy")


def sign_payload(payload: str, nonce: str, timestamp: int) -> str:
    mac = hmac.new(SECRET_KEY, f"{payload}{nonce}{timestamp}".encode(), hashlib.sha256)
    return mac.hexdigest()


def verify_payload(payload: str, nonce: str, timestamp: int, signature: str):
    expected = sign_payload(payload, nonce, timestamp)
    if not hmac.compare_digest(expected, signature):
        raise ValueError("HMAC mismatch")
    if abs(time.time() - float(timestamp)) > ALLOWED_SKEW_SECONDS:
        raise ValueError("Timestamp skew")


async def relay_cp_to_cs(cp_ws, cs_ws, client_id):
    """
    Read raw messages from CP (OCPP text) -> wrap with envelope -> forward to central
    """
    try:
        async for msg in cp_ws:
            logger.info("[CP->CS] %s", msg)
            nonce = secrets.token_hex(16)
            ts = int(time.time())
            sig = sign_payload(msg, nonce, ts)
            envelope = {
                "envelope_version": "1.0",
                "nonce": nonce,
                "timestamp": ts,
                "signature": sig,
                "payload": msg,
            }
            await cs_ws.send(json.dumps(envelope))
    except websockets.exceptions.ConnectionClosedOK:
        logger.info("[CP->CS] CP closed connection normally")
    except Exception as e:
        logger.exception("[CP->CS] error: %s", e)


async def relay_cs_to_cp(cs_ws, cp_ws, client_id):
    """
    Read envelope messages from Central -> verify -> forward inner payload to CP
    """
    try:
        async for wrapped in cs_ws:
            logger.info("[CS->CP] received envelope: %s", wrapped)
            try:
                obj = json.loads(wrapped)
                payload = obj.get("payload")
                nonce = obj.get("nonce", "")
                ts = obj.get("timestamp", 0)
                sig = obj.get("signature", "")
                verify_payload(payload, nonce, ts, sig)
            except Exception as e:
                logger.error("[CS->CP] verification failed: %s", e)
                # We do not forward bad messages to CP
                continue

            await cp_ws.send(payload)
    except websockets.exceptions.ConnectionClosedOK:
        logger.info("[CS->CP] central closed connection normally")
    except Exception as e:
        logger.exception("[CS->CP] error: %s", e)


# --- compatibility wrapper for websockets handler (accepts both signatures) ---
async def handle_client(*args):
    """
    Compatibility wrapper for websockets handler:
      - Some websockets versions call handler(ws, path)
      - Newer versions call handler(connection) only
    This implementation accepts either and extracts client_ws and path.
    """
    # Unpack args robustly
    if len(args) == 1:
        client_ws = args[0]
        # many websockets Connection objects store the path on .path attribute
        path = getattr(client_ws, "path", None)
    elif len(args) >= 2:
        client_ws, path = args[0], args[1]
    else:
        # shouldn't happen
        raise RuntimeError("handle_client called with unexpected args")

    cp_id = (path or "").lstrip("/") or "UNKNOWN"
    logger.info(
        "Proxy: CP connected id=%s remote=%s subprotocol=%s",
        cp_id,
        getattr(client_ws, "remote_address", None),
        getattr(client_ws, "subprotocol", None),
    )

    # Connect to central for this CP id
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
                          
