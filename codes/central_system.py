#!/usr/bin/env python3
# central_system.py
import asyncio
import logging
import json
import time
import hmac
import hashlib
import secrets

import websockets
from datetime import datetime, timezone

from ocpp.routing import on
from ocpp.v16 import ChargePoint as OcppChargePoint
from ocpp.v16 import call_result
from ocpp.v16.enums import Action, RegistrationStatus

# === Config ===
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 9000
SUBPROTOCOL = "ocpp-envelope"   # proxy will speak this to the central
SECRET_KEY = b"SuperSecretKey123"  # MUST match the proxy
ALLOWED_SKEW_SECONDS = 60

# === Logging ===
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("central")

# === Envelope-compatible WebSocket wrapper ===
class EnvelopeWebSocket:
    """
    Wrap a real websocket that speaks JSON envelope messages:
      {"envelope_version":"1.0","nonce": "...", "timestamp": 1234567890, "signature": "...", "payload": "<raw OCPP text>"}
    The wrapper exposes recv()/send() where recv() returns the inner payload string (after verifying HMAC/timestamp)
    and send() wraps outgoing payloads in a fresh envelope and sends.
    """
    def __init__(self, real_ws):
        self._ws = real_ws
        self.subprotocol = getattr(real_ws, "subprotocol", None)
        self.remote_address = getattr(real_ws, "remote_address", None)

    async def recv(self):
        wrapped = await self._ws.recv()
        # Expect wrapped JSON; if not JSON, return as-is (defensive)
        try:
            obj = json.loads(wrapped)
        except Exception:
            return wrapped

        if not isinstance(obj, dict) or "payload" not in obj:
            # Not an envelope -> return raw
            return wrapped

        payload = obj.get("payload", "")
        nonce = obj.get("nonce", "")
        timestamp = obj.get("timestamp", 0)
        signature = obj.get("signature", "")

        # Verify HMAC
        expected = hmac.new(SECRET_KEY, f"{payload}{nonce}{timestamp}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            logger.error("Envelope HMAC mismatch -> closing connection")
            # politely close
            await self._ws.close(code=4000, reason="HMAC mismatch")
            raise Exception("HMAC mismatch")

        # Check replay / timestamp
        now = time.time()
        if abs(now - float(timestamp)) > ALLOWED_SKEW_SECONDS:
            logger.error("Envelope timestamp outside allowed skew -> closing connection")
            await self._ws.close(code=4001, reason="Timestamp skew")
            raise Exception("Timestamp skew")

        return payload

    async def send(self, message: str):
        # message is a raw OCPP JSON/text string; wrap it
        nonce = secrets.token_hex(16)
        ts = int(time.time())
        signature = hmac.new(SECRET_KEY, f"{message}{nonce}{ts}".encode(), hashlib.sha256).hexdigest()
        envelope = {
            "envelope_version": "1.0",
            "nonce": nonce,
            "timestamp": ts,
            "signature": signature,
            "payload": message,
        }
        await self._ws.send(json.dumps(envelope))

    async def close(self, code=1000, reason=""):
        await self._ws.close(code, reason)

    # provide attributes the ocpp lib may inspect
    @property
    def closed(self):
        return getattr(self._ws, "closed", False)


# === OCPP ChargePoint subclass with handlers ===
class ChargePoint(OcppChargePoint):
    @on(Action.boot_notification)
    def on_boot_notification(self, charge_point_model: str, charge_point_vendor: str, **kwargs):
        logger.info("Central: BootNotification from model=%s vendor=%s", charge_point_model, charge_point_vendor)
        return call_result.BootNotification(
            current_time=datetime.now(timezone.utc).isoformat(),
            interval=10,
            status=RegistrationStatus.accepted,
        )

    @on(Action.heartbeat)
    def on_heartbeat(self, **kwargs):
        logger.info("Central: Heartbeat")
        return call_result.Heartbeat(current_time=datetime.now(timezone.utc).isoformat())


async def handler(raw_ws, path=None):
    """
    Accepts either (websocket, path) or (connection) depending on websockets version.
    We only accept the ocpp-envelope subprotocol here.
    """
    ws = raw_ws
    cp_id = (path or "").lstrip("/") or "UNKNOWN"

    logger.info("Central: new connection path=%s subprotocol=%s", path, getattr(ws, "subprotocol", None))

    if getattr(ws, "subprotocol", None) != SUBPROTOCOL:
        logger.warning("Central: client did not negotiate %s -> closing", SUBPROTOCOL)
        try:
            await ws.close()
        except Exception:
            pass
        return

    # Wrap underlying websocket with envelope-handling websocket for ocpp library
    wrapper = EnvelopeWebSocket(ws)
    charge_point = ChargePoint(cp_id, wrapper)

    try:
        await charge_point.start()
    except Exception as e:
        logger.exception("Central: chargepoint %s closed with exception: %s", cp_id, e)
    finally:
        logger.info("Central: connection closed for %s", cp_id)


async def main():
    logger.info("Central system listening on ws://%s:%s (%s)", LISTEN_HOST, LISTEN_PORT, SUBPROTOCOL)
    server = await websockets.serve(handler, LISTEN_HOST, LISTEN_PORT, subprotocols=[SUBPROTOCOL])
    await server.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())
