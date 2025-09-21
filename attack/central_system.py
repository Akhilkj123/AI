#!/usr/bin/env python3
# central_system.py
"""
Central system that accepts "ocpp-envelope" subprotocol connections.
Wraps an underlying websockets connection and verifies HMAC / timestamp
and detects simple replays (payload hash within REPLAY_WINDOW_SECONDS).
"""
import asyncio
import logging
import json
import time
import hmac
import hashlib
import secrets
from collections import OrderedDict
from datetime import datetime, timezone

import websockets

from ocpp.routing import on
from ocpp.v16 import ChargePoint as OcppChargePoint
from ocpp.v16 import call_result
from ocpp.v16.enums import Action, RegistrationStatus

# === Config ===
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 9000
SUBPROTOCOL = "ocpp-envelope"   # proxy will speak this to the central
SECRET_KEY = b"SuperSecretKey123"  # MUST match the proxy (bytes)
ALLOWED_SKEW_SECONDS = 60

# Replay protection (simple in-memory cache)
REPLAY_WINDOW_SECONDS = 30  # window to consider payloads as replay
_REPLAY_CACHE = OrderedDict()  # maps payload_hash -> last_seen_ts
_MAX_REPLAY_CACHE_ENTRIES = 2000

# === Logging ===
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("central")


# === Envelope-compatible WebSocket wrapper ===
class EnvelopeWebSocket:
    """
    Wrap a real websocket that speaks JSON envelope messages:
      {"envelope_version":"1.0","nonce": "...", "timestamp": 1234567890, "signature": "...", "payload": "<raw OCPP text>"}

    The wrapper exposes recv()/send() where recv() returns the inner payload string
    (after verifying HMAC/timestamp/replay) and send() wraps outgoing payloads in a fresh envelope and sends.
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
        try:
            expected = hmac.new(SECRET_KEY, f"{payload}{nonce}{timestamp}".encode(), hashlib.sha256).hexdigest()
        except Exception as e:
            logger.exception("Envelope HMAC generation error: %s", e)
            await self._ws.close(code=4000, reason="HMAC error")
            raise

        if not hmac.compare_digest(expected, signature):
            logger.error("Envelope HMAC mismatch -> closing connection")
            # politely close
            try:
                await self._ws.close(code=4000, reason="HMAC mismatch")
            except Exception:
                pass
            raise Exception("HMAC mismatch")

        # Check replay / timestamp
        now = time.time()
        try:
            ts_float = float(timestamp)
        except Exception:
            logger.error("Envelope timestamp parse error -> closing")
            try:
                await self._ws.close(code=4002, reason="Timestamp parse error")
            except Exception:
                pass
            raise Exception("Timestamp parse error")

        if abs(now - ts_float) > ALLOWED_SKEW_SECONDS:
            logger.error("Envelope timestamp outside allowed skew -> closing connection")
            try:
                await self._ws.close(code=4001, reason="Timestamp skew")
            except Exception:
                pass
            raise Exception("Timestamp skew")

        # ---- Replay detection ----
        payload_hash = hashlib.sha256(payload.encode()).hexdigest()

        # purge old entries
        cutoff = now - REPLAY_WINDOW_SECONDS
        keys_to_delete = [k for k, ts in _REPLAY_CACHE.items() if ts < cutoff]
        for k in keys_to_delete:
            _REPLAY_CACHE.pop(k, None)

        last_seen = _REPLAY_CACHE.get(payload_hash)
        if last_seen is not None:
            logger.warning(
                "Envelope replay detected for payload hash %s (last seen at %s) -> rejecting",
                payload_hash, datetime.fromtimestamp(last_seen, tz=timezone.utc).isoformat()
            )
            # Option: close or raise to stop processing this message
            # We'll raise to signal the caller; you can change to close instead.
            raise Exception("Replay detected")

        # record this payload
        _REPLAY_CACHE[payload_hash] = now
        # trim cache size if necessary
        while len(_REPLAY_CACHE) > _MAX_REPLAY_CACHE_ENTRIES:
            _REPLAY_CACHE.popitem(last=False)

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


# === Handler compatible with websockets versions that use (ws, path) or a single connection object ===
async def handler(*args):
    """
    Accepts either (websocket, path) or (connection) depending on websockets version.
    We only accept the ocpp-envelope subprotocol here.
    """
    if len(args) == 1:
        ws = args[0]
        path = getattr(ws, "path", None)
    elif len(args) >= 2:
        ws, path = args[0], args[1]
    else:
        raise RuntimeError("handler called with unexpected arguments")

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


# === Robust main() that logs startup and blocks forever ===
async def main():
    try:
        logger.info("Central system starting on ws://%s:%s (%s)", LISTEN_HOST, LISTEN_PORT, SUBPROTOCOL)
        async with websockets.serve(handler, LISTEN_HOST, LISTEN_PORT, subprotocols=[SUBPROTOCOL]) as server:
            logger.info("Central system listening (serve started). Server object: %s", server)
            # block forever until process is killed
            await asyncio.Future()
    except Exception as e:
        logger.exception("Central main() failed: %s", e)


if __name__ == "__main__":
    asyncio.run(main())
                             
