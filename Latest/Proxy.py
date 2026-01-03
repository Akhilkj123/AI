import asyncio
import json
import time
import hashlib
import hmac
import logging
import websockets

# ================= CONFIG =================

CENTRAL_URI = "ws://localhost:9000"
PROXY_HOST = "0.0.0.0"
PROXY_PORT = 9090

SHARED_SECRET = b"proxy-shared-secret"

FLOOD_WINDOW = 1.0        # seconds
FLOOD_LIMIT = 20          # messages per window

EXPECTED_FLOW = [
    "BootNotification",
    "Authorize",
    "StartTransaction",
    "Heartbeat",
    "StopTransaction"
]

# ================= LOGGING =================

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("proxy")

# ================= SECURITY CONTEXT =================

class ClientContext:
    def __init__(self):
        self.seen_nonces = set()
        self.last_action_index = -1
        self.msg_times = []

    def check_replay(self, nonce):
        if nonce in self.seen_nonces:
            return True
        self.seen_nonces.add(nonce)
        return False

    def check_reordering(self, action):
        if action not in EXPECTED_FLOW:
            return False

        idx = EXPECTED_FLOW.index(action)
        if idx < self.last_action_index:
            return True

        self.last_action_index = idx
        return False


# ================= SIGNATURE =================

def verify_signature(envelope):
    try:
        payload = envelope["payload"]
        received_sig = envelope["signature"]

        computed = hmac.new(
            SHARED_SECRET,
            payload.encode(),
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(received_sig, computed)
    except Exception:
        return False


# ================= PROXY HANDLER =================

async def handle_client(websocket):
    logger.info("Proxy: CP connected id=UNKNOWN")
    ctx = ClientContext()

    try:
        central = await websockets.connect(
            CENTRAL_URI,
            subprotocols=["ocpp-envelope"]
        )

        async for message in websocket:
            now = time.time()

            # ================= FLOOD CHECK =================
            ctx.msg_times = [t for t in ctx.msg_times if now - t < FLOOD_WINDOW]
            ctx.msg_times.append(now)

            if len(ctx.msg_times) > FLOOD_LIMIT:
                logger.error("[SECURITY] Flooding detected from UNKNOWN")
                await websocket.close(code=1013, reason="DoS detected")
                await central.close()
                return

            # ================= MESSAGE PARSING =================
            try:
                data = json.loads(message)
            except json.JSONDecodeError:
                logger.error("[SECURITY] Invalid JSON")
                await websocket.close()
                return

            # ================= ENVELOPE MODE =================
            if isinstance(data, dict):
                nonce = data.get("nonce")

                if ctx.check_replay(nonce):
                    logger.error("[SECURITY] Replay attack detected")
                    await websocket.close()
                    await central.close()
                    return

                if not verify_signature(data):
                    logger.error("[SECURITY] Message tampering detected")
                    await websocket.close()
                    await central.close()
                    return

                payload = json.loads(data["payload"])
            else:
                payload = data

            # ================= REORDERING CHECK =================
            if isinstance(payload, list) and len(payload) >= 3:
                action = payload[2]

                if ctx.check_reordering(action):
                    logger.error(
                        f"[SECURITY] Message reordering detected: "
                        f"last={EXPECTED_FLOW[ctx.last_action_index]} incoming={action}"
                    )
                    # Log only – do NOT close (research-friendly)
            else:
                action = "UNKNOWN"

            logger.info(f"[CP->CS] {payload}")

            # ================= FORWARD TO CENTRAL =================
            await central.send(message)

            # ================= NON-BLOCKING RESPONSE =================
            try:
                response = await asyncio.wait_for(central.recv(), timeout=1)
                await websocket.send(response)
            except asyncio.TimeoutError:
                pass

    except websockets.exceptions.ConnectionClosed:
        logger.info("Proxy: connection closed")

    finally:
        try:
            await central.close()
        except Exception:
            pass


# ================= MAIN =================

async def main():
    server = await websockets.serve(
        handle_client,
        PROXY_HOST,
        PROXY_PORT,
        subprotocols=["ocpp1.6"]
    )

    logger.info(f"Proxy running on ws://{PROXY_HOST}:{PROXY_PORT}")
    await server.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
