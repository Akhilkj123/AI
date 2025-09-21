
#!/usr/bin/env python3
# charge_point.py
import asyncio
import logging

import websockets

from ocpp.v16 import ChargePoint as OcppChargePoint
from ocpp.v16 import call
from ocpp.v16.enums import RegistrationStatus

# === Config ===
PROXY_URI = "ws://localhost:9090/CP_1"
SUBPROT = ["ocpp1.6"]

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("charge_point")

class ChargePoint(OcppChargePoint):
    async def send_boot_notification(self):
        request = call.BootNotification(charge_point_model="DemoModel-1000", charge_point_vendor="DemoVendor")
        try:
            response = await self.call(request)
        except Exception as e:
            logger.exception("BootNotification failed: %s", e)
            return

        if response and response.status == RegistrationStatus.accepted:
            logger.info("Connected to central (via proxy). BootNotification accepted: %s", response)
        else:
            logger.warning("BootNotification not accepted: %s", response)


async def main():
    async with websockets.connect(PROXY_URI, subprotocols=SUBPROT) as ws:
        cp = ChargePoint("CP_1", ws)
        await asyncio.gather(cp.start(), cp.send_boot_notification())

if __name__ == "__main__":
    asyncio.run(main())
