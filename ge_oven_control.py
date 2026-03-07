#!/usr/bin/env python3
"""
GE Café Oven Controller - Reverse-engineered from the SmartHQ Android APK

This script lets you control a GE Café oven (set it to bake at 350°F, etc.)
by talking directly to the GE SmartHQ/Brillion cloud API.

Protocol details reverse-engineered from com.ge.cafe APK (decompiled with jadx):
- WebSocket endpoint: wss://ws-us-east-1.brillion.geappliances.com
- Auth: OAuth2 via accounts.brillion.geappliances.com
- Appliance control via ERD (Entity Resource Dictionary) codes sent as hex strings
- Messages are JSON over WebSocket with kind/action/method/path/body structure

Key ERD codes for oven control (from GEMakers/gea-plugin-range + gehomesdk):
  0x5100 - Upper oven cook mode (read)
  0x5200 - Upper oven available cook modes
  0x5205 - Upper oven cook mode command (write) — THIS IS THE KEY ONE
  0x5201 - Upper oven raw temperature
  0x5400 - Lower oven cook mode
  0x5405 - Lower oven cook mode command (write)
  0x5401 - Lower oven raw temperature

Cook mode byte values (first byte of ERD 0x5205 value):
  0x00 - No mode / off
  0x01 - Bake
  0x02 - Convection Bake
  0x03 - Convection Multi-Bake
  0x04 - Convection Roast
  0x05 - Broil High
  0x06 - Broil Low
  0x07 - Warm
  0x18 - Self Clean

ERD 0x5205 value format (hex string, no 0x prefix):
  Byte 0: Cook mode (e.g., 01 = Bake)
  Bytes 1-2: Temperature in °F, big-endian (e.g., 350°F = 0x015E)
  Bytes 3-4: Cook time in minutes, big-endian (0x0000 = no timer)
  Byte 5: Delay start hours
  Byte 6: Delay start minutes
  Byte 7: Probe temperature (0x00 if not used)
  Byte 8: Probe temperature high byte (0x00 if not used)

Example: Bake at 350°F with no timer = "01015E0000000000" + "00"

Usage:
    python3 ge_oven_control.py --username YOUR_EMAIL --password YOUR_PASSWORD
"""

import argparse
import asyncio
import json
import logging
import ssl
import sys
import uuid
from dataclasses import dataclass
from enum import IntEnum

try:
    import aiohttp
except ImportError:
    print("ERROR: aiohttp is required. Install with: pip install aiohttp")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ─── Constants from decompiled APK ───────────────────────────────────────────

# OAuth2 endpoints (from accounts.brillion.geappliances.com)
OAUTH2_AUTH_URL = "https://accounts.brillion.geappliances.com/oauth2/token"
# The app uses a specific client_id embedded (obfuscated) in the APK
OAUTH2_CLIENT_ID = "564c31616c4f7768"
OAUTH2_CLIENT_SECRET = "6476512a5044654d"
OAUTH2_REDIRECT_URI = "brillion.4e617a6e:redirect"

# Alternative login endpoint used by gehomesdk (simpler, works with username/password)
LOGIN_URL = "https://accounts.brillion.geappliances.com/oauth2/token"

# WebSocket endpoint (from WsContains class in APK)
WS_URL = "wss://ws.brillion.geappliances.com/v1/websocket"

# REST API base (v2 API from remote/v2/api in the APK)
API_BASE = "https://api.brillion.geappliances.com/v1"

# ERD codes for oven control
APPLIANCE_TYPE_ERD = "0x0008"       # Appliance type identifier
OVEN_COOK_MODE_ERD = "0x5100"       # Current cook mode (read-only)
OVEN_COOK_MODE_CMD = "0x5205"       # Cook mode command (write) — upper oven
OVEN_TEMP_RAW = "0x5201"            # Current raw temperature (read-only)
OVEN_STATE = "0x5200"               # Available cook modes
LOWER_OVEN_COOK_CMD = "0x5405"      # Cook mode command — lower oven


class OvenCookMode(IntEnum):
    """Cook mode values (byte 0 of ERD 0x5205)"""
    OFF = 0x00
    BAKE = 0x01
    CONVECTION_BAKE = 0x02
    CONVECTION_MULTI_BAKE = 0x03
    CONVECTION_ROAST = 0x04
    BROIL_HIGH = 0x05
    BROIL_LOW = 0x06
    WARM = 0x07
    SELF_CLEAN = 0x18


@dataclass
class OvenCommand:
    """Represents an oven cook command to be encoded into ERD 0x5205 value"""
    cook_mode: OvenCookMode = OvenCookMode.BAKE
    temperature_f: int = 350
    cook_time_minutes: int = 0  # 0 = no timer
    delay_hours: int = 0
    delay_minutes: int = 0
    probe_temp_f: int = 0

    def encode(self) -> str:
        """Encode to hex string for ERD 0x5205 value.

        Format confirmed from decompiled CookSetting.java and
        GEMakers/gea-plugin-range ERD documentation:
          byte 0: cook mode
          bytes 1-2: temperature (big-endian uint16)
          bytes 3-4: cook time in minutes (big-endian uint16)
          byte 5: delay hours
          byte 6: delay minutes
          bytes 7-8: probe temperature (big-endian uint16)
        """
        data = bytearray(9)
        data[0] = self.cook_mode & 0xFF
        data[1] = (self.temperature_f >> 8) & 0xFF
        data[2] = self.temperature_f & 0xFF
        data[3] = (self.cook_time_minutes >> 8) & 0xFF
        data[4] = self.cook_time_minutes & 0xFF
        data[5] = self.delay_hours & 0xFF
        data[6] = self.delay_minutes & 0xFF
        data[7] = (self.probe_temp_f >> 8) & 0xFF
        data[8] = self.probe_temp_f & 0xFF
        return data.hex().upper()

    @classmethod
    def bake(cls, temperature_f: int = 350) -> "OvenCommand":
        return cls(cook_mode=OvenCookMode.BAKE, temperature_f=temperature_f)

    @classmethod
    def off(cls) -> "OvenCommand":
        return cls(cook_mode=OvenCookMode.OFF, temperature_f=0)


# ─── SmartHQ Client ──────────────────────────────────────────────────────────

class SmartHQClient:
    """Client for the GE SmartHQ/Brillion API.

    Reverse-engineered from the SmartHQ Android APK websocket layer:
    - WebSocketManger.java: WebSocket connection management
    - SendApiRequestWithBody.java: Request format (kind, action, host, method, path, id, body)
    - RequestBodyData.java: Body format (kind, userId, applianceId, erd, value, ackTimeout, delay)
    - WsAction enum: SUBSCRIBE, API, PUBSUB, PING
    - WsKind enum: KIND_WEBSOCKET_API, KIND_WRITE_ERD_LIST_ENTRY, etc.
    - WsMethod enum: GET, POST, DELETE
    """

    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self.access_token = None
        self.user_id = None
        self.session = None
        self.ws = None
        self.appliances = []

    async def login(self) -> bool:
        """Authenticate via OAuth2 Resource Owner Password Credentials flow.

        The SmartHQ app authenticates through accounts.brillion.geappliances.com.
        We use the direct token endpoint with username/password grant.
        """
        self.session = aiohttp.ClientSession()
        logger.info("Authenticating with SmartHQ...")

        try:
            async with self.session.post(
                LOGIN_URL,
                json={
                    "kind": "login#credential",
                    "brand": "cafe",  # or "ge", "monogram", "haier", "fisher_paykel", "profile"
                    "email": self.username,
                    "password": self.password,
                    "stay_signed_in": True,
                },
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "okhttp/4.12.0",
                },
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    self.access_token = data.get("access_token")
                    self.user_id = data.get("user_id")
                    logger.info(f"Login successful! User ID: {self.user_id}")
                    return True
                else:
                    body = await resp.text()
                    logger.error(f"Login failed (HTTP {resp.status}): {body}")
                    return False
        except Exception as e:
            logger.error(f"Login error: {e}")
            return False

    async def get_appliances(self) -> list:
        """Fetch list of appliances via REST API.

        From the decompiled code (LoadAllDevicePagesRequest.java), the app
        fetches appliances from the v1 API with pagination.
        """
        if not self.access_token:
            logger.error("Not authenticated")
            return []

        url = f"{API_BASE}/appliance"
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "User-Agent": "okhttp/4.12.0",
        }

        try:
            async with self.session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    # Response contains a "kind" and "items" list
                    items = data if isinstance(data, list) else data.get("items", [data])
                    self.appliances = items
                    logger.info(f"Found {len(items)} appliance(s)")
                    for i, app in enumerate(items):
                        jid = app.get("jid", app.get("applianceId", "unknown"))
                        nickname = app.get("nickname", "unnamed")
                        logger.info(f"  [{i}] {nickname} (ID: {jid})")
                    return items
                else:
                    body = await resp.text()
                    logger.error(f"Failed to get appliances (HTTP {resp.status}): {body}")
                    return []
        except Exception as e:
            logger.error(f"Error fetching appliances: {e}")
            return []

    async def read_erd(self, appliance_id: str, erd_code: str) -> str | None:
        """Read an ERD value from an appliance via REST API.

        ERD codes are the core of GE's appliance protocol — each one represents
        a specific property or command endpoint on the appliance.
        """
        url = f"{API_BASE}/appliance/{appliance_id}/erd/{erd_code}"
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "User-Agent": "okhttp/4.12.0",
        }

        try:
            async with self.session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    value = data.get("value", data)
                    logger.info(f"ERD {erd_code} = {value}")
                    return value
                else:
                    body = await resp.text()
                    logger.error(f"Failed to read ERD {erd_code} (HTTP {resp.status}): {body}")
                    return None
        except Exception as e:
            logger.error(f"Error reading ERD: {e}")
            return None

    async def write_erd(self, appliance_id: str, erd_code: str, value: str) -> bool:
        """Write an ERD value to an appliance via REST API.

        This is how the app controls appliances. The value is a hex string.

        From the decompiled RequestBodyData.java, the WebSocket version sends:
        {
            "kind": "websocket#erd",
            "userId": "...",
            "applianceId": "...",
            "erd": "0x5205",
            "value": "01015E000000000000",
            "ackTimeout": 10,
            "delay": 0
        }

        The REST equivalent POSTs the value directly.
        """
        url = f"{API_BASE}/appliance/{appliance_id}/erd/{erd_code}"
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
            "User-Agent": "okhttp/4.12.0",
        }
        payload = {
            "kind": "appliance#erdListEntry",
            "userId": self.user_id,
            "applianceId": appliance_id,
            "erd": erd_code,
            "value": value,
            "ackTimeout": 10,
            "delay": 0,
        }

        try:
            async with self.session.post(url, json=payload, headers=headers) as resp:
                if resp.status in (200, 204):
                    logger.info(f"Successfully wrote ERD {erd_code} = {value}")
                    return True
                else:
                    body = await resp.text()
                    logger.error(f"Failed to write ERD {erd_code} (HTTP {resp.status}): {body}")
                    return False
        except Exception as e:
            logger.error(f"Error writing ERD: {e}")
            return False

    async def set_oven_bake(self, appliance_id: str, temperature_f: int = 350,
                            cavity: str = "upper") -> bool:
        """Set the oven to bake at the specified temperature.

        This encodes the cook command into the ERD 0x5205 format and writes it.

        Args:
            appliance_id: The appliance JID/MAC from get_appliances()
            temperature_f: Temperature in Fahrenheit (typically 170-550)
            cavity: "upper" or "lower" for double ovens
        """
        cmd = OvenCommand.bake(temperature_f)
        erd = OVEN_COOK_MODE_CMD if cavity == "upper" else LOWER_OVEN_COOK_CMD
        hex_value = cmd.encode()

        logger.info(f"Setting oven to BAKE at {temperature_f}°F")
        logger.info(f"  ERD: {erd}")
        logger.info(f"  Value: {hex_value}")
        logger.info(f"  Decoded: mode=BAKE(0x01), temp={temperature_f}°F(0x{temperature_f:04X}), "
                     f"timer=0min, delay=0:00, probe=0°F")

        return await self.write_erd(appliance_id, erd, hex_value)

    async def turn_off_oven(self, appliance_id: str, cavity: str = "upper") -> bool:
        """Turn off the oven."""
        cmd = OvenCommand.off()
        erd = OVEN_COOK_MODE_CMD if cavity == "upper" else LOWER_OVEN_COOK_CMD
        logger.info("Turning oven OFF")
        return await self.write_erd(appliance_id, erd, cmd.encode())

    async def get_oven_status(self, appliance_id: str) -> dict | None:
        """Read current oven status (cook mode + temperature)."""
        mode_hex = await self.read_erd(appliance_id, OVEN_COOK_MODE_ERD)
        temp_hex = await self.read_erd(appliance_id, OVEN_TEMP_RAW)

        if mode_hex and isinstance(mode_hex, str) and len(mode_hex) >= 2:
            mode_byte = int(mode_hex[:2], 16)
            try:
                mode_name = OvenCookMode(mode_byte).name
            except ValueError:
                mode_name = f"UNKNOWN(0x{mode_byte:02X})"
        else:
            mode_name = "UNKNOWN"

        if temp_hex and isinstance(temp_hex, str) and len(temp_hex) >= 4:
            temp_f = int(temp_hex[:4], 16)
        else:
            temp_f = 0

        status = {"cook_mode": mode_name, "temperature_f": temp_f}
        logger.info(f"Oven status: {status}")
        return status

    # ─── WebSocket-based control (from WebSocketManger.java) ─────────────

    async def connect_websocket(self) -> bool:
        """Connect to the SmartHQ WebSocket for real-time control.

        From the decompiled WebSocketManger.java, the app:
        1. Opens WSS connection to ws.brillion.geappliances.com
        2. Sends a subscription request for the user's appliances
        3. Listens for ERD change notifications
        4. Sends PING frames to keep alive
        """
        if not self.access_token:
            logger.error("Not authenticated")
            return False

        ws_url = f"{WS_URL}?token={self.access_token}"
        ssl_ctx = ssl.create_default_context()

        try:
            self.ws = await self.session.ws_connect(
                ws_url,
                ssl=ssl_ctx,
                heartbeat=30,
            )
            logger.info("WebSocket connected!")

            # Subscribe to appliance updates (from WsAction.SUBSCRIBE)
            subscribe_msg = {
                "kind": "websocket#subscribe",
                "action": "subscribe",
                "resources": [f"/appliance/{self.user_id}/erd"],
            }
            await self.ws.send_json(subscribe_msg)
            logger.info("Subscribed to appliance updates")
            return True

        except Exception as e:
            logger.error(f"WebSocket connection failed: {e}")
            return False

    async def ws_write_erd(self, appliance_id: str, erd_code: str, value: str) -> bool:
        """Write an ERD value via WebSocket.

        This mirrors the SendApiRequestWithBody message format from the decompiled APK:
        {
            "kind": "websocket#api",
            "action": "api",
            "host": "api.brillion.geappliances.com",
            "method": "POST",
            "path": "/v1/appliance/{appliance_id}/erd/{erd}",
            "id": "{uuid}",
            "body": {
                "kind": "appliance#erdListEntry",
                "userId": "...",
                "applianceId": "...",
                "erd": "...",
                "value": "...",
                "ackTimeout": 10,
                "delay": 0
            }
        }
        """
        if not self.ws:
            logger.error("WebSocket not connected, falling back to REST")
            return await self.write_erd(appliance_id, erd_code, value)

        msg = {
            "kind": "websocket#api",
            "action": "api",
            "host": "api.brillion.geappliances.com",
            "method": "POST",
            "path": f"/v1/appliance/{appliance_id}/erd/{erd_code}",
            "id": str(uuid.uuid4()),
            "body": {
                "kind": "appliance#erdListEntry",
                "userId": self.user_id,
                "applianceId": appliance_id,
                "erd": erd_code,
                "value": value,
                "ackTimeout": 10,
                "delay": 0,
            },
        }

        try:
            await self.ws.send_json(msg)
            logger.info(f"Sent WebSocket ERD write: {erd_code} = {value}")
            return True
        except Exception as e:
            logger.error(f"WebSocket write failed: {e}")
            return False

    async def close(self):
        """Clean up connections."""
        if self.ws:
            await self.ws.close()
        if self.session:
            await self.session.close()


# ─── CLI ─────────────────────────────────────────────────────────────────────

async def main():
    parser = argparse.ArgumentParser(
        description="Control your GE Café oven from the command line",
        epilog="""
Examples:
  # List your appliances
  %(prog)s --username you@email.com --password secret --list

  # Set oven to bake at 350°F
  %(prog)s --username you@email.com --password secret --bake 350

  # Set oven to bake at 400°F (lower cavity)
  %(prog)s --username you@email.com --password secret --bake 400 --cavity lower

  # Turn off the oven
  %(prog)s --username you@email.com --password secret --off

  # Check oven status
  %(prog)s --username you@email.com --password secret --status

  # Write a raw ERD value
  %(prog)s --username you@email.com --password secret --erd 0x5205 --value 01015E000000000000
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--username", required=True, help="SmartHQ account email")
    parser.add_argument("--password", required=True, help="SmartHQ account password")
    parser.add_argument("--list", action="store_true", help="List appliances")
    parser.add_argument("--bake", type=int, metavar="TEMP_F", help="Set oven to bake at temperature (°F)")
    parser.add_argument("--off", action="store_true", help="Turn off the oven")
    parser.add_argument("--status", action="store_true", help="Get oven status")
    parser.add_argument("--cavity", choices=["upper", "lower"], default="upper",
                        help="Oven cavity (default: upper)")
    parser.add_argument("--appliance", type=int, default=0,
                        help="Appliance index from --list (default: 0)")
    parser.add_argument("--erd", help="Raw ERD code to read/write (e.g., 0x5205)")
    parser.add_argument("--value", help="Raw hex value to write to ERD")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    client = SmartHQClient(args.username, args.password)

    try:
        if not await client.login():
            logger.error("Authentication failed. Check your credentials.")
            return 1

        appliances = await client.get_appliances()
        if not appliances:
            logger.error("No appliances found on your account.")
            return 1

        if args.list:
            # Already printed during get_appliances
            return 0

        # Get the target appliance ID
        if args.appliance >= len(appliances):
            logger.error(f"Appliance index {args.appliance} out of range (have {len(appliances)})")
            return 1

        app = appliances[args.appliance]
        appliance_id = app.get("jid", app.get("applianceId", ""))
        logger.info(f"Using appliance: {app.get('nickname', appliance_id)}")

        if args.bake:
            if args.bake < 170 or args.bake > 550:
                logger.error(f"Temperature {args.bake}°F out of range (170-550°F)")
                return 1
            await client.set_oven_bake(appliance_id, args.bake, args.cavity)

        elif args.off:
            await client.turn_off_oven(appliance_id, args.cavity)

        elif args.status:
            await client.get_oven_status(appliance_id)

        elif args.erd:
            if args.value:
                await client.write_erd(appliance_id, args.erd, args.value)
            else:
                await client.read_erd(appliance_id, args.erd)

        else:
            parser.print_help()
            return 1

        return 0

    finally:
        await client.close()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
