#!/usr/bin/env python3
"""
GE Café Oven Controller - Reverse-engineered from the SmartHQ Android APK

This script lets you control a GE Café oven (set it to bake at 350°F, etc.)
by talking directly to the GE SmartHQ/Brillion cloud API.

Protocol details from decompiled APK + gehomesdk open-source project:
- OAuth2 via accounts.brillion.geappliances.com (browser-style flow)
- WebSocket endpoint dynamically obtained from API
- Appliance control via ERD (Entity Resource Dictionary) codes as hex strings
- Messages are JSON over WebSocket with kind/action/method/path/body structure

Key ERD codes for oven control:
  0x5100 - Upper oven cook mode (read/write) — 13-byte encoded value
  0x5101 - Upper oven current state (read-only)
  0x5109 - Upper oven display temperature (read-only)
  0x510a - Upper oven remote enabled (read-only)
  0x510d - Upper oven raw temperature (read-only)
  0x5200 - Lower oven cook mode (read/write)

ERD 0x5100 value format (13 bytes = 26 hex chars):
  Byte 0:    Cook mode enum (e.g., 0x01 = Bake)
  Bytes 1-2: Temperature in °F, big-endian (e.g., 350°F = 0x015E)
  Bytes 3-4: Cook time in minutes, big-endian (0x0000 = untimed)
  Bytes 5-6: Probe temperature, big-endian (0x0000 = none)
  Bytes 7-8: Delay time in minutes, big-endian (0x0000 = none)
  Bytes 9-10: Two-temp temperature, big-endian (0x0000 = none)
  Bytes 11-12: Two-temp cook time, big-endian (0x0000 = none)

Example: Bake at 350°F = "01015e00000000000000000000"

Usage:
    python3 ge_oven_control.py --username YOUR_EMAIL --password YOUR_PASSWORD --bake 350

Requirements:
    pip install aiohttp
"""

import argparse
import asyncio
import json
import logging
import re
import ssl
import sys
import uuid
from dataclasses import dataclass
from enum import IntEnum
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlencode, urlparse

try:
    import aiohttp
except ImportError:
    print("ERROR: aiohttp is required. Install with: pip install aiohttp")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ─── Constants from gehomesdk + decompiled APK ──────────────────────────────

# OAuth2 credentials (from gehomesdk/clients/const.py)
OAUTH2_APP_ID = "com.ge.kitchen.wca.prd.android"
OAUTH2_CLIENT_ID = "564c31616c4f7474434b307435412b4d2f6e7672"
OAUTH2_CLIENT_SECRET = "6476512b5246446d452f697154444941387052645938466e5671746e5847593d"
OAUTH2_REDIRECT_URI = "brillion.4e617a766474657344444e562b5935566e51324a://oauth/redirect"

# API endpoints
LOGIN_URL = "https://accounts.brillion.geappliances.com"
API_URL = "https://api.brillion.geappliances.com"
API_HOST = "api.brillion.geappliances.com"

# ERD codes for oven control
UPPER_OVEN_COOK_MODE = "0x5100"
UPPER_OVEN_CURRENT_STATE = "0x5101"
UPPER_OVEN_COOK_TIME_REMAINING = "0x5104"
UPPER_OVEN_DISPLAY_TEMPERATURE = "0x5109"
UPPER_OVEN_REMOTE_ENABLED = "0x510a"
UPPER_OVEN_RAW_TEMPERATURE = "0x510d"
LOWER_OVEN_COOK_MODE = "0x5200"


class OvenCookMode(IntEnum):
    """Cook mode values (byte 0 of ERD 0x5100 value).
    From gehomesdk/erd/values/oven/erd_oven_cook_mode.py"""
    NOMODE = 0
    BAKE_NOOPTION = 1
    BAKE_PROBE = 2
    BAKE_DELAYSTART = 3
    BAKE_TIMED_WARM = 4
    BAKE_TIMED_TWOTEMP = 5
    BAKE_PROBE_DELAYSTART = 6
    BAKE_TIMED_SHUTOFF_DELAY = 7
    BAKE_TIMED_WARM_DELAYSTART = 8
    BAKE_TIMED_TWOTEMP_DELAY = 9
    BROIL_LOW = 11
    BROIL_HIGH = 12
    PROOF_NOOPTION = 13
    WARM_NOOPTION = 14
    WARM_PROBE = 15
    CONVBAKE_NOOPTION = 18
    CONVBAKE_PROBE = 19
    CONVBAKE_DELAYSTART = 20
    CONVBAKE_TIMED_WARM = 21
    CONVBAKE_TIMED_TWOTEMP = 22
    CONVBAKE_PROBE_DELAYSTART = 23
    CONVBAKE_TIMED_SHUTOFF_DELAY = 24
    CONVBAKE_TIMED_WARM_DELAYSTART = 25
    CONVBAKE_TIMED_TWOTEMP_DELAY = 26
    CONVMULTIBAKE_NOOPTION = 27
    CONVROAST_NOOPTION = 36
    CONVROAST_PROBE = 37
    CONVROAST_DELAYSTART = 38
    CONVROAST_TIMED_WARM = 39
    CONVROAST_PROBE_DELAYSTART = 41
    CONVROAST_TIMED_SHUTOFF_DELAY = 42
    CONVROAST_TIMED_WARM_DELAYSTART = 43
    SELFCLEAN = 45
    SELFCLEAN_DELAYSTART = 46
    STEAMCLEAN = 47
    STEAMCLEAN_DELAYSTART = 48
    DUALBROIL_LOW_NOOPTION = 49
    DUALBROIL_HIGH_NOOPTION = 50
    AIRFRY = 158


@dataclass
class OvenCommand:
    """Represents an oven cook command to be encoded into ERD 0x5100 value.

    The value is 13 bytes (26 hex chars) encoding cook mode, temperature,
    cook time, probe temp, delay, and two-temp settings.
    """
    cook_mode: OvenCookMode = OvenCookMode.BAKE_NOOPTION
    temperature_f: int = 350
    cook_time_minutes: int = 0
    probe_temp_f: int = 0
    delay_minutes: int = 0
    two_temp_f: int = 0
    two_temp_minutes: int = 0

    def encode(self) -> str:
        """Encode to hex string for ERD 0x5100 value.

        Format (13 bytes):
          byte 0:    cook mode
          bytes 1-2: temperature (big-endian uint16)
          bytes 3-4: cook time in minutes (big-endian uint16)
          bytes 5-6: probe temperature (big-endian uint16)
          bytes 7-8: delay time in minutes (big-endian uint16)
          bytes 9-10: two-temp temperature (big-endian uint16)
          bytes 11-12: two-temp cook time (big-endian uint16)
        """
        data = bytearray(13)
        data[0] = self.cook_mode & 0xFF
        data[1] = (self.temperature_f >> 8) & 0xFF
        data[2] = self.temperature_f & 0xFF
        data[3] = (self.cook_time_minutes >> 8) & 0xFF
        data[4] = self.cook_time_minutes & 0xFF
        data[5] = (self.probe_temp_f >> 8) & 0xFF
        data[6] = self.probe_temp_f & 0xFF
        data[7] = (self.delay_minutes >> 8) & 0xFF
        data[8] = self.delay_minutes & 0xFF
        data[9] = (self.two_temp_f >> 8) & 0xFF
        data[10] = self.two_temp_f & 0xFF
        data[11] = (self.two_temp_minutes >> 8) & 0xFF
        data[12] = self.two_temp_minutes & 0xFF
        return data.hex()

    @classmethod
    def bake(cls, temperature_f: int = 350) -> "OvenCommand":
        return cls(cook_mode=OvenCookMode.BAKE_NOOPTION, temperature_f=temperature_f)

    @classmethod
    def off(cls) -> "OvenCommand":
        return cls(cook_mode=OvenCookMode.NOMODE, temperature_f=0)


# ─── SmartHQ Client ──────────────────────────────────────────────────────────

class SmartHQClient:
    """Client for the GE SmartHQ/Brillion API.

    Implements the OAuth2 browser-style login flow and WebSocket-based
    appliance control, reverse-engineered from the SmartHQ APK and
    gehomesdk open-source project.
    """

    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self.access_token = None
        self.refresh_token = None
        self.user_id = None
        self.session = None
        self.ws = None
        self.appliances = []

    async def login(self) -> bool:
        """Authenticate via OAuth2 browser-style flow.

        The flow mimics what the SmartHQ app does:
        1. Set region cookie
        2. GET the OAuth2 authorization page to get hidden form fields
        3. POST credentials to g_authenticate endpoint
        4. Extract auth code from redirect
        5. Exchange auth code for access token
        """
        self.session = aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar())
        logger.info("Authenticating with SmartHQ...")

        try:
            # Step 1: Set region cookie
            self.session.cookie_jar.update_cookies(
                {"abgea_region": "us-east-1"},
                response_url=aiohttp.client.URL(LOGIN_URL),
            )

            # Step 2: Get authorization page
            auth_params = {
                "client_id": OAUTH2_CLIENT_ID,
                "response_type": "code",
                "access_type": "offline",
                "redirect_uri": OAUTH2_REDIRECT_URI,
            }
            auth_url = f"{LOGIN_URL}/oauth2/auth?{urlencode(auth_params)}"

            async with self.session.get(auth_url, allow_redirects=True) as resp:
                if resp.status != 200:
                    logger.error(f"Failed to get auth page (HTTP {resp.status})")
                    return False
                html = await resp.text()

            # Extract hidden form fields from the HTML
            hidden_fields = {}
            for match in re.finditer(
                r'<input[^>]+type=["\']hidden["\'][^>]+name=["\']([^"\']+)["\'][^>]+value=["\']([^"\']*)["\']',
                html,
            ):
                hidden_fields[match.group(1)] = match.group(2)
            # Also check reverse attribute order
            for match in re.finditer(
                r'<input[^>]+value=["\']([^"\']*)["\'][^>]+name=["\']([^"\']+)["\'][^>]+type=["\']hidden["\']',
                html,
            ):
                hidden_fields[match.group(2)] = match.group(1)

            logger.debug(f"Found hidden fields: {list(hidden_fields.keys())}")

            # Step 3: Submit credentials
            form_data = {**hidden_fields, "username": self.username, "password": self.password}

            async with self.session.post(
                f"{LOGIN_URL}/oauth2/g_authenticate",
                data=form_data,
                allow_redirects=False,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            ) as resp:
                if resp.status == 302:
                    redirect_url = resp.headers.get("Location", "")
                    parsed = urlparse(redirect_url)
                    params = parse_qs(parsed.query)
                    auth_code = params.get("code", [None])[0]

                    if not auth_code:
                        logger.error(f"No auth code in redirect: {redirect_url}")
                        return False
                elif resp.status == 200:
                    # May need to handle MFA, terms acceptance, or app authorization
                    body = await resp.text()
                    logger.error("Login requires additional steps (MFA/terms). Check the app.")
                    logger.debug(f"Response body: {body[:500]}")
                    return False
                else:
                    body = await resp.text()
                    logger.error(f"Auth failed (HTTP {resp.status}): {body[:200]}")
                    return False

            # Step 4: Exchange auth code for token
            token_data = {
                "code": auth_code,
                "client_id": OAUTH2_CLIENT_ID,
                "client_secret": OAUTH2_CLIENT_SECRET,
                "redirect_uri": OAUTH2_REDIRECT_URI,
                "grant_type": "authorization_code",
            }

            auth_header = aiohttp.BasicAuth(OAUTH2_CLIENT_ID, OAUTH2_CLIENT_SECRET)

            async with self.session.post(
                f"{LOGIN_URL}/oauth2/token",
                data=token_data,
                auth=auth_header,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    self.access_token = data["access_token"]
                    self.refresh_token = data.get("refresh_token")
                    logger.info("Login successful!")
                    return True
                else:
                    body = await resp.text()
                    logger.error(f"Token exchange failed (HTTP {resp.status}): {body[:200]}")
                    return False

        except Exception as e:
            logger.error(f"Login error: {e}")
            return False

    async def _get_ws_endpoint(self) -> tuple[str, str] | None:
        """Get WebSocket endpoint and user ID from the API.

        The app calls GET /v1/websocket to get the dynamic WSS URL.
        """
        headers = {"Authorization": f"Bearer {self.access_token}"}
        try:
            async with self.session.get(f"{API_URL}/v1/websocket", headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    endpoint = data.get("endpoint")
                    self.user_id = data.get("userId")
                    logger.info(f"WebSocket endpoint: {endpoint}")
                    logger.info(f"User ID: {self.user_id}")
                    return endpoint, self.user_id
                else:
                    body = await resp.text()
                    logger.error(f"Failed to get WS endpoint (HTTP {resp.status}): {body[:200]}")
                    return None
        except Exception as e:
            logger.error(f"Error getting WS endpoint: {e}")
            return None

    async def get_appliances(self) -> list:
        """Fetch list of appliances via REST API."""
        if not self.access_token:
            logger.error("Not authenticated")
            return []

        headers = {"Authorization": f"Bearer {self.access_token}"}

        try:
            async with self.session.get(f"{API_URL}/v1/appliance", headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
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
                    logger.error(f"Failed to get appliances (HTTP {resp.status}): {body[:200]}")
                    return []
        except Exception as e:
            logger.error(f"Error fetching appliances: {e}")
            return []

    async def read_erd(self, appliance_id: str, erd_code: str) -> str | None:
        """Read an ERD value from an appliance via REST API."""
        headers = {"Authorization": f"Bearer {self.access_token}"}
        try:
            async with self.session.get(
                f"{API_URL}/v1/appliance/{appliance_id}/erd/{erd_code}",
                headers=headers,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    value = data.get("value", data)
                    logger.info(f"ERD {erd_code} = {value}")
                    return value
                else:
                    body = await resp.text()
                    logger.error(f"Failed to read ERD {erd_code} (HTTP {resp.status}): {body[:200]}")
                    return None
        except Exception as e:
            logger.error(f"Error reading ERD: {e}")
            return None

    async def write_erd(self, appliance_id: str, erd_code: str, value: str) -> bool:
        """Write an ERD value to an appliance via REST API."""
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
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
            async with self.session.post(
                f"{API_URL}/v1/appliance/{appliance_id}/erd/{erd_code}",
                json=payload,
                headers=headers,
            ) as resp:
                if resp.status in (200, 204):
                    logger.info(f"Successfully wrote ERD {erd_code} = {value}")
                    return True
                else:
                    body = await resp.text()
                    logger.error(f"Failed to write ERD {erd_code} (HTTP {resp.status}): {body[:200]}")
                    return False
        except Exception as e:
            logger.error(f"Error writing ERD: {e}")
            return False

    async def set_oven_bake(self, appliance_id: str, temperature_f: int = 350,
                            cavity: str = "upper") -> bool:
        """Set the oven to bake at the specified temperature."""
        cmd = OvenCommand.bake(temperature_f)
        erd = UPPER_OVEN_COOK_MODE if cavity == "upper" else LOWER_OVEN_COOK_MODE
        hex_value = cmd.encode()

        logger.info(f"Setting oven to BAKE at {temperature_f}°F")
        logger.info(f"  ERD: {erd}")
        logger.info(f"  Value: {hex_value}")

        return await self.write_erd(appliance_id, erd, hex_value)

    async def turn_off_oven(self, appliance_id: str, cavity: str = "upper") -> bool:
        """Turn off the oven."""
        cmd = OvenCommand.off()
        erd = UPPER_OVEN_COOK_MODE if cavity == "upper" else LOWER_OVEN_COOK_MODE
        logger.info("Turning oven OFF")
        return await self.write_erd(appliance_id, erd, cmd.encode())

    async def get_oven_status(self, appliance_id: str) -> dict | None:
        """Read current oven status (cook mode + temperature)."""
        mode_hex = await self.read_erd(appliance_id, UPPER_OVEN_COOK_MODE)
        temp_hex = await self.read_erd(appliance_id, UPPER_OVEN_DISPLAY_TEMPERATURE)

        if mode_hex and isinstance(mode_hex, str) and len(mode_hex) >= 2:
            mode_byte = int(mode_hex[:2], 16)
            try:
                mode_name = OvenCookMode(mode_byte).name
            except ValueError:
                mode_name = f"UNKNOWN(0x{mode_byte:02X})"

            temp_from_mode = 0
            if len(mode_hex) >= 6:
                temp_from_mode = int(mode_hex[2:6], 16)
        else:
            mode_name = "UNKNOWN"
            temp_from_mode = 0

        display_temp = 0
        if temp_hex and isinstance(temp_hex, str) and len(temp_hex) >= 4:
            display_temp = int(temp_hex[:4], 16)

        status = {
            "cook_mode": mode_name,
            "set_temperature_f": temp_from_mode,
            "display_temperature_f": display_temp,
        }
        logger.info(f"Oven status: {status}")
        return status

    # ─── WebSocket-based control ─────────────────────────────────────────

    async def connect_websocket(self) -> bool:
        """Connect to the SmartHQ WebSocket for real-time control.

        The endpoint is obtained dynamically from GET /v1/websocket.
        """
        if not self.access_token:
            logger.error("Not authenticated")
            return False

        result = await self._get_ws_endpoint()
        if not result:
            return False

        ws_endpoint, _ = result
        ssl_ctx = ssl.create_default_context()

        try:
            self.ws = await self.session.ws_connect(ws_endpoint, ssl=ssl_ctx, heartbeat=30)
            logger.info("WebSocket connected!")

            # Subscribe to all appliance ERD updates
            subscribe_msg = {
                "kind": "websocket#subscribe",
                "action": "subscribe",
                "resources": ["/appliance/*/erd/*"],
            }
            await self.ws.send_json(subscribe_msg)
            logger.info("Subscribed to appliance updates")
            return True

        except Exception as e:
            logger.error(f"WebSocket connection failed: {e}")
            return False

    async def ws_write_erd(self, appliance_id: str, erd_code: str, value: str) -> bool:
        """Write an ERD value via WebSocket.

        Message format from decompiled SendApiRequestWithBody.java:
        {
            "kind": "websocket#api",
            "action": "api",
            "host": "api.brillion.geappliances.com",
            "method": "POST",
            "path": "/v1/appliance/{id}/erd/{erd}",
            "id": "{uuid}",
            "body": { ... }
        }
        """
        if not self.ws:
            logger.error("WebSocket not connected, falling back to REST")
            return await self.write_erd(appliance_id, erd_code, value)

        msg = {
            "kind": "websocket#api",
            "action": "api",
            "host": API_HOST,
            "method": "POST",
            "path": f"/v1/appliance/{appliance_id}/erd/{erd_code}",
            "id": f"{appliance_id}-setErd-{erd_code}",
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

    async def ws_list_appliances(self) -> bool:
        """List appliances via WebSocket."""
        if not self.ws:
            return False

        msg = {
            "kind": "websocket#api",
            "action": "api",
            "host": API_HOST,
            "method": "GET",
            "path": "/v1/appliance",
            "id": "List-appliances",
        }
        await self.ws.send_json(msg)
        return True

    async def ws_get_all_erds(self, appliance_id: str) -> bool:
        """Get all ERD values for an appliance via WebSocket."""
        if not self.ws:
            return False

        msg = {
            "kind": "websocket#api",
            "action": "api",
            "host": API_HOST,
            "method": "GET",
            "path": f"/v1/appliance/{appliance_id}/erd",
            "id": f"{appliance_id}-allErd",
        }
        await self.ws.send_json(msg)
        return True

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
  %(prog)s --username you@email.com --password secret --erd 0x5100 --value 01015e00000000000000000000
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
    parser.add_argument("--erd", help="Raw ERD code to read/write (e.g., 0x5100)")
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

        # Get WS endpoint to populate user_id
        await client._get_ws_endpoint()

        appliances = await client.get_appliances()
        if not appliances:
            logger.error("No appliances found on your account.")
            return 1

        if args.list:
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
