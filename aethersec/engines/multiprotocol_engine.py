"""
Engine 5: Multi-Protocol State Convergence Monitor.
"""

import asyncio
import json
import aiohttp
import websockets
from typing import List, Dict, Any
from aethersec.core.models import AuditTarget, Finding, Severity, ProtocolEvent, RemediationPatch
from aethersec.core.config import Config, DEFAULT_CONFIG


class MultiProtocolEngine:
    def __init__(self, target: AuditTarget, config: Config = DEFAULT_CONFIG):
        self.target = target
        self.config = config
        self.events: List[ProtocolEvent] = []
        self.findings: List[Finding] = []

    async def audit_websocket_session_revocation(self, session: aiohttp.ClientSession) -> List[Finding]:
        """
        Audits if invalidating an HTTP session automatically closes active WebSocket channels (Cross-Protocol Session Binding).
        """
        ws_url = self.target.ws_url or self.target.base_url.replace("http://", "ws://").replace("https://", "wss://") + "/ws"
        logout_url = f"{self.target.base_url.rstrip('/')}/api/v1/auth/logout"

        try:
            # 1. Establish persistent WebSocket connection
            async with websockets.connect(ws_url) as ws:
                # Receive greeting or connection ack
                init_msg = await asyncio.wait_for(ws.recv(), timeout=3.0)
                self.events.append(ProtocolEvent(protocol="WS", event_type="CONNECTED", payload={"msg": init_msg}))

                # 2. Trigger HTTP Logout session invalidation while WebSocket is open
                async with session.post(logout_url, headers=self.target.headers) as resp:
                    status = resp.status
                    self.events.append(ProtocolEvent(protocol="HTTP", event_type="LOGOUT", payload={"status": status}))

                # 3. Try sending a WebSocket message post-HTTP logout
                ping_payload = json.dumps({"action": "ping_data_stream"})
                await ws.send(ping_payload)

                try:
                    ws_resp = await asyncio.wait_for(ws.recv(), timeout=3.0)
                    self.events.append(ProtocolEvent(protocol="WS", event_type="MESSAGE_RECEIVED", payload={"resp": ws_resp}))

                    # If WebSocket responds post-HTTP logout, session invalidation across protocols failed!
                    finding = Finding(
                        title="Cross-Protocol Session Revocation Failure (WebSocket / HTTP Desync)",
                        severity=Severity.HIGH,
                        engine="MultiProtocolEngine",
                        description=(
                            "Invalidating the HTTP session via POST /api/v1/auth/logout failed to terminate "
                            "open WebSocket channels, allowing persistent unauthorized socket communication."
                        ),
                        evidence={
                            "ws_url": ws_url,
                            "http_logout_status": status,
                            "ws_post_logout_response": ws_resp
                        },
                        cvss_score=7.7,
                        cwe_id="CWE-613",
                        poc_steps=[
                            f"1. Connect to WebSocket stream at {ws_url}",
                            f"2. Trigger HTTP logout request to {logout_url}",
                            "3. Send frames over open WebSocket channel.",
                            "4. Observe WebSocket connection remains active and processes commands."
                        ],
                        remediation=RemediationPatch(
                            description="Implement central session event bus (e.g. Redis Pub/Sub) to broadcast disconnect signals to WebSocket workers upon HTTP session termination.",
                            code_snippet=(
                                "# On HTTP Logout:\n"
                                "redis_client.publish('session_revoked', json.dumps({'session_id': session_id}))\n\n"
                                "# On WS Worker:\n"
                                "if message['session_id'] == current_ws.session_id:\n"
                                "    await current_ws.close(code=4001, reason='Session Revoked')\n"
                            ),
                            language="python",
                            owasp_category="A07:2021-Identification and Authentication Failures"
                        )
                    )
                    self.findings.append(finding)

                except asyncio.TimeoutError:
                    # Connection closed properly or stopped responding
                    pass

        except Exception as e:
            # Handle mock server connection or socket errors gracefully
            pass

        return self.findings

    async def run(self, session: aiohttp.ClientSession) -> List[Finding]:
        await self.audit_websocket_session_revocation(session)
        return self.findings
