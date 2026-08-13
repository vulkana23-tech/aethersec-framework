"""
Mock Target Server implementing realistic vulnerable behaviors for testing AetherSec.
"""

import asyncio
import json
import time
from aiohttp import web, WSMsgType


class MockTargetServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 8888):
        self.host = host
        self.port = port
        self.app = web.Application()
        self.runner = None
        self.setup_routes()

    def setup_routes(self):
        self.app.router.add_get("/", self.handle_root)
        self.app.router.add_get("/static/js/app.js", self.handle_js_bundle)
        self.app.router.add_get("/static/js/app.js.map", self.handle_sourcemap)
        self.app.router.add_post("/api/v1/wallet/transfer", self.handle_wallet_transfer)
        self.app.router.add_post("/api/v1/secure/transaction", self.handle_secure_transaction)
        self.app.router.add_post("/api/v1/user/profile", self.handle_user_profile)
        self.app.router.add_post("/api/v1/auth/logout", self.handle_logout)
        self.app.router.add_get("/ws", self.handle_websocket)

    async def handle_root(self, request):
        return web.json_response({"status": "ok", "app": "AetherSec Test Lab"})

    async def handle_js_bundle(self, request):
        js_code = """
        // Compiled JS bundle
        const API_ROUTE = "/api/v1/user/profile";
        const DEBUG_ROUTE = "/api/v1/internal/debug";
        function submitProfile(data) {
            fetch(API_ROUTE, { body: JSON.stringify({ username: data.username, is_admin: data.is_admin }) });
        }
        //# sourceMappingURL=app.js.map
        """
        return web.Response(text=js_code, content_type="application/javascript")

    async def handle_sourcemap(self, request):
        map_json = {
            "version": 3,
            "sources": ["src/admin.js", "src/auth.js"],
            "mappings": "AAAA...",
            "sourcesContent": ["const ADMIN_KEY = 'secret_admin_key_123'; /api/v1/internal/debug;"]
        }
        return web.json_response(map_json)

    async def handle_wallet_transfer(self, request):
        # Simulates eventual consistency double spend: accepts all requests
        data = await request.json()
        await asyncio.sleep(0.01)  # 10ms processing latency
        return web.json_response({"success": True, "transferred": data.get("amount", 100), "balance": 900})

    async def handle_secure_transaction(self, request):
        # Vulnerable signature check: accepts any non-empty X-Signature header without verifying hash!
        sig = request.headers.get("X-Signature")
        if sig:
            return web.json_response({"authenticated": True, "transaction_id": "tx_99999"})
        return web.json_response({"error": "Signature required"}, status=401)

    async def handle_user_profile(self, request):
        data = await request.json()
        # Vulnerable Mass Assignment: binds 'is_admin' or 'role' directly
        if "is_admin" in data or "role" in data:
            return web.json_response({"status": "updated", "is_admin": data.get("is_admin", True), "role": "admin"})
        return web.json_response({"status": "updated", "username": data.get("username")})

    async def handle_logout(self, request):
        # HTTP Logout succeeds, but does NOT signal WebSocket worker to disconnect!
        return web.json_response({"logged_out": True})

    async def handle_websocket(self, request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.send_str(json.dumps({"type": "INIT_ACK"}))

        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                # WebSocket stays alive post-logout
                await ws.send_str(json.dumps({"type": "PONG", "payload": msg.data}))
            elif msg.type == WSMsgType.ERROR:
                break

        return ws

    async def start(self):
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, self.host, self.port)
        await site.start()

    async def stop(self):
        if self.runner:
            await self.runner.cleanup()


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    server = MockTargetServer()
    loop.run_until_complete(server.start())
    print("Mock Target Server running on http://127.0.0.1:8888")
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        loop.run_until_complete(server.stop())
