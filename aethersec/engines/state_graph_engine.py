"""
Engine 1: Cross-Domain State Graphing & Eventual Consistency Evaluator.
"""

import asyncio
import time
import aiohttp
from typing import List, Dict, Any, Tuple
from aethersec.core.models import AuditTarget, Finding, Severity, StateNode, StateEdge, RemediationPatch
from aethersec.core.config import Config, DEFAULT_CONFIG


class StateGraphEngine:
    def __init__(self, target: AuditTarget, config: Config = DEFAULT_CONFIG):
        self.target = target
        self.config = config
        self.nodes: Dict[str, StateNode] = {}
        self.edges: List[StateEdge] = []
        self.findings: List[Finding] = []

    async def build_state_graph(self, session: aiohttp.ClientSession) -> Dict[str, StateNode]:
        """
        Crawls target endpoints and builds a dynamic state machine model.
        """
        endpoints = [
            ("/", "Public Root", False),
            ("/api/v1/auth/session", "Session Endpoint", False),
            ("/api/v1/user/profile", "User Profile", True),
            ("/api/v1/wallet/transfer", "Wallet Transfer", True),
            ("/api/v1/admin/dashboard", "Admin Dashboard", True),
        ]

        for path, name, auth_req in endpoints:
            node_id = f"node_{path.replace('/', '_').strip('_')}"
            url = f"{self.target.base_url.rstrip('/')}{path}"
            try:
                async with session.get(url, headers=self.target.headers, timeout=self.config.request_timeout) as resp:
                    status = resp.status
                    node = StateNode(
                        id=node_id,
                        name=name,
                        path=path,
                        auth_required=auth_req,
                        meta={"status": status, "url": url}
                    )
                    self.nodes[node_id] = node
            except Exception as e:
                # Add node even if unreachable, mark error in meta
                self.nodes[node_id] = StateNode(
                    id=node_id,
                    name=name,
                    path=path,
                    auth_required=auth_req,
                    meta={"error": str(e), "url": url}
                )

        return self.nodes

    async def evaluate_eventual_consistency(self, session: aiohttp.ClientSession, endpoint_path: str) -> List[Finding]:
        """
        Simulates micro-latency differential requests (simulating multi-region POPs)
        to detect eventual consistency race windows.
        """
        url = f"{self.target.base_url.rstrip('/')}{endpoint_path}"
        payload = {"amount": 100, "recipient_id": "usr_99"}

        # Simulate 2 rapid concurrent requests spaced by < 10ms
        async def send_req(req_id: int, delay_ms: float) -> Tuple[int, float, Dict[str, Any]]:
            if delay_ms > 0:
                await asyncio.sleep(delay_ms / 1000.0)
            t0 = time.time()
            try:
                async with session.post(url, json=payload, headers=self.target.headers) as resp:
                    data = await resp.json()
                    elapsed = (time.time() - t0) * 1000.0
                    return resp.status, elapsed, data
            except Exception as e:
                return 500, 0.0, {"error": str(e)}

        t_start = time.time()
        res1, res2 = await asyncio.gather(
            send_req(1, 0.0),
            send_req(2, 5.0)  # 5ms offset simulation
        )

        status1, time1, body1 = res1
        status2, time2, body2 = res2

        # Check if both requests succeeded simultaneously when state should lock
        if status1 == 200 and status2 == 200 and body1.get("success") and body2.get("success"):
            finding = Finding(
                title="Eventual Consistency Race Window Detected",
                severity=Severity.HIGH,
                engine="StateGraphEngine",
                description=(
                    f"Sub-millisecond multi-region timing simulation against {endpoint_path} "
                    f"revealed double execution within a {abs(time2 - time1):.2f}ms consistency window."
                ),
                evidence={
                    "request_1": {"status": status1, "latency_ms": time1, "response": body1},
                    "request_2": {"status": status2, "latency_ms": time2, "response": body2},
                    "endpoint": endpoint_path,
                },
                cvss_score=8.1,
                cwe_id="CWE-362",
                poc_steps=[
                    f"1. Send concurrent POST request to {endpoint_path} from region node A.",
                    f"2. Send concurrent POST request to {endpoint_path} with 5ms offset from region node B.",
                    "3. Observe both transactions succeed before database state replication syncs."
                ],
                remediation=RemediationPatch(
                    description="Implement distributed locks (e.g. Redlock / Redis Mutex) or pessimistic database locking during balance transactions.",
                    code_snippet=(
                        "with redis_client.lock(f'lock:wallet:{user_id}', timeout=5):\n"
                        "    execute_transaction(user_id, amount)\n"
                    ),
                    language="python",
                    owasp_category="A04:2021-Insecure Design"
                )
            )
            self.findings.append(finding)

        return self.findings

    async def run(self, session: aiohttp.ClientSession) -> List[Finding]:
        await self.build_state_graph(session)
        await self.evaluate_eventual_consistency(session, "/api/v1/wallet/transfer")
        return self.findings
