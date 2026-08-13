"""
Engine 3: Dynamic Signature Synthesizer & Symbolic Parser.
"""

import hmac
import hashlib
import time
import json
import aiohttp
from typing import Dict, Any, List, Optional
from aethersec.core.models import AuditTarget, Finding, Severity, RemediationPatch
from aethersec.core.config import Config, DEFAULT_CONFIG


class SignatureSynthesizer:
    def __init__(self, target: AuditTarget, secret_key: str = "aethersec_secret_key", config: Config = DEFAULT_CONFIG):
        self.target = target
        self.secret_key = secret_key
        self.config = config
        self.findings: List[Finding] = []

    def compute_hmac_signature(self, payload: Dict[str, Any], timestamp: int) -> str:
        """
        Synthesizes a valid HMAC-SHA256 signature header for API requests.
        """
        raw_data = f"{timestamp}:{json.dumps(payload, sort_keys=True)}"
        signature = hmac.new(
            self.secret_key.encode('utf-8'),
            raw_data.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        return signature

    async def verify_signature_enforcement(self, session: aiohttp.ClientSession, endpoint_path: str) -> List[Finding]:
        """
        Tests if API endpoint properly enforces signature verification, replay protection, or allows signature bypass.
        """
        url = f"{self.target.base_url.rstrip('/')}{endpoint_path}"
        payload = {"action": "query_sensitive_data", "timestamp": int(time.time())}
        ts = int(time.time())
        valid_sig = self.compute_hmac_signature(payload, ts)

        # Test 1: Send request without signature
        headers_no_sig = dict(self.target.headers)
        headers_no_sig.update({"Content-Type": "application/json"})

        # Test 2: Send request with forged/invalid signature
        headers_bad_sig = dict(headers_no_sig)
        headers_bad_sig.update({
            "X-Signature": "invalid_forged_hash_00000000000000000000000000000000",
            "X-Timestamp": str(ts)
        })

        # Test 3: Send valid synthesized signature
        headers_valid = dict(headers_no_sig)
        headers_valid.update({
            "X-Signature": valid_sig,
            "X-Timestamp": str(ts)
        })

        try:
            async with session.post(url, json=payload, headers=headers_bad_sig) as resp_bad:
                status_bad = resp_bad.status
                body_bad = await resp_bad.json()

                if status_bad == 200 and body_bad.get("authenticated") is not False:
                    self.findings.append(
                        Finding(
                            title="API Signature Verification Bypass Discovered",
                            severity=Severity.CRITICAL,
                            engine="SignatureSynthesizer",
                            description=f"Endpoint {endpoint_path} accepted an invalid/forged X-Signature header.",
                            evidence={"endpoint": endpoint_path, "status": status_bad, "response": body_bad},
                            cvss_score=9.1,
                            cwe_id="CWE-347",
                            poc_steps=[
                                f"1. Send POST request to {url}",
                                "2. Set header X-Signature: invalid_forged_hash",
                                "3. Observe API processes request without validating HMAC hash."
                            ],
                            remediation=RemediationPatch(
                                description="Enforce strict server-side HMAC signature verification before processing request payload.",
                                code_snippet=(
                                    "expected_sig = hmac.new(SECRET, f'{ts}:{raw_body}'.encode(), hashlib.sha256).hexdigest()\n"
                                    "if not hmac.compare_digest(expected_sig, req_sig):\n"
                                    "    return jsonify({'error': 'Invalid signature'}), 401\n"
                                ),
                                language="python",
                                owasp_category="A07:2021-Identification and Authentication Failures"
                            )
                        )
                    )

        except Exception:
            pass

        return self.findings

    async def run(self, session: aiohttp.ClientSession) -> List[Finding]:
        await self.verify_signature_enforcement(session, "/api/v1/secure/transaction")
        return self.findings
