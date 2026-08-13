"""
Engine 4: Backend Class & Schema Inference Engine.
"""

import aiohttp
from typing import List, Dict, Any
from aethersec.core.models import AuditTarget, Finding, Severity, SchemaAttribute, RemediationPatch
from aethersec.core.config import Config, DEFAULT_CONFIG


class SchemaInferenceEngine:
    def __init__(self, target: AuditTarget, config: Config = DEFAULT_CONFIG):
        self.target = target
        self.config = config
        self.inferred_attributes: List[SchemaAttribute] = []
        self.findings: List[Finding] = []

    async def infer_backend_schema(self, session: aiohttp.ClientSession, endpoint_path: str) -> List[SchemaAttribute]:
        """
        Infers unmapped backend POJO / model properties by injecting type mutations
        and evaluating serialization error responses.
        """
        url = f"{self.target.base_url.rstrip('/')}{endpoint_path}"

        # Candidate privileged attributes commonly hidden in backend ORM models
        probe_attributes = ["is_admin", "role", "permissions", "discount_percentage", "internal_id"]

        for attr in probe_attributes:
            # Type mutation probe: send array instead of boolean/string to trigger type mismatch trace or reflection
            mutation_payload = {"username": "test_user", attr: ["INVALID_TYPE_PROBE"]}

            try:
                async with session.post(url, json=mutation_payload, headers=self.target.headers) as resp:
                    status = resp.status
                    body = await resp.json()

                    # Check if error message leaks field acceptance or if status indicates attribute recognition
                    resp_str = str(body).lower()

                    if attr.lower() in resp_str or status in (400, 422, 500):
                        # The backend acknowledged the field exists in its class schema
                        is_priv = attr in ["is_admin", "role", "permissions", "discount_percentage"]
                        schema_attr = SchemaAttribute(
                            name=attr,
                            inferred_type="Boolean/String",
                            is_documented=False,
                            is_privileged=is_priv,
                            confidence=0.9
                        )
                        self.inferred_attributes.append(schema_attr)

                        # Test if Mass Assignment actually works by sending valid privileged value
                        if is_priv:
                            valid_probe = {"username": "test_user", attr: True if attr == "is_admin" else "admin"}
                            async with session.post(url, json=valid_probe, headers=self.target.headers) as test_resp:
                                if test_resp.status == 200:
                                    test_data = await test_resp.json()
                                    if test_data.get("updated") or test_data.get(attr):
                                        self.findings.append(
                                            Finding(
                                                title=f"Mass Assignment Vulnerability in Backend Model Attribute '{attr}'",
                                                severity=Severity.HIGH if attr != "is_admin" else Severity.CRITICAL,
                                                engine="SchemaInferenceEngine",
                                                description=(
                                                    f"Backend class schema for {endpoint_path} accepts unmapped privileged property '{attr}' "
                                                    "without DTO boundary filtering."
                                                ),
                                                evidence={"endpoint": endpoint_path, "accepted_attribute": attr, "response": test_data},
                                                cvss_score=8.6,
                                                cwe_id="CWE-915",
                                                poc_steps=[
                                                    f"1. Send POST request to {endpoint_path}",
                                                    f"2. Include unmapped attribute in JSON body: \"{attr}\": \"admin\"",
                                                    f"3. Observe server binds attribute directly into ORM model."
                                                ],
                                                remediation=RemediationPatch(
                                                    description="Use strict Data Transfer Objects (DTOs) with explicit field whitelisting (e.g. Pydantic / Jackson DTOs).",
                                                    code_snippet=(
                                                        "class UserProfileDTO(BaseModel):\n"
                                                        "    username: str\n"
                                                        "    # Exclude privileged fields like is_admin, role from DTO\n"
                                                    ),
                                                    language="python",
                                                    owasp_category="A01:2021-Broken Access Control"
                                                )
                                            )
                                        )

            except Exception:
                pass

        return self.inferred_attributes

    async def run(self, session: aiohttp.ClientSession) -> List[Finding]:
        await self.infer_backend_schema(session, "/api/v1/user/profile")
        return self.findings
