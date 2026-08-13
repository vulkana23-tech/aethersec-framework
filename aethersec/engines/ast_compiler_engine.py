"""
Engine 2: AST & Transpilation Artifact Extractor.
"""

import re
import aiohttp
from typing import List, Dict, Any, Set
from aethersec.core.models import AuditTarget, Finding, Severity, ASTArtifact, RemediationPatch
from aethersec.core.config import Config, DEFAULT_CONFIG


class ASTCompilerEngine:
    def __init__(self, target: AuditTarget, config: Config = DEFAULT_CONFIG):
        self.target = target
        self.config = config
        self.artifacts: List[ASTArtifact] = []
        self.findings: List[Finding] = []

    def extract_unlinked_routes(self, js_content: str) -> Set[str]:
        """
        Extracts internal API routes from JavaScript bundle AST regex patterns.
        """
        route_pattern = re.compile(r'["\'](/api/v\d+/[a-zA-Z0-9_\-/]+)["\']')
        matches = route_pattern.findall(js_content)
        return set(matches)

    def extract_hidden_params(self, js_content: str) -> Set[str]:
        """
        Extracts unlinked internal parameter names from JS bundle AST.
        """
        param_pattern = re.compile(r'(?:params|body|payload)\.([a-zA-Z0-9_]+)')
        matches = param_pattern.findall(js_content)
        # Filter common words
        common_words = {"length", "toString", "slice", "forEach", "map", "filter", "data", "json"}
        return set(m for m in matches if m not in common_words)

    async def analyze_js_bundle(self, session: aiohttp.ClientSession, js_url: str) -> ASTArtifact:
        """
        Fetches and parses JS bundle for compiler/bundler artifacts and sourcemaps.
        """
        unlinked = set()
        hidden_params = set()
        sourcemap_found = False

        try:
            async with session.get(js_url, headers=self.target.headers) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    unlinked = self.extract_unlinked_routes(content)
                    hidden_params = self.extract_hidden_params(content)

                    # Check for sourcemap comment
                    if "sourceMappingURL=" in content:
                        sourcemap_found = True

            # Try fetching sourcemap if present
            if sourcemap_found:
                map_url = f"{js_url}.map"
                async with session.get(map_url, headers=self.target.headers) as map_resp:
                    if map_resp.status == 200:
                        map_content = await map_resp.text()
                        unlinked.update(self.extract_unlinked_routes(map_content))
                        hidden_params.update(self.extract_hidden_params(map_content))

                        finding = Finding(
                            title="Exposed JavaScript SourceMap Discovered",
                            severity=Severity.MEDIUM,
                            engine="ASTCompilerEngine",
                            description=f"Publicly accessible SourceMap found at {map_url}, leaking uncompiled backend routes and parameters.",
                            evidence={"sourcemap_url": map_url, "extracted_routes": list(unlinked)},
                            cvss_score=5.3,
                            cwe_id="CWE-540",
                            poc_steps=[
                                f"1. Request {js_url}",
                                f"2. Extract sourceMappingURL directive pointing to {map_url}",
                                "3. Download and unpack original unminified source code tree."
                            ],
                            remediation=RemediationPatch(
                                description="Disable production SourceMap generation in your build bundler (Webpack/Vite/SWC).",
                                code_snippet="// vite.config.js\nexport default {\n  build: {\n    sourcemap: false\n  }\n}",
                                language="javascript",
                                owasp_category="A05:2021-Security Misconfiguration"
                            )
                        )
                        self.findings.append(finding)

        except Exception as e:
            pass

        artifact = ASTArtifact(
            file_name=js_url,
            unlinked_endpoints=list(unlinked),
            hidden_parameters=list(hidden_params),
            sourcemap_found=sourcemap_found
        )
        self.artifacts.append(artifact)

        # Flag unlinked endpoints found
        internal_admin_routes = [r for r in unlinked if "admin" in r or "internal" in r or "debug" in r]
        if internal_admin_routes:
            self.findings.append(
                Finding(
                    title="Unlinked Internal API Endpoint Discovered via AST Analysis",
                    severity=Severity.HIGH,
                    engine="ASTCompilerEngine",
                    description=f"AST parsing of {js_url} revealed internal/admin endpoints not linked in application UI.",
                    evidence={"bundle_url": js_url, "internal_routes": internal_admin_routes},
                    cvss_score=7.5,
                    cwe_id="CWE-200",
                    poc_steps=[
                        f"1. Download frontend JS bundle {js_url}",
                        "2. Parse AST nodes for route string literals.",
                        f"3. Send HTTP GET to discovered unlinked route: {internal_admin_routes[0]}"
                    ],
                    remediation=RemediationPatch(
                        description="Remove dead administrative code paths from production JS builds and enforce server-side RBAC on all internal routes.",
                        code_snippet="@app.route('/api/v1/internal/debug')\n@require_admin_auth\ndef internal_debug():\n    pass",
                        language="python",
                        owasp_category="A01:2021-Broken Access Control"
                    )
                )
            )

        return artifact

    async def run(self, session: aiohttp.ClientSession) -> List[Finding]:
        # Crawl main target HTML page to dynamically discover JavaScript scripts & bundles
        discovered_js = set()
        base_url = self.target.base_url.rstrip('/')

        try:
            async with session.get(base_url, headers=self.target.headers) as resp:
                if resp.status == 200:
                    html_content = await resp.text()
                    script_matches = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html_content, re.IGNORECASE)
                    preload_matches = re.findall(r'<link[^>]+href=["\']([^"\']+\.js[^"\']*)["\']', html_content, re.IGNORECASE)

                    for src in script_matches + preload_matches:
                        if src.startswith("http://") or src.startswith("https://"):
                            discovered_js.add(src)
                        elif src.startswith("/"):
                            discovered_js.add(f"{base_url}{src}")
                        else:
                            discovered_js.add(f"{base_url}/{src}")
        except Exception:
            pass

        if not discovered_js:
            discovered_js.add(f"{base_url}/static/js/app.js")

        for js_url in list(discovered_js)[:5]:  # Process top 5 bundles
            await self.analyze_js_bundle(session, js_url)

        return self.findings

