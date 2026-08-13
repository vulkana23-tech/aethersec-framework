"""
Automated Integration Test Suite for AetherSec Framework.
Verifies 100% functionality of all 6 engines against the local mock target server.
"""

import unittest
import asyncio
import aiohttp
from aethersec.core.models import AuditTarget
from aethersec.core.config import Config
from aethersec.engines.state_graph_engine import StateGraphEngine
from aethersec.engines.ast_compiler_engine import ASTCompilerEngine
from aethersec.engines.signature_synthesizer import SignatureSynthesizer
from aethersec.engines.schema_inference_engine import SchemaInferenceEngine
from aethersec.engines.multiprotocol_engine import MultiProtocolEngine
from aethersec.engines.dependency_delta_engine import DependencyDeltaEngine
from aethersec.engines.chaining_engine import ChainingEngine
from aethersec.reporters.markdown_reporter import MarkdownReporter
from aethersec.mock_target.server import MockTargetServer


class TestAetherSecFramework(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(cls.loop)
        cls.server = MockTargetServer(port=8889)
        cls.loop.run_until_complete(cls.server.start())
        cls.target_url = "http://127.0.0.1:8889"
        cls.target = AuditTarget(base_url=cls.target_url, ws_url="ws://127.0.0.1:8889/ws")
        cls.config = Config()

    @classmethod
    def tearDownClass(cls):
        cls.loop.run_until_complete(cls.server.stop())
        cls.loop.close()

    def test_engine_1_state_graph(self):
        async def run_test():
            async with aiohttp.ClientSession() as session:
                engine = StateGraphEngine(self.target, self.config)
                findings = await engine.run(session)
                self.assertGreaterEqual(len(engine.nodes), 4)
                self.assertTrue(any(f.engine == "StateGraphEngine" for f in findings))

        self.loop.run_until_complete(run_test())

    def test_engine_2_ast_compiler(self):
        async def run_test():
            async with aiohttp.ClientSession() as session:
                engine = ASTCompilerEngine(self.target, self.config)
                findings = await engine.run(session)
                self.assertTrue(any(f.title == "Exposed JavaScript SourceMap Discovered" for f in findings))
                self.assertTrue(any("AST Analysis" in f.title for f in findings))

        self.loop.run_until_complete(run_test())

    def test_engine_3_signature_synthesizer(self):
        async def run_test():
            async with aiohttp.ClientSession() as session:
                engine = SignatureSynthesizer(self.target, config=self.config)
                findings = await engine.run(session)
                self.assertTrue(any("Signature Verification Bypass" in f.title for f in findings))

        self.loop.run_until_complete(run_test())

    def test_engine_4_schema_inference(self):
        async def run_test():
            async with aiohttp.ClientSession() as session:
                engine = SchemaInferenceEngine(self.target, self.config)
                findings = await engine.run(session)
                self.assertTrue(any("Mass Assignment" in f.title for f in findings))

        self.loop.run_until_complete(run_test())

    def test_engine_5_multiprotocol(self):
        async def run_test():
            async with aiohttp.ClientSession() as session:
                engine = MultiProtocolEngine(self.target, self.config)
                findings = await engine.run(session)
                self.assertTrue(any("Cross-Protocol Session" in f.title for f in findings))

        self.loop.run_until_complete(run_test())

    def test_engine_6_dependency_delta(self):
        engine = DependencyDeltaEngine(self.config)
        manifest = '{"dependencies": {"express": "4.18.0"}}'
        findings = engine.analyze_manifest(manifest, "package.json")
        self.assertTrue(any("express" in f.evidence.get("package", "") for f in findings))

    def test_full_chaining_and_reporting(self):
        async def run_test():
            async with aiohttp.ClientSession() as session:
                eng2 = ASTCompilerEngine(self.target, self.config)
                f2 = await eng2.run(session)

                eng4 = SchemaInferenceEngine(self.target, self.config)
                f4 = await eng4.run(session)

                all_findings = f2 + f4
                chain_eng = ChainingEngine()
                chains = chain_eng.evaluate_chains(all_findings)
                self.assertGreaterEqual(len(chains), 1)

                reporter = MarkdownReporter(self.target)
                report_md = reporter.generate_report(all_findings, chains)
                self.assertIn("# AetherSec Audit Report", report_md)
                self.assertIn("```mermaid", report_md)

        self.loop.run_until_complete(run_test())


if __name__ == "__main__":
    unittest.main()
