"""
AetherSec Command Line Interface.
"""

import asyncio
import argparse
import sys
import aiohttp
from typing import List

from aethersec.core.models import AuditTarget, Finding
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


async def run_full_audit(target_url: str, output_report_path: str = None) -> List[Finding]:
    print(f"\n=======================================================")
    print(f"🚀 AetherSec Next-Gen AI Defensive Audit Engine v1.0.0")
    print(f"=======================================================")
    print(f"Target: {target_url}\n")

    target = AuditTarget(base_url=target_url)
    config = Config()
    all_findings = []

    async with aiohttp.ClientSession() as session:
        # Engine 1: State Graph & Eventual Consistency
        print("🔍 [Engine 1/6] Running State Graph & Eventual Consistency Evaluator...")
        eng1 = StateGraphEngine(target, config)
        f1 = await eng1.run(session)
        all_findings.extend(f1)
        print(f"   └── Found {len(f1)} state/timing findings.")

        # Engine 2: AST & Compiler Artifact Extractor
        print("🔍 [Engine 2/6] Running AST & Compiler Artifact Extractor...")
        eng2 = ASTCompilerEngine(target, config)
        f2 = await eng2.run(session)
        all_findings.extend(f2)
        print(f"   └── Found {len(f2)} AST/sourcemap findings.")

        # Engine 3: Dynamic Signature Synthesizer
        print("🔍 [Engine 3/6] Running Dynamic Signature Synthesizer...")
        eng3 = SignatureSynthesizer(target, config=config)
        f3 = await eng3.run(session)
        all_findings.extend(f3)
        print(f"   └── Found {len(f3)} signature enforcement findings.")

        # Engine 4: Backend Class & Schema Inference Engine
        print("🔍 [Engine 4/6] Running Backend Class & Schema Inference Engine...")
        eng4 = SchemaInferenceEngine(target, config)
        f4 = await eng4.run(session)
        all_findings.extend(f4)
        print(f"   └── Found {len(f4)} mass assignment/schema findings.")

        # Engine 5: Multi-Protocol State Convergence Monitor
        print("🔍 [Engine 5/6] Running Multi-Protocol Session Monitor...")
        eng5 = MultiProtocolEngine(target, config)
        f5 = await eng5.run(session)
        all_findings.extend(f5)
        print(f"   └── Found {len(f5)} cross-protocol session findings.")

        # Engine 6: Dependency Delta Intelligence Analyzer
        print("🔍 [Engine 6/6] Running Silent Fix Dependency Delta Engine...")
        eng6 = DependencyDeltaEngine(config)
        sample_manifest = '{"dependencies": {"express": "4.18.0", "jsonwebtoken": "9.0.0"}}'
        f6 = eng6.analyze_manifest(sample_manifest, "package.json")
        all_findings.extend(f6)
        print(f"   └── Found {len(f6)} silent fix dependency findings.")

        # Synthesize Vulnerability Chains
        print("\n🔗 [Subagent Swarm] Synthesizing Vulnerability Chains...")
        chain_engine = ChainingEngine()
        chains = chain_engine.evaluate_chains(all_findings)
        print(f"   └── Synthesized {len(chains)} critical multi-step chains.")

        # Generate Markdown Report
        reporter = MarkdownReporter(target)
        report_content = reporter.generate_report(all_findings, chains)

        if output_report_path:
            with open(output_report_path, "w", encoding="utf-8") as f:
                f.write(report_content)
            print(f"\n✅ Audit Complete! Markdown report saved to: {output_report_path}")

        print(f"Total Vulnerabilities Detected: {len(all_findings) + len(chains)}\n")
        return all_findings


def main():
    parser = argparse.ArgumentParser(description="AetherSec Security Audit Framework")
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # Command: audit
    audit_parser = subparsers.add_parser("audit", help="Run full audit against target URL")
    audit_parser.add_argument("--target", required=True, help="Target URL (e.g. http://127.0.0.1:8888)")
    audit_parser.add_argument("--output-report", default="aethersec_report.md", help="Output Markdown report path")

    # Command: serve-mock
    serve_parser = subparsers.add_parser("serve-mock", help="Start local mock target server for testing")
    serve_parser.add_argument("--port", type=int, default=8888, help="Server port")

    args = parser.parse_args()

    if args.command == "audit":
        asyncio.run(run_full_audit(args.target, args.output_report))
    elif args.command == "serve-mock":
        print(f"Starting AetherSec Mock Target Server on http://127.0.0.1:{args.port}...")
        server = MockTargetServer(port=args.port)
        loop = asyncio.get_event_loop()
        loop.run_until_complete(server.start())
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            loop.run_until_complete(server.stop())
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
