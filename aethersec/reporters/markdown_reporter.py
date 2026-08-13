"""
Markdown Report Generator for AetherSec.
"""

from typing import List
from aethersec.core.models import Finding, ChainFinding, AuditTarget


class MarkdownReporter:
    def __init__(self, target: AuditTarget):
        self.target = target

    def generate_report(self, findings: List[Finding], chains: List[ChainFinding] = None) -> str:
        chains = chains or []

        # Count severities
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1
        for c in chains:
            sev_counts[c.severity.value] = sev_counts.get(c.severity.value, 0) + 1

        md = []
        md.append(f"# AetherSec Audit Report - {self.target.base_url}")
        md.append("")
        md.append("## Executive Summary")
        md.append("")
        md.append(f"**Target URL:** `{self.target.base_url}`  ")
        md.append(f"**Total Findings:** {len(findings) + len(chains)}  ")
        md.append("")
        md.append("| Severity | Count |")
        md.append("| :--- | :--- |")
        md.append(f"| 🚨 **CRITICAL** | {sev_counts['CRITICAL']} |")
        md.append(f"| 🟠 **HIGH** | {sev_counts['HIGH']} |")
        md.append(f"| 🟡 **MEDIUM** | {sev_counts['MEDIUM']} |")
        md.append(f"| 🔵 **LOW** | {sev_counts['LOW']} |")
        md.append("")

        md.append("## Architecture & State Machine Diagram")
        md.append("")
        md.append("```mermaid")
        md.append("graph TD")
        md.append("    A[Audit Target] --> B[AST & Compiler Analysis]")
        md.append("    A --> C[State Graph & Consistency Engine]")
        md.append("    A --> D[Backend Schema Inference]")
        md.append("    A --> E[Multi-Protocol Session Monitor]")
        md.append("    B & C & D & E --> F[Subagent Chaining Swarm]")
        md.append("```")
        md.append("")

        if chains:
            md.append("## Synthesized Vulnerability Chains (Multi-Step)")
            md.append("")
            for idx, chain in enumerate(chains, 1):
                md.append(f"### Chain #{idx}: {chain.title}")
                md.append(f"**Severity:** `{chain.severity.value}` | **Combined CVSS:** `{chain.combined_cvss}`")
                md.append("")
                md.append(f"> [!CAUTION]")
                md.append(f"> {chain.chain_description}")
                md.append("")
                md.append("#### End-to-End Proof of Concept Steps:")
                for step in chain.full_poc:
                    md.append(f"- {step}")
                md.append("")
                md.append("#### Defensive Remediation:")
                md.append(f"**Strategy:** {chain.remediation.description}")
                md.append(f"```{chain.remediation.language}")
                md.append(chain.remediation.code_snippet)
                md.append("```")
                md.append("---")
                md.append("")

        md.append("## Detailed Audit Findings")
        md.append("")
        for idx, f in enumerate(findings, 1):
            md.append(f"### Finding #{idx}: {f.title}")
            md.append(f"**Engine:** `{f.engine}` | **Severity:** `{f.severity.value}` | **CVSS:** `{f.cvss_score}` | **CWE:** `{f.cwe_id}`")
            md.append("")
            md.append(f"> [!IMPORTANT]")
            md.append(f"> {f.description}")
            md.append("")
            md.append("#### Proof of Concept:")
            for step in f.poc_steps:
                md.append(f"1. {step}")
            md.append("")
            md.append("#### Remediation Patch:")
            md.append(f"**OWASP Category:** `{f.remediation.owasp_category}`")
            md.append(f"```{f.remediation.language}")
            md.append(f.remediation.code_snippet)
            md.append("```")
            md.append("")
            md.append("---")
            md.append("")

        return "\n".join(md)
