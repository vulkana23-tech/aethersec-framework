# AetherSec: Next-Gen AI Defensive Security Auditing & Bug Bounty Framework

AetherSec is a modular, production-grade defensive security auditing framework engineered around 6 AI-native methodologies for deep vulnerability detection, state desynchronization analysis, and automated remediation generation.

---

## The 6 Core Audit Engines

1. **State Graph & Eventual Consistency Evaluator (`state_graph_engine.py`)**
   - Builds dynamic state machine models of targets.
   - Evaluates sub-millisecond multi-region timing differentials to detect eventual consistency double-spend/race windows.

2. **AST & Compiler Artifact Extractor (`ast_compiler_engine.py`)**
   - Parses JavaScript ASTs and Sourcemaps to uncover unlinked internal API endpoints and hidden payload parameters.

3. **Dynamic Signature Synthesizer (`signature_synthesizer.py`)**
   - Synthesizes valid HMAC/X-Signature headers dynamically to validate signature enforcement and bypass vulnerabilities.

4. **Backend Class & Schema Inference Engine (`schema_inference_engine.py`)**
   - Injects type mutations and measures serialization error entropy to infer unmapped backend class attributes (Mass Assignment / BOLA).

5. **Multi-Protocol Session Convergence Monitor (`multiprotocol_engine.py`)**
   - Audits state synchronization between HTTP/2 and WebSockets (e.g. verifying if HTTP session invalidation terminates open WebSockets).

6. **Silent Fix Dependency Delta Analyzer (`dependency_delta_engine.py`)**
   - Correlates dependency manifests against silent security commit fixes prior to public CVE assignment.

---

## Quick Start

### Installation
```bash
pip install -r requirements.txt
```

### Running the Test Suite
```bash
python -m unittest tests/test_all_engines.py
```

### Running a Full Audit
1. Start local test lab server:
```bash
python -m aethersec.cli serve-mock --port 8888
```

2. Run audit against mock target:
```bash
python -m aethersec.cli audit --target http://127.0.0.1:8888 --output-report report.md
```
