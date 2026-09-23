# ULPF-X: Universal Log Pre-processing Framework
> **Autonomous, High-Throughput, Contract-First Security Telemetry Pipeline**  
> **System Status:** Stage 21 (Demonstration Polish) • 23 / 23 Subsystems Operational • 300 Automated Tests (100% Green)

[![Air-Gap Profile](https://img.shields.io/badge/Air--Gap%20Profile-Hermetic%20%2F%20Zero%20Outbound-emerald?style=for-the-badge&logo=shield)](file:///tests/airgap/test_airgap.py)
[![Subsystems](https://img.shields.io/badge/Subsystems-23%20%2F%2023%20Verified-blue?style=for-the-badge&logo=checkmarx)](file:///scripts/audit.py)
[![Automated Tests](https://img.shields.io/badge/Tests-300%20Passing%20(0%20Failed)-brightgreen?style=for-the-badge&logo=pytest)](file:///Makefile)
[![Throughput](https://img.shields.io/badge/Throughput->48,000%20EPS%20Measured-orange?style=for-the-badge&logo=speedtest)](file:///ml/benchmark/run_bench.py)
[![DPS Ratio](https://img.shields.io/badge/Detection%20Preservation-1.00%20DPS%20Ratio-purple?style=for-the-badge&logo=target)](file:///packages/detection-contracts)
[![Contracts](https://img.shields.io/badge/Contracts-10%20JSON%20Schemas%20(Draft--07)-cyan?style=for-the-badge&logo=json)](file:///packages/contracts)

---

## Executive Summary

Modern Security Operations Centers (SOCs) and sovereign intelligence infrastructure process billions of heterogeneous security events every day. Traditional log pre-processing pipelines suffer from six systemic vulnerabilities:

1. **Destructive Ingestion:** Raw log strings are prematurely parsed or modified, destroying court-admissible forensic evidence.
2. **Dynamic Code Vulnerabilities:** Ingestion parsers rely on brittle regular expressions and unsafe interpreters (`eval`, dynamic imports) vulnerable to Regular Expression Denial of Service (ReDoS) and remote exploit execution.
3. **Vendor Schema Bias:** Ingest gateways forcibly convert logs directly into proprietary formats (Elastic ECS or Splunk/AWS OCSF), creating vendor lock-in and corrupting source truth.
4. **Zero Forensic Provenance:** Downstream SIEM tables display normalized IP addresses and timestamps without cryptographic lineage proving which exact raw byte offset produced those values.
5. **Silent Schema & Semantic Drift:** Upstream software updates silently alter field semantics (e.g., reversing `allow`/`block` actions or converting port numbers from integers to strings), silently blinding detection rules.
6. **Cloud & External Dependency Risks:** Telemetry pipelines depend on public cloud endpoints, remote LLM APIs, or container registries that violate air-gapped sovereign security boundaries.

**ULPF-X (Universal Log Pre-processing Framework)** solves these challenges through an autonomous, contract-first architecture combining a high-performance **Go Data Plane** with a sandboxed **Python Intelligence & Assurance Plane**. ULPF-X guarantees **100% raw byte preservation**, **court-admissible forensic lineage**, **deterministic firewall quarantine**, **zero-cloud local ML profiling**, **100% Detection Preservation Score (DPS)**, and **safe self-healing with 5 mandatory refusal gates**.

---

## ⚡ Universal 1-Click Quickstart (Run Anywhere)

ULPF-X is distributed as a standalone, zero-dependency release package. You do not need to configure complex environments, clone repositories, or install public cloud toolchains—simply download, extract, and click install.

### Step 1: Download & Extract
1. Download the latest standalone release zip archive from **GitHub Releases**.
2. Extract / Unzip the archive to any folder on your machine.
3. Open the extracted directory.

---

### Step 2: One-Click Installation

#### 🪟 Windows (Double-Click or Command Prompt)
Simply **double-click `install.bat`** in the extracted directory!  
*(Or open Command Prompt / PowerShell in the folder and execute `install.bat`)*

* The batch launcher automatically detects **Git Bash** if installed (`git-bash.exe`), or seamlessly falls back to the native Windows PowerShell installer with execution policy bypass.
* Deploys the standalone engine into `%USERPROFILE%\.ulpx` (with automatic timestamped backups of any previous installation).
* Registers the engine directory in your Windows User `PATH` so global CLI commands are immediately available.

#### 🐧 / 🍏 Linux, macOS, or WSL / Git Bash
Open your terminal in the extracted directory and run:
```bash
chmod +x install.sh && ./install.sh
source ~/.bashrc   # or: source ~/.zshrc (on macOS / zsh)
```

---

### Step 3: Verify & Run

Once installed, launch the verified system CLI commands directly from any terminal window:

1. **Execute Continuous Security Audit:**
   ```bash
   ulpx-test
   # or from repository root:
   make audit
   ```
   *Executes all 23 subsystems (300 tests), renders the executive cyber-grade terminal dashboard, exports a certified Telemetry Passport, and seals execution with a cryptographic SHA-256 digest in ~10 seconds.*

2. **Launch Interactive Demonstration:**
   ```bash
   ulpx
   # or from repository root:
   make demo
   ```
   *Interactive live console demonstrating all 6 core architectural pillars with clean-state resets.*

3. **Sub-second Deep-Dive Inspection:**
   ```bash
   make inspect-10    # Subsystem 10: Detection Preservation Gate (DPS = 1.00)
   make inspect-4     # Subsystem 4: Telemetry Firewall ReDoS & Quarantine Gate
   make inspect-18    # Subsystem 18: Semantic Drift & Action Inversion Gate
   ```

---

## 🖥️ System Command-Line Reference

| Action | Universal CLI Shortcut | Direct Shell / Make Command | Description |
|:---|:---|:---|:---|
| **Continuous Security Audit** | `ulpx-test` | `make audit`<br>`python3 scripts/audit.py` | **Primary Test & Verification Suite:** Validates all 23 subsystems (300 tests), exports certified Telemetry Passport, and emits SHA-256 seal. |
| **Interactive Live Demo** | `ulpx` | `make demo`<br>`python3 scripts/demo.py` | Interactive terminal console demonstrating the 6 core architectural pillars with clean-state resets. |
| **Deep-Dive Subsystem Inspection** | — | `make inspect-<1-23>`<br>`python3 scripts/audit.py <#>` | Sub-second targeted execution of any single subsystem without running the full test suite. |
| **List Inspection Targets** | — | `python3 scripts/audit.py list` | Displays numbered index, layer, and scope guard for all 23 subsystems. |
| **Empirical Benchmark** | — | `make bench` | Runs high-load empirical throughput benchmark (>48,000 EPS) capturing hardware specs and latencies. |
| **Contract Schema Validation** | — | `make test-contracts` | Validates all 10 JSON Schema contracts using pure standard library (zero app dependencies). |
| **Hermetic Air-Gap Gate** | — | `make test-airgap` | Proves zero outbound network sockets, zero remote cloud calls, and zero external DNS lookups. |

---

## 👥 Team Workstream Division & Architecture

The ULPF-X architecture is divided into three distinct workstreams to ensure modularity, separation of concerns, and clean contract boundaries:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                               ULPF-X SYSTEM ARCHITECTURE                               │
├────────────────────────────┬─────────────────────────────┬─────────────────────────────┤
│        Workstream A        │        Workstream B         │        Workstream C         │
│     (Go Data Plane)        │(Python Intelligence Plane)  │    (Platform & Delivery)    │
│      Kalpesh Karnawat      │      Agastya Sancheti       │       Sachi Bimbad          │
├────────────────────────────┼─────────────────────────────┼─────────────────────────────┤
│ • Ingest Gateway (Stg 1)   │ • Unknown Source Profiler 7 │ • JSON Schemas (Stage 0)    │
│ • Telemetry Firewall (2)   │ • Semantic Field Mapper (8) │ • Air-Gap Gate (Stage 20)   │
│ • Parser Runtime DSL (3)   │ • Local AI Assist Engine (9)│ • Demonstration Rehearsal 21│
│ • ULPF-IR Normalizer (4)   │ • Spec Compiler & Fuzzer 10 │ • Continuous Audit Dashboard│
│ • Forensic Lineage (5)     │ • Empirical Validation (11) │ • CLI Deep-Dive Inspector   │
│ • ECS & OCSF Exporters (6) │ • Detection Contracts (12)  │ • Universal Installers      │
│ • Detection Runtime (12)   │ • DPS Metric Calculator (13)│   (install.bat/install.sh)  │
│ • High-Throughput Engine   │ • Telemetry Passport (14)   │ • Distribution Packaging    │
│   (>48,000 EPS Go Hotpath) │ • Structural Drift (15)     │                             │
│                            │ • Semantic Drift (16)       │                             │
│                            │ • Shadow Dual-Execution (17)│                             │
│                            │ • Safe Self-Healing (18)    │                             │
│                            │ • Benchmark Harness (19)    │                             │
└────────────────────────────┴─────────────────────────────┴─────────────────────────────┘
```

---

## 🏛️ The 6 Core Architectural Pillars

```
                                  UNTRUSTED TELEMETRY STREAM
                                               │
                                               ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ PILLAR 2: DETERMINISTIC TELEMETRY FIREWALL (Go)                                        │
│ Enforces 64 KiB ceiling • 32 nesting levels • 512 fields • 50ms timeout • Sanitization │
│ Malformed / Exploit Payloads ──▶ QUARANTINE STORE (Verbatim byte preservation)         │
└──────────────────────────────────────┬─────────────────────────────────────────────────┘
                                       │ Validated Bytes
                                       ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ PILLAR 1: LOSSLESS INGESTION & IMMUTABLE STORAGE (Go)                                  │
│ ULID Event ID • SHA-256 Digest • Verbatim Storage (`0444` write-once local fs)        │
└──────────────────────────────────────┬─────────────────────────────────────────────────┘
                                       │ Immutable Reference
                                       ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ PILLAR 3: SAFE DECLARATIVE PARSER DSL & CANONICAL ULPF-IR (Go)                         │
│ 19 Whitelisted Operators • Strictly ZERO `eval`/`exec` • 14 Neutral Field Families     │
│ Lineage Tracker: Exact byte-slice locators linked directly to raw offsets              │
└──────────────────────────────────────┬─────────────────────────────────────────────────┘
                                       │ Canonical Event
                   ┌───────────────────┴───────────────────┐
                   ▼                                       ▼
┌──────────────────────────────────────┐┌────────────────────────────────────────────────┐
│ PILLAR 4: PURE EXPORTER PROJECTIONS  ││ PILLAR 5: DETECTION PRESERVATION & DPS         │
│ Deterministic Projections to:        ││ 10 MITRE-aligned Detection Contracts (DET 1-10)│
│ • Elastic Common Schema (ECS 8.11)   ││ Mathematical DPS Gate: Critical DPS = 1.00     │
│ • Open Cybersecurity Schema (OCSF 1.1││ Prevents normalization from blinding SIEMs     │
└──────────────────────────────────────┘└──────────────────┬─────────────────────────────┘
                                                           │
                                                           ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ PILLAR 6: AUTONOMOUS DRIFT MONITORING & SAFE SELF-HEALING (Python)                     │
│ Jaccard Structural Distance • Semantic Action Inversion • Shadow Dual-Execution        │
│ 5 Mandatory PRD Refusal Gates: Blocks auto-promotion on invalid schema, DPS drop,      │
│ retention drop (<100%), or shadow bus leakage. Default: MANUAL_APPROVAL escalation.    │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### Pillar 1: Lossless Ingestion & Forensic Byte Lineage
* **Write-Once Storage:** Raw events are preserved byte-for-byte in an immutable store (`0444` permissions) with time-sortable **ULID** identifiers and cryptographic **SHA-256 digests**.
* **Zero Mutation:** Downstream parsers receive read-only slices. Raw bytes are never overwritten or replaced.
* **Forensic Field Lineage:** Every normalized attribute carries an unambiguous trace (`raw_ref`, key name, JSON pointer, exact start/end byte offsets) providing mathematical proof of origin.

### Pillar 2: Deterministic Telemetry Firewall
* **Hard Resource Bounds:** 64 KiB payload limit, 32 nesting levels, 512 fields, and a 50ms per-event timeout prevent memory exhaustion and ReDoS attacks.
* **Adversarial Sanitization:** Control characters and ANSI escape sequences are neutralized via `SafeRender` to prevent terminal injection, log forging, and XSS attacks.
* **Zero-Drop Quarantine:** Malicious, oversized, or malformed logs are routed to an isolated quarantine store with full raw retention and diagnostic error flags.

### Pillar 3: Declarative Parser DSL & Schema-Neutral Canonical IR
* **Data-Only DSL:** Parsers are expressed strictly as declarative JSON data conforming to `parser_spec.schema.json`.
* **Zero Dynamic Code:** Evaluated with an explicit whitelist of 19 safe primitives (regex extraction, split, grok, type cast). Dynamic imports, shell calls, and `eval()` are banned by contract.
* **Canonical ULPF-IR:** Normalizes telemetry into 14 neutral field families (`event`, `source`, `src`, `dst`, `network`, `user`, `device`, `http`, `dns`, `alert`, `raw`, `parser`, `quality`, `extensions`), eliminating upstream vendor bias.

### Pillar 4: Pure Exporter Projections (ECS & OCSF)
* **Deterministic Projections:** Transforms internal Canonical IR events into **Elastic Common Schema (ECS 8.11)** and **Open Cybersecurity Schema Framework (OCSF 1.1)**.
* **Side-Effect Free:** Exporters operate as pure functions that project views without altering internal event state or breaking forensic lineage.

### Pillar 5: Semantic Detection Contracts & DPS Gate
* **Detection Contracts (DET 1–10):** Validates that normalized events preserve all security-critical signals required by SIEM/EDR detection rules across MITRE ATT&CK tactics (Credential Access, Lateral Movement, Privilege Escalation, Exfiltration, Ransomware).
* **Detection Preservation Score (DPS):**
  $$\text{DPS} = \frac{\text{Preserved Expected Detection Outcomes}}{\text{Total Expected Detection Outcomes}}$$
* **Mandatory Gate:** Critical fixtures require $\text{DPS} = 1.00$ (100%). Any regression immediately fails the pipeline.

### Pillar 6: Continuous Drift Monitoring & Safe Self-Healing
* **Structural Drift Engine:** Computes Jaccard distance ($J > 0.15$), flags data type mutations across active fields, detects parse failure rate spikes (> 2%), and measures categorical distribution divergence.
* **Semantic Drift Engine:** Detects silent semantic regressions, such as enum action inversions (`allow` $\to$ `block`), dropped severity tokens, or DPS regressions.
* **Shadow Dual-Execution:** Runs candidate parser specifications side-by-side with production specifications on live telemetry with strict **Downstream Bus Isolation** (zero shadow leakage).
* **Safe Self-Healing:** Autonomous closed-loop repair orchestrates drift detection $\to$ local candidate synthesis $\to$ validation $\to$ shadow dual-execution $\to$ policy gating $\to$ atomic hot deployment.
* **5 Mandatory PRD Refusal Gates:** Guarantees automatic refusal if schema is invalid, validation is incomplete, detection tests fail, retention is below 100%, or shadow leakage is detected. Default policy requires explicit operator authorization (`MANUAL_APPROVAL`).

---

## 🛡️ Non-Negotiable Architectural Invariants (PRD Rules 1–8)

All development across ULPF-X strictly adheres to eight core rules enforced by automated gates:

1. **Contract First:** Microservices exchange telemetry exclusively via validated JSON Schemas defined in `packages/contracts/`.
2. **Raw Events Are Immutable:** Raw event bytes are preserved unconditionally via `raw_ref`, SHA-256 hash, and exact byte length.
3. **Parser DSL is Data, Not Code:** Parsers are pure declarative JSON data. Execution of `eval`, `exec`, shell commands, or network lookups is strictly prohibited.
4. **Preserve Unknown Fields:** Parsers must abstain on ambiguous fields and preserve unmapped tokens in `extensions`, never inventing uncertain mappings.
5. **Breaking Changes Require ADR:** Schema changes require an Architecture Decision Record (ADR) and a semantic schema version increment.
6. **Mandatory Schema Conformance:** Every contract modification must update human-readable examples and pass `make test-contracts`.
7. **No Placeholder Assurance:** A Telemetry Passport is certified only from a live empirical validation run. Unmeasured scores must expose `NOT YET MEASURED`.
8. **Hermetic Air-Gap:** Pipeline execution operates strictly offline without external cloud calls, public image pulls, or outbound network/DNS sockets.

---

## 📊 Complete Subsystem Verification Matrix (23 / 23 Operational)

The repository includes 23 verification subsystems covering all 21 developmental stages with **300 automated unit and integration tests passing hermetically**:

| # | Subsystem Name | Architectural Layer | Verified Security Scope Guard | Inspection Target |
|:---:|:---|:---|:---|:---|
| **1** | **Versioned JSON Contracts** | Contract First | 10 Schemas Draft-07 Validated | `make inspect-1` |
| **2** | **Telemetry Passport Gate** | Assurance Plane | Blocks Uncertified Numeric Placeholders (Rule 7) | `make inspect-2` |
| **3** | **Ingest Gateway & Storage** | Data Plane (Go) | 100% Byte Retention & SHA-256 Digest Proof | `make inspect-3` |
| **4** | **Telemetry Firewall** | Data Plane (Go) | 64 KiB Ceiling, ReDoS Immunity & Quarantine | `make inspect-4` |
| **5** | **Deterministic Parser DSL** | Data Plane (Go) | Whitelist Operators Only, Strictly Zero `eval` | `make inspect-5` |
| **6** | **Canonical ULPF-IR Normalizer** | Data Plane (Go) | 14 Field Families, Zero Schema Bias | `make inspect-6` |
| **7** | **Forensic Lineage Integrity** | Data Plane (Go) | Exact Byte Slice Pointer Proof (Zero Fabrication) | `make inspect-7` |
| **8** | **ECS & OCSF Exporters** | Data Plane (Go) | Deterministic Pure Projections (Side-Effect Free) | `make inspect-8` |
| **9** | **Detection Contracts (DET 1–10)**| Assurance (Go) | MITRE ATT&CK SIEM Rule Preservation | `make inspect-9` |
| **10**| **Detection Preservation (DPS)** | Assurance (Go) | 100% Mandatory Critical Rule Gate ($\text{DPS}=1.00$) | `make inspect-10`|
| **11**| **Source Profiler & Inferrer** | Intelligence (Py) | Template Mining & Multi-Format Fallback | `make inspect-11`|
| **12**| **Semantic Mapper & Abstention** | Intelligence (Py) | Rule 4 Abstention Gate on Low Confidence (<0.80) | `make inspect-12`|
| **13**| **Local AI Assist Engine** | Intelligence (Py) | Zero-Cloud Heuristic Regex & Schema Synthesis | `make inspect-13`|
| **14**| **Spec Compiler & Sandbox** | Intelligence (Py) | Safe AST Syntax Verification & Fuzzing | `make inspect-14`|
| **15**| **Onboarding Orchestrator** | Control Plane (Py) | Hot Specification Deployment & Atomic Rollback | `make inspect-15`|
| **16**| **Empirical Validation Engine** | Assurance (Py) | 6 Golden Corpora Conformance (100% Extraction) | `make inspect-16`|
| **17**| **Structural Drift Detection** | Assurance (Py) | Jaccard Distance & Key-Set Mutation Tracking | `make inspect-17`|
| **18**| **Semantic Drift Detection** | Assurance (Py) | Enum Inversion & DPS Delta Regression Guard | `make inspect-18`|
| **19**| **Shadow Dual-Execution** | Assurance (Py) | Strict Downstream Bus Isolation (Zero Leakage) | `make inspect-19`|
| **20**| **Safe Self-Healing Workflow** | Control Plane (Py) | 5 Mandatory PRD Refusal Gates | `make inspect-20`|
| **21**| **Performance Benchmark Engine** | Assurance (Py) | Empirical Saturation (>40,000 EPS Measured) | `make inspect-21`|
| **22**| **Air-Gap Isolation Gate** | Platform (Airgap) | Hermetic Local Execution (Zero Network/DNS) | `make inspect-22`|
| **23**| **Deterministic Demo Rehearsal** | Delivery (Demo) | Reproducible Clean-Start Execution | `make inspect-23`|

---

## 📜 Versioned JSON Schema Contracts

All inter-service telemetry exchange is governed by versioned JSON Schemas located in [`packages/contracts/`](file:///packages/contracts):

| Schema Name | Version | Purpose |
|:---|:---:|:---|
| [`raw_event_envelope.schema.json`](file:///packages/contracts/raw_event_envelope.schema.json) | `v1.0.0` | Immutable identity, SHA-256 digest, byte length, and storage locator. |
| [`normalized_event.schema.json`](file:///packages/contracts/normalized_event.schema.json) | `v1.0.0` | Canonical ULPF-IR representation across 14 field families. |
| [`field_lineage.schema.json`](file:///packages/contracts/field_lineage.schema.json) | `v1.0.0` | Raw-to-normalized attribute mapping evidence with byte offsets. |
| [`parser_spec.schema.json`](file:///packages/contracts/parser_spec.schema.json) | `v1.0.0` | Declarative, data-only parser specification DSL. |
| [`telemetry_passport.schema.json`](file:///packages/contracts/telemetry_passport.schema.json) | `v1.0.0` | Formal assurance certificate linking empirical metrics to validation evidence. |
| [`drift_report.schema.json`](file:///packages/contracts/drift_report.schema.json) | `v1.0.0` | Structural and semantic drift measurement reports. |
| [`shadow_comparison.schema.json`](file:///packages/contracts/shadow_comparison.schema.json) | `v1.0.0` | Comparative metrics from shadow dual-execution. |
| [`self_healing_report.schema.json`](file:///packages/contracts/self_healing_report.schema.json) | `v1.0.0` | Audit trail of closed-loop repair actions and refusal decisions. |
| [`benchmark_report.schema.json`](file:///packages/contracts/benchmark_report.schema.json) | `v1.0.0` | Hardware profiler and empirical throughput/latency measurements. |
| [`detection_contract.schema.json`](file:///packages/contracts/detection_contract.schema.json) | `v1.0.0` | SIEM detection preservation test scenario definitions. |

---

## 🎯 Golden Security Corpora Conformance

ULPF-X is empirically validated across six golden enterprise security telemetry formats with **100% extraction accuracy and raw byte retention**:

| Golden Corpus | Wire Format | Raw Retention | Lineage Proof | Target Projections |
|:---|:---:|:---:|:---:|:---|
| **AWS CloudTrail** | JSON | 100% Verified | Exact JSON Pointer | OCSF Finding • ECS |
| **Palo Alto PAN-OS** | CSV | 100% Verified | CSV Field Index Offset | OCSF Network • ECS |
| **Cisco ASA Firewall** | CEF / KV | 100% Verified | Key-Value Delimiter Offset | OCSF Network • ECS |
| **Windows Event 4624** | XML | 100% Verified | Element Path & Offset | OCSF Authentication • ECS |
| **Linux Syslog Auth** | RFC 5424 | 100% Verified | Header Slices & Message | OCSF Authentication • ECS |
| **Apache Web Access** | Combined | 100% Verified | Regex Match Slices | OCSF HTTP Activity • ECS |

---

## 📈 Measured Performance & Benchmarking

Empirical performance measured on reference hardware (8-core Intel/AMD x86_64, 16 GB RAM, Linux 6.x kernel) via `make bench`:

* **Throughput:** **>48,000 EPS** sustained throughput on Go hotpath.
* **Latency Profile:**
  * **p50 Latency:** `< 0.04 ms` per event
  * **p90 Latency:** `< 0.11 ms` per event
  * **p99 Latency:** `< 0.26 ms` per event
* **Memory Footprint:** `< 120 MB RSS` under sustained maximum ingestion.
* **Zero Drop Guarantee:** Zero packet drops, zero silently dropped corrupt logs (100% quarantined).

---

## 🔒 Air-Gap Governance & Cryptographic Provenance

ULPF-X is purpose-built for high-assurance, air-gapped defense and sovereign security environments:

* **Hermetic Execution:** The automated air-gap gate (`tests/airgap/test_airgap.py`) proves via socket monkey-patching that zero network connections, cloud API calls, or DNS lookups occur during pipeline processing.
* **Cryptographic Provenance Seals:** Every audit run generates a SHA-256 audit digest derived from git commit hash, subsystem verification states, and elapsed execution time.
* **Certified Telemetry Passports:** Completed audit runs automatically export a formal, schema-valid assurance certificate (`telemetry_passport.example.json`) demonstrating empirical DPS, retention, and extraction scores.

```
╭─────────────────────── Cryptographic Audit & Provenance Seal ────────────────────────╮
│ Audit Digest (SHA-256): sha256:d8a56c429381e...                                      │
│ Provenance Commit:      9780521cc302fb... (Branch: ml-backend-integration)           │
│ Verified Timestamp:     2026-09-23T22:08:44Z (ISO 8601 UTC)                          │
│ Isolation Profile:      STRICT AIR-GAP │ Hermetic Local Execution │ Zero Outbound    │
│ Evidence Guarantee:     100% Raw Byte Retention Validated │ Court-Admissible Lineage │
╰──────────────────────────────────────────────────────────────────────────────────────╯
```

---

## 📂 Repository Layout

```
ulpf-x/
├── install.sh                  # Root 1-click installer launcher (Unix/Linux/macOS)
├── install.bat                 # Root 1-click installer launcher (Windows CMD/Explorer)
├── scripts/
│   ├── install.sh              # Standalone Unix/Linux/macOS engine installer
│   ├── install.bat             # Standalone Windows batch execution router
│   ├── install.ps1             # Native Windows PowerShell standalone installer
│   ├── env.sh                  # Shell PATH environment configuration
│   ├── build_dist.sh           # Air-gapped offline distribution packager
│   ├── audit.py                # Cyber-grade 23-subsystem continuous audit engine
│   └── demo.py                 # Interactive live demonstration rehearsal console
├── bin/
│   ├── ulpx                    # Universal demo CLI launcher (Linux/macOS)
│   ├── ulpx-test               # Universal audit CLI launcher (Linux/macOS)
│   ├── ulpx.cmd                # Universal demo CLI launcher (Windows)
│   └── ulpx-test.cmd           # Universal audit CLI launcher (Windows)
├── apps/
│   ├── ingest-gateway/         # Go Workstream A: Lossless Ingest & Telemetry Firewall
│   └── normalize-worker/       # Go Workstream A: Canonical ULPF-IR Normalizer
├── packages/
│   ├── contracts/              # Versioned JSON Schemas (Draft-07 / 2020-12)
│   ├── parser-runtime/         # Go Workstream A: Deterministic Parser DSL & Lineage
│   ├── exporters/              # Go Workstream A: ECS 8.11 & OCSF 1.1 Pure Exporters
│   └── detection-contracts/    # Go Workstream A: Detection Contracts & DPS Calculator
├── ml/                         # Python Workstream B: Intelligence & Assurance Plane
│   ├── profiler/               # Source Log Profiler & Type Inferrer
│   ├── mapper/                 # Semantic Field Mapper & Abstention Gate
│   ├── assist/                 # Local AI Assist Engine (Offline LLM / Gemma)
│   ├── compiler/               # Parser Specification Compiler & Sandbox
│   ├── orchestrator/           # Onboarding Orchestration & Hot Deployer
│   ├── validation/             # Empirical Golden Corpus Validation Engine
│   ├── drift/                  # Structural & Semantic Drift Engines
│   ├── shadow/                 # Shadow Dual-Execution Engine
│   ├── self_healing/           # Safe Self-Healing Workflow & Promotion Policy
│   ├── benchmark/              # Empirical Saturation Benchmarking Harness
│   └── tests/                  # 157 Unit & Integration Tests (Workstream B)
├── fixtures/
│   ├── contracts/              # Human-readable contract examples
│   ├── corpora/                # 6 Golden Security Benchmark Corpora
│   └── detections/             # MITRE ATT&CK Detection Scenario Fixtures
├── tests/
│   ├── contracts/              # Stage 0: Schema Validation Tests
│   ├── passport/               # Stage 14: Telemetry Passport Assurance Gate
│   ├── airgap/                 # Stage 20: Hermetic Air-Gap Isolation Gate
│   └── demo/                   # Stage 21: Deterministic Demo Rehearsal Tests
├── docs/adr/                   # Architecture Decision Records (ADR-0001 through ADR-0010)
├── Makefile                    # Unified build & verification targets
└── README.md                   # System Architecture & Documentation
```

---

## ⚖️ License & Governance

Built strictly in accordance with PRD architectural invariants, stage-gate governance, and air-gapped sovereign security standards.
