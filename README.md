# ULPF-X — Universal Log Pre-processing Framework


[![Contract Tests](https://img.shields.io/badge/Contracts-10%2F10%20Verified-brightgreen?style=flat-square)](packages/contracts)
[![Subsystems](https://img.shields.io/badge/Subsystems-23%2F23%20Operational-blue?style=flat-square)](scripts/audit.py)
[![Lineage Proof](https://img.shields.io/badge/Byte%20Retention-100%25%20SHA--256-success?style=flat-square)](packages/contracts/field_lineage.schema.json)
[![Detection Integrity](https://img.shields.io/badge/DPS%20Ratio-1.00%20Zero%20Regression-teal?style=flat-square)](packages/contracts/telemetry_passport.schema.json)
[![Air-Gap Profile](https://img.shields.io/badge/Air--Gap-Hermetic%20%2F%20Zero--Cloud-purple?style=flat-square)](tests/airgap)

ULPF-X is an air-gapped, vendor-neutral **security-telemetry trust layer and preprocessing platform**. It transforms heterogeneous perimeter security logs (firewalls, VPNs, proxies, IDS/IPS, DNS) into canonical, analytics-ready security events while cryptographically **proving** that the normalization is lossless, traceable, semantically preserved, and detection-safe.

---

## The Core Problem

Security Operations Centers (SOCs) ingest logs from dozens of security vendors—Palo Alto Networks, Fortinet, Check Point, Cisco ASA, F5, Zeek, Snort, Suricata—each formatting data differently (Syslog, Key-Value, JSON, CSV, CEF, LEEF). 

Existing ETL and normalization engines ask:  
*"Can we parse this into a common schema?"*  

They fail to answer the critical security question:  
> **"Did the normalization silently alter, drop, or fabricate security meaning—causing SIEM detection rules to fail?"**

When vendor firmware updates introduce structural or semantic field shifts:
1. **Silent Dropping:** Unknown fields vanish, destroying forensic evidence.
2. **Forced Mappings:** Ambiguous status codes get guessed, creating false positives or false negatives.
3. **Detection Blindspots:** SIEM queries and threat detection rules silently stop matching, creating unmonitored blindspots.

---

## Architectural Guarantee & Invariants

ULPF-X enforces strict architectural non-negotiables:

- **100% Raw Byte Retention:** Raw logs are preserved byte-for-byte with SHA-256 cryptographic seals and exact byte slice pointers (`raw_ref`, `raw_sha256`, `raw_length_bytes`).
- **Deterministic Whitelisted DSL:** The parser DSL is declarative data, never executable code. Zero `eval`, zero dynamic imports, zero external shell execution.
- **Rule 4 Abstention:** Ambiguous mappings strictly abstain when confidence is below 0.80. Unknown fields are retained in `extensions`—nothing is discarded.
- **Detection Preservation Score (DPS):** Automated regression gates verify that downstream SIEM detection rules continue to fire at a 1.00 ratio across all schema transformations.
- **Certified Telemetry Passports:** Telemetry quality is authenticated exclusively via completed empirical validation runs. Zero placeholder metrics.
- **Hermetic Air-Gap Execution:** Operates completely offline with local model weights, schemas, and wheel dependencies. Zero external cloud or DNS dependencies.

---

## Unified Command Suite ("Best of Both Worlds")

ULPF-X provides an enterprise-grade command hierarchy: a structured unified subcommand core (`ulpx <subcommand>`) paired with fast, single-word convenience shorthands (`ulpx-*`) across **Linux, macOS, and Windows** (CMD & PowerShell).

```
                            ┌────────────────────────┐
                            │    ulpx [subcommand]   │
                            │  Enterprise Unified CLI│
                            └───────────┬────────────┘
                                        │
     ┌─────────────┬─────────────┬──────┴──────┬─────────────┬─────────────┬─────────────┐
     ▼             ▼             ▼             ▼             ▼             ▼             ▼
ulpx export    ulpx export   ulpx export   ulpx watch    ulpx api      ulpx daemon   ulpx daemon
--format text  --format json --format csv  (or term)     (or listen)   start         stop
     │             │             │             │             │             │             │
     ▼             ▼             ▼             ▼             ▼             ▼             ▼
 [ulpx-text]   [ulpx-json]   [ulpx-csv]   [ulpx-term]   [ulpx-api]     [ulpx-on]     [ulpx-off]
```

### Command Reference

| Unified Subcommand | Shorthand Alias | Target Destination | Functional Purpose |
| :--- | :--- | :--- | :--- |
| `ulpx export --format text` | `ulpx-text` | stdout or file | Structured text security log sink (firewall/syslog format) |
| `ulpx export --format json` | `ulpx-json` | stdout or file | Contract-compliant NDJSON / JSON Lines sink |
| `ulpx export --format csv` | `ulpx-csv` | stdout or file | Tabular CSV sink for analytical SIEM ingestion |
| `ulpx watch` *(or `ulpx term`)* | `ulpx-term` | Interactive TUI | Real-time live rolling telemetry observer window |
| `ulpx api` *(or `ulpx listen`)* | `ulpx-api` | Port `8080` (HTTP) | Direct pipeline HTTP ingestion server (`/api/v1/events/raw`) |
| `ulpx daemon start` | `ulpx-on` | Background Service | Daemonized background task with PID tracking |
| `ulpx daemon stop` | `ulpx-off` | Process Shutdown | Graceful background daemon termination |
| `ulpx audit` *(or `ulpx test`)* | `ulpx-test` | Console Report | 23-Subsystem Continuous Security Assurance Suite |
| `ulpx` *(zero arguments)* | `ulpx` | Interactive Console | 6-Pillar Guided Judge Demonstration Console |

---

## Quick Start & Installation

### Option 1: Standalone Package (Linux / macOS / Windows)

Download `ULPF-X-Standalone-v1.0.0.zip` from [GitHub Releases](https://github.com/kalpeshkarnawat19/ULPX/releases/tag/v1.0.0-rc1).

#### Linux & macOS
```bash
unzip ULPF-X-Standalone-v1.0.0.zip
cd ULPF-X-Standalone-v1.0.0
bash install.sh
```

#### Windows (Git Bash / PowerShell / Command Prompt)
- **Command Prompt (CMD):** Double-click or run `install.bat`
- **PowerShell:** `powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1`

### Option 2: Developer Repository Setup

```bash
# Clone the repository
git clone https://github.com/kalpeshkarnawat19/SIH-PS-2.git
cd SIH-PS-2

# Add bin directory to PATH for the current session
source scripts/env.sh

# Run the 23-subsystem verification suite
ulpx-test

# Launch the interactive judge demonstration
ulpx
```

---

## The 6 Demonstration Pillars (Judge Evaluation)

The ULPF-X live demonstration (`ulpx` or `python3 scripts/demo.py`) delivers an interactive 6-pillar evaluation workflow:

### Pillar 1: High-Throughput Hardware Saturation & Ingestion
- **Empirical Measurement:** Benchmarks the local data plane under realistic enterprise network loads.
- **Hardware Capacity:** Sustained processing exceeding **16,000 Events/Sec (EPS)** on commodity laptop hardware.
- **Zero Memory Leaks:** Deterministic memory bounds with zero memory degradation under peak saturation.

### Pillar 2: Forensic Lineage & Exact Byte Offset Tracking
- **Cryptographic Sealing:** Every raw event receives a SHA-256 digest at the ingestion boundary.
- **Exact Slices:** Normalizer maps target fields (e.g., `src.ip`, `dst.port`, `event.action`) to precise start and end byte offsets within the raw payload.
- **Auditable Lineage:** Exported lineage graphs enable courtroom-admissible, non-repudiable log auditing.

### Pillar 3: Semantic Drift Detection & Safe Auto-Healing
- **Drift Identification:** Detects vendor format shifts (e.g., status field changing from `"ALLOW"` to `1`, or timestamp reformatting).
- **Safe Candidate Synthesis:** Local heuristic engine proposes candidate DSL specs without touching production code.
- **5-Gate Safety Sandbox:** Prevents automated regression through mandatory syntax validation, fuzz testing, coverage checks, abstention bounds, and shadow dual-run comparisons.

### Pillar 4: Detection Preservation Score (DPS) & SIEM Rule Integrity
- **Rule Verification:** Evaluates detection contracts (DET 1–6: Brute Force, C2 Beaconing, Port Scanning, Lateral Movement, Data Exfiltration, Privilege Escalation).
- **1.00 Ratio Gate:** Guarantees that alerts which triggered on raw logs continue to trigger identically on normalized logs.
- **Zero Alert Drops:** Strict block on any parser deployment that degrades detection efficacy.

### Pillar 5: Certified Telemetry Passport Generation
- **Cryptographic Seal:** Produces a tamper-evident, machine-readable passport certifying schema conformance, DPS score, byte retention, and drift status.
- **No Placeholders:** If a metric cannot be measured empirically, the passport strictly outputs `NOT YET MEASURED`.

### Pillar 6: Continuous Security Assurance Suite (23 Subsystems)
- **Exhaustive Invariant Audit:** Executes 23 subsystem checks covering contracts, parsers, lineage, firewall guards, exporters, and air-gap boundaries in under 12 seconds.
- **Run Command:** `ulpx audit` or `ulpx-test`.

---

## Technology Stack

| Architectural Layer | Technology | Operational Responsibility |
| :--- | :--- | :--- |
| **Data Plane Runtime** | Python 3.9+ / Go | High-velocity streaming ingestion, SHA-256 sealing, deterministic DSL parsing |
| **Contract Specifications** | JSON Schema (Draft-07) | 10 formal schemas governing all inter-service artifacts |
| **Intelligence & Assurance** | Python / AST Compiler | Template mining, semantic mapping, drift analysis, shadow dual-run |
| **CLI & Terminal UX** | Rich / Native OS Shells | Interactive demonstration console, real-time TUI observer, cross-platform CLI |
| **Air-Gap Packaging** | Pure Wheels / Shell Wrappers | 100% offline self-contained standalone execution |

---

## Repository Structure

```
ulpf-x/
├── bin/                         # Cross-platform CLI entrypoints (Unix, CMD, PS1)
│   ├── ulpx                     # Unified master CLI launcher
│   ├── ulpx-text                # Shorthand: Structured Text Log Sink
│   ├── ulpx-json                # Shorthand: NDJSON / JSON Lines Sink
│   ├── ulpx-csv                 # Shorthand: Tabular CSV Security Sink
│   ├── ulpx-term                # Shorthand: Real-Time Observer Window
│   ├── ulpx-api                 # Shorthand: Direct Pipeline Ingestion API
│   ├── ulpx-on                  # Shorthand: Background Daemon Starter
│   ├── ulpx-off                 # Shorthand: Background Daemon Stopper
│   └── ulpx-test                # Shorthand: 23-Subsystem Assurance Suite
├── packages/
│   ├── contracts/               # Versioned JSON Schemas (Single Source of Truth)
│   ├── parser-runtime/          # Deterministic DSL evaluation engine
│   ├── exporters/               # ECS and OCSF projection transformers
│   └── detection-contracts/     # SIEM detection rule contracts (DET 1-6)
├── ml/
│   ├── source_profiler/         # Log format & template inference
│   ├── semantic_mapper/         # Semantic field mapping & Rule 4 abstention
│   ├── drift/                   # Structural and semantic drift detection
│   ├── shadow/                  # Dual-execution shadow runner
│   ├── self_healing/            # 5-gate safe candidate spec synthesis
│   └── benchmark/               # Empirical hardware saturation engine
├── fixtures/
│   ├── contracts/               # Schema-validated contract examples
│   ├── golden/                  # Golden security log corpora (Palo Alto, Fortinet, etc.)
│   └── drift/                   # Drift scenario simulation fixtures
├── tests/
│   ├── contracts/               # Contract gate validation (`make test-contracts`)
│   ├── demo/                    # Demo rehearsal verification (`make demo-check`)
│   └── airgap/                  # Offline hermetic validation checks
├── scripts/
│   ├── cli.py                   # Master unified CLI controller
│   ├── demo.py                  # 6-pillar interactive judge presentation
│   ├── audit.py                 # 23-subsystem continuous invariant test suite
│   ├── install.sh               # Unix/macOS/Git Bash autonomous installer
│   ├── install.bat              # Windows Command Prompt installer
│   ├── install.ps1              # Windows PowerShell native installer
│   └── build_dist.sh            # Air-gapped offline distribution packager
├── Makefile                     # Build, test, and verification automation
└── README.md                    # System documentation
```

---

## Verification & Testing

Verify system invariants and contract compliance locally:

```bash
# Validate all 10 JSON Schema contracts
make test-contracts

# Verify stage-gate demo invariants
make demo-check

# Run full continuous security assurance audit (23 subsystems)
ulpx audit
# or
ulpx-test
```

---

## License & Compliance

Developed for the **Smart India Hackathon (SIH 2026)** under Problem Statement **SIH26156** for the **National Technical Research Organisation (NTRO)**. All software adheres strictly to air-gap deployment requirements and defense-in-depth telemetry governance.
