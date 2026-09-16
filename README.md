# ULPF-X — Universal Log Pre-processing Framework

> **SIH 2026 | Problem Statement ID: SIH26156 | Organisation: NTRO (National Technical Research Organisation)**

ULPF-X is a vendor-neutral **security-telemetry preprocessing platform** that converts heterogeneous perimeter-device logs into normalized, analytics-ready security events — while **proving** that the transformation is lossless, semantically trustworthy, traceable and safe.

---

## The Problem

Security Operations Centers (SOCs) ingest logs from dozens of vendors — firewalls, routers, VPN gateways, IDS/IPS, proxies, DNS appliances — each with its own format. Existing normalization pipelines ask *"can we transform this into a common schema?"* but never answer the harder question:

> **Can we transform it without silently changing, losing, or fabricating security meaning?**

Parser pipelines break silently when vendors change log formats. Unknown fields vanish. Ambiguous mappings get forced. Detection rules stop working — and nobody notices until an incident is missed.

---

## What ULPF-X Does

ULPF-X is a **continuously verified security-telemetry trust layer** that:

- **Preserves raw events** byte-for-byte with SHA-256 integrity
- **Parses deterministically** using a whitelisted DSL — no `eval`, no arbitrary code
- **Normalizes** into a canonical Intermediate Representation (ULPF-IR)
- **Traces every field** from normalized output back to raw evidence (forensic lineage)
- **Abstains** from uncertain mappings instead of guessing
- **Retains unknown fields** — nothing silently disappears
- **Exports** to ECS (Elastic Common Schema) and OCSF
- **Detects format drift** when vendors change log structures
- **Validates parser evolution** through shadow parsing before promotion
- **Measures trust** via Telemetry Passports backed by real validation scores

### What ULPF-X Is *Not*

- ❌ Not a SIEM, IDS/IPS, or SOAR platform
- ❌ Not an LLM in the event hot path
- ❌ Not a replacement for OCSF, ECS, or ASIM — it feeds them
- ❌ Not a generic ETL tool
- ❌ Not a system that forces uncertain semantic mappings

---

## Core Properties

| Property | Behavior |
|---|---|
| **Lossless** | Exact raw event retained; unknown fields never silently disappear |
| **Deterministic** | Same raw event + parser version + schema version → identical normalized event |
| **Explainable** | Every normalized field traces to raw evidence and transformation steps |
| **Uncertainty-aware** | Ambiguous mappings abstain; preserved in source extensions |
| **Continuously verified** | Parser evolution is regression-tested and shadow-compared before promotion |
| **Air-gap capable** | Runtime requires no public Internet or cloud API |

---

## Architecture

ULPF-X is split into two planes:

### Data Plane (Hot Path)
Deterministic, fast, AI-free. Handles production events:

```
Raw Event → Telemetry Firewall → Raw Preservation (MinIO + SHA-256)
    → Certified Parser (DSL) → ULPF Canonical IR → Field Lineage
    → ECS / OCSF Export
```

### Control Plane (Assurance)
Performs expensive/probabilistic work away from the hot path:

```
Unknown Source → Profiling → Semantic Mapping (AI-assisted)
    → Candidate ParserSpec → Validation → Detection Contracts
    → Shadow Parsing → Certification → Telemetry Passport
```

> **Non-negotiable boundary:** AI may *propose* a ParserSpec. AI may *never* generate code that is automatically executed in production and may *never* directly promote a parser.

---

## Technology Stack

| Layer | Technology | Responsibility |
|---|---|---|
| Data Plane | **Go** | Ingestion, hashing, safety checks, parser runtime, IR construction, exporters |
| Control API | **Python + FastAPI** | Onboarding, semantic mapping, validation, lifecycle, drift, certification |
| Web UI | **Next.js + TypeScript** | Review, lineage, passports, drift and parser lifecycle UX |
| Metadata | **PostgreSQL** | Sources, parser versions, jobs, validation, audit events |
| Event Analytics | **ClickHouse** | Normalized events and high-volume querying |
| Raw Storage | **MinIO** | Immutable raw-event bytes |
| Transport | **EventBus interface** | InMemoryBus for dev; Kafka/Redpanda optional |

---

## Repository Structure

```
ulpf-x/
├── apps/
│   ├── ingest-gateway/          # Go — Event ingestion + raw preservation
│   ├── normalize-worker/        # Go — Deterministic parser execution
│   ├── control-api/             # Python/FastAPI — Control plane API
│   └── web/                     # Next.js — UI
├── packages/
│   ├── contracts/               # Versioned JSON schemas (source of truth)
│   ├── parser-runtime/          # Parser DSL engine
│   ├── exporters/
│   │   ├── ecs/                 # Elastic Common Schema exporter
│   │   └── ocsf/                # OCSF exporter
│   └── detection-contracts/     # Detection preservation rules
├── ml/
│   ├── source_profiler/         # Unknown-source profiling
│   ├── semantic_mapper/         # Semantic field mapping + AI assist
│   └── drift/                   # Structural & semantic drift detection
├── fixtures/
│   ├── golden/                  # Golden test fixtures per source
│   ├── malformed/               # Malformed input test cases
│   ├── drift/                   # Drift simulation fixtures
│   └── onboarding/              # Unseen-source onboarding samples
├── tests/
│   ├── contracts/               # JSON Schema validation
│   ├── integration/             # Storage, API, service boundaries
│   ├── performance/             # Throughput & latency benchmarks
│   └── e2e/                     # Full onboarding → certification flow
├── infra/
│   ├── clickhouse/              # ClickHouse config
│   ├── postgres/                # PostgreSQL config + migrations
│   └── minio/                   # MinIO config
└── docs/
    ├── PRD.md
    ├── ARCHITECTURE.md
    ├── DATA_MODEL.md
    ├── PARSER_DSL.md
    ├── TESTING.md
    ├── DEMO.md
    └── adr/                     # Architecture Decision Records
```

---

## V1 Scope

**Perimeter/network-security logs first:**
- Firewalls, routers, VPN gateways, IDS/IPS, secure web gateways/proxies, DNS appliances, generic syslog devices

**Supported formats:**
- Syslog, key-value text, JSON, CSV, CEF, LEEF, structured vendor-like text

**Initial event families:**
- `NETWORK_CONNECTION`, `FIREWALL_POLICY`, `AUTHENTICATION`, `DNS_ACTIVITY`, `WEB_SESSION`, `SECURITY_ALERT`, `GENERIC_NETWORK_EVENT`

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/kalpeshkarnawat19/SIH-PS-2.git
cd SIH-PS-2

# Start all services
docker compose up -d

# Run tests
make test
```

---

## Key Differentiators

1. **Forensic Lineage** — Every normalized field traces back to raw evidence and transformation steps
2. **Abstention over Hallucination** — Uncertain mappings are preserved as source extensions, never forced
3. **Detection Preservation Score** — Regression-tests that security detection rules still fire correctly after parser changes
4. **Telemetry Passport** — Machine-readable assurance record tied to real validation runs, never placeholder scores
5. **Safe Self-Healing** — Format drift triggers candidate parser generation → shadow comparison → human-approved promotion
6. **Air-Gap Ready** — No required cloud APIs, no required Internet, all models/schemas stored locally

---


## Engineering Principles

- **Optimize for trust, not automation.** Fast incorrect normalization is worse than transparent abstention.
- **Contract-first.** No service is implemented before its input/output schema exists.
- **Fixture-first.** Integrate against schemas and golden fixtures, not verbal descriptions.
- **Version everything.** Parser specs, schemas, exporter mappings, and validation reports are immutable and versioned.
- **AI never activates a parser.** All promotion goes through validation gates and human/policy approval.

