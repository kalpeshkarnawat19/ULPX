# ADR-0003: Add CSV Support to Field Lineage Contract Extractor Enum

- **Status:** Accepted
- **Date:** 2026-09-17
- **Authors:** Workstream A (Kalpesh), Workstream C (Sachi)
- **Target Schema:** `packages/contracts/field_lineage.schema.json`

## Context

Under Stage 3 (ADR-0001), CSV format parsing (`csv_parse`) was introduced into the `ParserSpec` contract (`parser_spec.schema.json`) and verified across the golden corpus (`fixtures/golden/csv_access`).

Stage 5 ("Forensic Field Lineage") requires that every canonical field extracted from raw telemetry records the exact extractor mechanism (`extractor`) alongside raw locators and transformation chains.

The initial draft of `field_lineage.schema.json` v1.0 included `"key_value"`, `"json_pointer"`, `"regex_capture"`, `"cef_parse"`, `"leef_parse"`, `"syslog_parse"`, and `"kv"`, but omitted `"csv"` and `"csv_parse"`.

## Decision

We update `packages/contracts/field_lineage.schema.json` to:
1. Add `"csv"` and `"csv_parse"` to the `extractor` enum.

## Consequences

- **Backwards Compatibility:** Additive and backwards-compatible contract update. Existing lineage records and fixtures remain completely valid.
- **Contract Verification:** `make test-contracts` passes without error.
- **Lineage Integrity:** Allows CSV access logs and table-based telemetry to establish formal forensic field lineage back to raw column locators.
