# ADR-0005: Telemetry Passport measurement gate

## Status

Accepted - Stage 14.

## Context

A passport must communicate assurance without displaying synthetic scores as
measured results. The original 1.0 contract required numeric scores even when a
source had no completed validation evidence.

## Decision

Telemetry Passport schema 1.1 makes validation linkage explicit. A certified
passport requires a passed validation run, complete numeric evidence, and a
measured drift observation. An uncertified passport contains the literal `NOT
YET MEASURED` for every score and drift state, while retaining a failed run ID
and completion time when such a run exists.

The Stage 14 builder accepts evidence as input and copies its values exactly; it
has no defaults for numeric metrics or actual drift state.

## Consequences

Consumers can distinguish absence of measurement from a low score. Existing
1.0 passport producers must migrate to 1.1 rather than silently changing the
meaning of their output.
