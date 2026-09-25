# Stage 21 non-frontend demo rehearsal

Run `make demo-check` from a clean checkout. It validates two existing golden
sources, builds their Telemetry Passports from real validation results, and
checks that the compact rehearsal summary is repeatable. No numeric score is
stored in a demo fixture or manually supplied by the rehearsal.

Use `tools/demo/reset.ps1` to clear only `work/demo` between rehearsals.

The frontend/dashboard portion is intentionally absent. No seeded dashboard,
mock dashboard response, or UI claim is included until a real frontend exists.
