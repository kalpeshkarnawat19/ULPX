"""Stage 21 non-frontend rehearsal built solely from golden fixture evidence."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.passport.passport import NOT_YET_MEASURED, TelemetryPassportBuilder
from ml.validation.validator import ValidationEngine


def run_rehearsal() -> dict[str, Any]:
    manifest = json.loads((ROOT / "fixtures/demo/rehearsal.json").read_text(encoding="utf-8"))
    if manifest["dashboard"]["included"]:
        raise ValueError("Stage 21 does not include a frontend dashboard")

    engine = ValidationEngine()
    builder = TelemetryPassportBuilder()
    outcomes = []
    for item in manifest["sources"]:
        report = engine.validate_golden_source(ROOT / item["fixture"])
        if report.source_id != item["expected_source_id"] or not report.passed:
            raise RuntimeError(f"rehearsal validation failed for {item['fixture']}")
        passport = builder.build(
            report.source_id, report.parser_id, report.parser_version,
            report.to_evidence(run_id=f"demo-{report.source_id}-{report.parser_version}"),
        )
        if passport["certification"]["status"] != "CERTIFIED" or NOT_YET_MEASURED in passport["scores"].values():
            raise RuntimeError(f"rehearsal did not obtain measured assurance for {report.source_id}")
        # Exclude run timestamps: output is reproducible while all scores remain
        # directly derived from the real validation execution above.
        outcomes.append({
            "source_id": report.source_id,
            "parser": passport["parser"],
            "certification": passport["certification"]["status"],
            "scores": passport["scores"],
            "drift_state": passport["drift"]["state"],
        })
    return {"schema_version": manifest["schema_version"], "sources": outcomes, "frontend": "NOT_IMPLEMENTED"}


if __name__ == "__main__":
    print(json.dumps(run_rehearsal(), indent=2, sort_keys=True))
