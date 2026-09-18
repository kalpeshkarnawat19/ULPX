"""Stage 0 contract gate: validate every declared example without app dependencies."""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "packages" / "contracts"
FIXTURES = ROOT / "fixtures" / "contracts"
CODE_SUFFIXES = {".go", ".py", ".js", ".ts", ".tsx"}


def fail(path: str, message: str) -> None:
    raise AssertionError(f"{path}: {message}")


def resolve(schema: dict[str, Any], root: dict[str, Any]) -> dict[str, Any]:
    if "$ref" not in schema:
        return schema
    ref = schema["$ref"]
    if not ref.startswith("#/"):
        raise AssertionError(f"unsupported schema reference: {ref}")
    node: Any = root
    for part in ref[2:].split("/"):
        node = node[part]
    return node


def validate(value: Any, schema: dict[str, Any], root: dict[str, Any], path: str = "$") -> None:
    schema = resolve(schema, root)
    for branch in schema.get("allOf", []):
        validate(value, branch, root, path)
    if "if" in schema:
        try:
            validate(value, schema["if"], root, path)
        except AssertionError:
            if "else" in schema:
                validate(value, schema["else"], root, path)
        else:
            if "then" in schema:
                validate(value, schema["then"], root, path)
    if "oneOf" in schema:
        valid_branches = 0
        for branch in schema["oneOf"]:
            try:
                validate(value, branch, root, path)
                valid_branches += 1
            except AssertionError:
                pass
        if valid_branches != 1:
            fail(path, "must match exactly one oneOf branch")
        return
    if "const" in schema and value != schema["const"]:
        fail(path, f"must equal {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        fail(path, f"must be one of {schema['enum']!r}")
    kinds = schema.get("type")
    kinds = kinds if isinstance(kinds, list) else [kinds] if kinds else []
    if not kinds and "properties" in schema:
        # JSON Schema's properties keyword applies to object instances even when
        # the author omits an explicit type declaration (as conditional branches do).
        kinds = ["object"]
    if value is None and "null" in kinds:
        return
    if kinds and "object" in kinds:
        if not isinstance(value, dict): fail(path, "must be an object")
        for name in schema.get("required", []):
            if name not in value: fail(path, f"missing required property {name!r}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for name in value:
                if name not in properties: fail(path, f"unexpected property {name!r}")
        for name, item in value.items():
            child = properties.get(name, schema.get("additionalProperties"))
            if isinstance(child, dict): validate(item, child, root, f"{path}.{name}")
        if len(value) < schema.get("minProperties", 0): fail(path, "has too few properties")
    elif "array" in kinds:
        if not isinstance(value, list): fail(path, "must be an array")
        if len(value) < schema.get("minItems", 0): fail(path, "has too few items")
        for index, item in enumerate(value): validate(item, schema.get("items", {}), root, f"{path}[{index}]")
    elif "string" in kinds:
        if not isinstance(value, str): fail(path, "must be a string")
        if len(value) < schema.get("minLength", 0): fail(path, "is shorter than minLength")
        if "pattern" in schema and not re.fullmatch(schema["pattern"], value): fail(path, "does not match pattern")
        if schema.get("format") == "date-time":
            try: datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError: fail(path, "must be an RFC3339 date-time")
        if schema.get("format") == "ipv4":
            octets = value.split(".")
            if len(octets) != 4 or any(not p.isdigit() or not 0 <= int(p) <= 255 for p in octets): fail(path, "must be IPv4")
    elif "integer" in kinds:
        if not isinstance(value, int) or isinstance(value, bool): fail(path, "must be an integer")
    elif "number" in kinds:
        if not isinstance(value, (int, float)) or isinstance(value, bool): fail(path, "must be a number")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if value < schema.get("minimum", value): fail(path, "is below minimum")
        if value > schema.get("maximum", value): fail(path, "is above maximum")


def test_examples_validate() -> None:
    examples = sorted(FIXTURES.glob("*.example.json"))
    assert len(examples) == 5, "Stage 0 must contain exactly five contract examples"
    schemas = sorted(CONTRACTS.glob("*.schema.json"))
    assert len(schemas) == 5, "Stage 0 must contain exactly five versioned contracts"
    for example_path in examples:
        example = json.loads(example_path.read_text(encoding="utf-8"))
        schema_ref = example.pop("$schema", None)
        assert schema_ref, f"{example_path.name} has no $schema declaration"
        schema_path = (example_path.parent / schema_ref).resolve()
        assert schema_path.parent == CONTRACTS.resolve(), f"{example_path.name} references a non-contract schema"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        validate(example, schema, schema)
        print(f"PASS {example_path.name} -> {schema_path.name}")


def test_passport_state_rules() -> None:
    schema = json.loads((CONTRACTS / "telemetry_passport.schema.json").read_text(encoding="utf-8"))
    unmeasured = {
        "schema_version": "1.1", "source_id": "new-source",
        "parser": {"id": "new.source", "version": "1.0.0"},
        "validation": {"status": "NOT_YET_MEASURED", "run_id": None, "completed_at": None},
        "certification": {"status": "NOT_CERTIFIED", "timestamp": None},
        "scores": {key: "NOT YET MEASURED" for key in ["extraction_accuracy", "semantic_accuracy", "raw_retention", "unknown_field_retention", "detection_preservation"]},
        "drift": {"state": "NOT_YET_MEASURED", "observed_at": None},
    }
    validate(unmeasured, schema, schema)
    unmeasured["scores"]["semantic_accuracy"] = 0.99
    try:
        validate(unmeasured, schema, schema)
    except AssertionError:
        print("PASS telemetry passport rejects an uncertified numeric metric")
    else:
        raise AssertionError("uncertified passport must not expose a numeric metric")


def test_no_future_stage_service_code() -> None:
    """Guard: Stage 14 permits assurance code but not future platform/API work."""
    reserved = [ROOT / "apps" / "control-api", ROOT / "apps" / "web", ROOT / "infra"]
    nonempty = [path.relative_to(ROOT) for folder in reserved for path in folder.rglob("*") if path.is_file() and path.suffix in CODE_SUFFIXES and path.read_text(encoding="utf-8").strip()]
    assert not nonempty, f"Stage 14 cannot include future-stage service/runtime code: {nonempty}"


if __name__ == "__main__":
    test_examples_validate()
    test_passport_state_rules()
    test_no_future_stage_service_code()
    print("PASS Stage 14 contract gate")
