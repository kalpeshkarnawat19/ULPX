import hashlib
import json
import logging
from typing import Dict, Any, List, Optional
from ml.spec_compiler.schemas import TargetRuntime, FieldMapping, CompiledParserSpec

logger = logging.getLogger(__name__)

class SpecCompilerEngine:
    """
    Merges reviewer overrides with auto-generated candidate specs, validates schema integrity,
    and compiles final ParserSpec binaries for target runtime execution.
    """
    
    def merge_overrides(self, candidate_package: Dict[str, Any], reviewer_overrides: Optional[Dict[str, str]] = None) -> List[FieldMapping]:
        """Combines deterministic, AI-suggested, and manual reviewer field mappings."""
        resolved_mappings: Dict[str, FieldMapping] = {}
        overrides = reviewer_overrides or {}

        # 1. Process deterministic mappings from Stage 8
        for item in candidate_package.get("deterministic_mappings", []):
            raw = item.get("raw_field")
            canonical = item.get("canonical_field")
            if raw and canonical:
                resolved_mappings[raw] = FieldMapping(raw_field=raw, canonical_field=canonical)

        # 2. Process AI candidate specs from Stage 9
        for spec in candidate_package.get("ai_candidate_specs", []):
            for item in spec.get("mapped_fields", []):
                raw = item.get("raw_field")
                canonical = item.get("canonical_field")
                if raw and canonical and raw not in resolved_mappings:
                    resolved_mappings[raw] = FieldMapping(raw_field=raw, canonical_field=canonical)

        # 3. Apply manual reviewer overrides (Highest Priority)
        for raw, canonical in overrides.items():
            resolved_mappings[raw] = FieldMapping(
                raw_field=raw,
                canonical_field=canonical,
                override_applied=True
            )

        return list(resolved_mappings.values())

    def generate_ulpf_parser_spec(self, source_id: str, detected_format: str, mappings: List[FieldMapping]) -> Dict[str, Any]:
        """Generates a declarative ParserSpec conforming to packages/contracts/parser_spec.schema.json."""
        fmt_lower = detected_format.lower()
        if "json" in fmt_lower:
            match_fmt = "json"
            body_type = "json"
        elif "syslog" in fmt_lower:
            match_fmt = "syslog"
            body_type = "syslog"
        elif "cef" in fmt_lower:
            match_fmt = "cef"
            body_type = "cef"
        elif "leef" in fmt_lower:
            match_fmt = "leef"
            body_type = "leef"
        elif "csv" in fmt_lower or "tsv" in fmt_lower:
            match_fmt = "csv"
            body_type = "csv"
        else:
            match_fmt = "key_value"
            body_type = "key_value"

        import re
        clean_id = re.sub(r"[^a-z0-9._-]", "_", source_id.lower()).strip("_")
        if not clean_id or not clean_id[0].isalnum():
            clean_id = f"source_{clean_id}" if clean_id else "source_parser"

        fields_dict = {}
        for m in mappings:
            canon = m.canonical_field.lower()
            if "ip" in canon:
                field_type = "ip"
                transforms = ["trim", "ip"]
            elif "port" in canon or "status_code" in canon:
                field_type = "integer"
                transforms = ["integer"]
            elif "time" in canon or "timestamp" in canon:
                field_type = "timestamp"
                transforms = ["timestamp"]
            elif "is_" in canon or "enabled" in canon:
                field_type = "boolean"
                transforms = ["boolean"]
            else:
                field_type = "string"
                transforms = ["trim"]

            fields_dict[m.raw_field] = {
                "type": field_type,
                "map_to": m.canonical_field,
                "transformations": transforms
            }

        if not fields_dict:
            fields_dict["raw_message"] = {
                "type": "string",
                "map_to": "event.action",
                "transformations": ["trim"]
            }

        return {
            "dsl_version": "1.0",
            "parser": {
                "id": clean_id,
                "version": "1.0.0"
            },
            "match": {
                "format": match_fmt
            },
            "body_parser": {
                "type": body_type
            },
            "fields": fields_dict,
            "unknown_fields": {
                "policy": "preserve"
            },
            "raw": {
                "preserve": True
            }
        }

    def generate_compiled_code(self, mappings: List[FieldMapping], target_runtime: TargetRuntime, source_id: str = "unknown_source", detected_format: str = "key_value") -> str:
        """Generates target execution code based on the runtime format."""
        if target_runtime == TargetRuntime.ULPF_PARSER_SPEC:
            ulpf_spec = self.generate_ulpf_parser_spec(source_id, detected_format, mappings)
            return json.dumps(ulpf_spec, indent=2)

        elif target_runtime == TargetRuntime.PYTHON_NATIVE:
            lines = ["def parse_log(event: dict) -> dict:", "    parsed = {}"]
            for m in mappings:
                lines.append(f'    if "{m.raw_field}" in event:')
                lines.append(f'        parsed["{m.canonical_field}"] = event["{m.raw_field}"]')
            lines.append("    return parsed")
            return "\n".join(lines)
            
        elif target_runtime == TargetRuntime.VECTOR_REMAP:
            vrl_lines = []
            for m in mappings:
                vrl_lines.append(f'.{m.canonical_field} = delete(.{m.raw_field})')
            return "\n".join(vrl_lines)

        else:
            spec_dict = {m.raw_field: m.canonical_field for m in mappings}
            return json.dumps(spec_dict, indent=2)

    def compile_spec(self, candidate_package: Dict[str, Any], reviewer_overrides: Optional[Dict[str, str]] = None, target_runtime: TargetRuntime = TargetRuntime.ULPF_PARSER_SPEC) -> CompiledParserSpec:
        """Executes full compilation pipeline emitting an immutable CompiledParserSpec."""
        source_id = candidate_package.get("source_id", "unknown_source")
        detected_format = candidate_package.get("detected_format", "key_value")
        mappings = self.merge_overrides(candidate_package, reviewer_overrides)
        
        compiled_code = self.generate_compiled_code(mappings, target_runtime, source_id, detected_format)
        
        hash_payload = f"{source_id}:{compiled_code}".encode("utf-8")
        spec_hash = hashlib.sha256(hash_payload).hexdigest()[:16]

        return CompiledParserSpec(
            spec_id=f"spec_{source_id}_{spec_hash}",
            source_id=source_id,
            version=1,
            target_runtime=target_runtime,
            mappings=mappings,
            compiled_code=compiled_code,
            spec_hash=spec_hash
        )
