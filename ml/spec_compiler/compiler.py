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

    def generate_compiled_code(self, mappings: List[FieldMapping], target_runtime: TargetRuntime) -> str:
        """Generates target execution code based on the runtime format."""
        if target_runtime == TargetRuntime.PYTHON_NATIVE:
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

    def compile_spec(self, candidate_package: Dict[str, Any], reviewer_overrides: Optional[Dict[str, str]] = None, target_runtime: TargetRuntime = TargetRuntime.PYTHON_NATIVE) -> CompiledParserSpec:
        """Executes full compilation pipeline emitting an immutable CompiledParserSpec."""
        source_id = candidate_package.get("source_id", "unknown_source")
        mappings = self.merge_overrides(candidate_package, reviewer_overrides)
        
        compiled_code = self.generate_compiled_code(mappings, target_runtime)
        
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
