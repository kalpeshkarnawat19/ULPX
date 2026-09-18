import json
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class LocalAIAssistant:
    def __init__(self, model_name: str = "local-fallback"):
        self.model_name = model_name

    def sanitize_untrusted_input(self, text: str) -> str:
        return text.replace("\\", "\\\\").replace('"', '\\"')

    def generate_prompt(self, unmapped_fields: List[Dict[str, Any]], log_sample: str) -> str:
        clean_sample = self.sanitize_untrusted_input(log_sample)
        prompt = {
            "instruction": "Propose canonical field mappings for the provided unmapped raw fields.",
            "unmapped_fields": unmapped_fields,
            "raw_log_sample": clean_sample,
            "formatting_rule": "Output strictly valid JSON matching the ParserCandidate schema."
        }
        return json.dumps(prompt, indent=2)

    def validate_candidate_spec(self, candidate_data: Dict[str, Any]) -> bool:
        if not isinstance(candidate_data, dict):
            return False
        
        required_keys = {"candidate_id", "source_format", "mapped_fields"}
        if not required_keys.issubset(candidate_data.keys()):
            return False

        if not isinstance(candidate_data.get("candidate_id"), str):
            return False
        if not isinstance(candidate_data.get("source_format"), str):
            return False
        if not isinstance(candidate_data.get("mapped_fields"), list):
            return False

        for field in candidate_data["mapped_fields"]:
            if not isinstance(field, dict):
                return False
            field_keys = {"raw_field", "canonical_field", "confidence"}
            if not field_keys.issubset(field.keys()):
                return False

        return True

    def propose_mappings_mock(self, candidate_id: str, source_format: str, unmapped_fields: List[Dict[str, Any]], log_sample: str) -> Dict[str, Any]:
        mapped = []
        unmapped_list = []

        for field in unmapped_fields:
            raw_name = field.get("raw_field", "")
            if "ip" in raw_name.lower():
                mapped.append({
                    "raw_field": raw_name,
                    "canonical_field": "src.ip" if "src" in raw_name.lower() or "client" in raw_name.lower() else "dest.ip",
                    "confidence": 0.88,
                    "reasoning": "Inferred from field name heuristic in AI assistant."
                })
            else:
                unmapped_list.append(raw_name)

        candidate_spec = {
            "candidate_id": candidate_id,
            "source_format": source_format,
            "mapped_fields": mapped,
            "unmapped_fields": unmapped_list
        }

        if self.validate_candidate_spec(candidate_spec):
            return candidate_spec
        else:
            raise ValueError("Generated candidate spec failed schema validation.")
