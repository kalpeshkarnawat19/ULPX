import json
import logging
from typing import Dict, Any, List, Optional
from ml.ai_assist.schemas import CANONICAL_SCHEMA_REGISTRY, PARSER_CANDIDATE_SCHEMA

logger = logging.getLogger(__name__)

class BaseLLMProvider:
    """Abstract base class for AI model execution backends (Ollama, OpenAI, REST)."""
    def generate(self, prompt: str) -> str:
        raise NotImplementedError("Subclasses must implement generate()")

class MockLLMProvider(BaseLLMProvider):
    """Deterministic offline fallback provider for CI/CD and offline development."""
    def generate(self, prompt: str) -> str:
        data = json.loads(prompt)
        unmapped = data.get("unmapped_fields", [])
        mapped_fields = []
        unmapped_list = []

        for item in unmapped:
            raw_field = item.get("raw_field", "") if isinstance(item, dict) else str(item)
            field_lower = raw_field.lower()

            if "src" in field_lower and "ip" in field_lower:
                mapped_fields.append({
                    "raw_field": raw_field,
                    "canonical_field": "src.ip",
                    "confidence": 0.88,
                    "reasoning": "Matched src and ip in field name via mock model heuristics."
                })
            elif "dst" in field_lower or "dest" in field_lower:
                mapped_fields.append({
                    "raw_field": raw_field,
                    "canonical_field": "dest.ip",
                    "confidence": 0.85,
                    "reasoning": "Matched destination keyword via mock model heuristics."
                })
            elif "act" in field_lower or "action" in field_lower:
                mapped_fields.append({
                    "raw_field": raw_field,
                    "canonical_field": "event.action",
                    "confidence": 0.90,
                    "reasoning": "Matched action event indicator."
                })
            else:
                unmapped_list.append(raw_field)

        response = {
            "candidate_id": data.get("candidate_id", "cand_generated"),
            "source_format": data.get("source_format", "unknown"),
            "mapped_fields": mapped_fields,
            "unmapped_fields": unmapped_list
        }
        return json.dumps(response)

class LocalAIAssistant:
    """
    Control-plane AI Assistant for generating candidate field mappings
    when deterministic profilers and semantic mappers abstain.
    """
    def __init__(self, provider: Optional[BaseLLMProvider] = None):
        self.provider = provider or MockLLMProvider()
        self.schema = PARSER_CANDIDATE_SCHEMA
        self.canonical_registry = CANONICAL_SCHEMA_REGISTRY

    def sanitize_untrusted_input(self, text: str) -> str:
        """Sanitizes untrusted raw log samples to prevent prompt injection."""
        if not text:
            return ""
        # Escape quotes, backslashes, and control characters
        sanitized = text.replace("\\", "\\\\").replace('"', '\\"').replace("\x00", "")
        return sanitized

    def build_structured_prompt(self, candidate_id: str, source_format: str, unmapped_fields: List[Dict[str, Any]], log_sample: str) -> str:
        """Constructs an isolated, structured prompt wrapper."""
        clean_sample = self.sanitize_untrusted_input(log_sample)
        
        prompt_payload = {
            "instruction": "Map the provided unmapped raw fields to canonical target schemas.",
            "candidate_id": candidate_id,
            "source_format": source_format,
            "unmapped_fields": unmapped_fields,
            "raw_log_sample": clean_sample,
            "allowed_canonical_targets": sorted(list(self.canonical_registry)),
            "formatting_rules": [
                "Respond ONLY with valid JSON.",
                "Ensure every canonical_field matches allowed_canonical_targets exactly.",
                "Set confidence between 0.00 and 1.00."
            ]
        }
        return json.dumps(prompt_payload, indent=2)

    def validate_candidate_structure(self, candidate_data: Dict[str, Any]) -> bool:
        """Type-checks candidate payload against structural schema definitions."""
        if not isinstance(candidate_data, dict):
            return False

        required_keys = {"candidate_id", "source_format", "mapped_fields", "unmapped_fields"}
        if not required_keys.issubset(candidate_data.keys()):
            return False

        if not isinstance(candidate_data["candidate_id"], str):
            return False
        if not isinstance(candidate_data["source_format"], str):
            return False
        if not isinstance(candidate_data["mapped_fields"], list):
            return False
        if not isinstance(candidate_data["unmapped_fields"], list):
            return False

        for field in candidate_data["mapped_fields"]:
            if not isinstance(field, dict):
                return False
            field_keys = {"raw_field", "canonical_field", "confidence", "reasoning"}
            if not field_keys.issubset(field.keys()):
                return False
            if not isinstance(field["confidence"], (int, float)):
                return False

        return True

    def filter_hallucinated_fields(self, candidate_data: Dict[str, Any]) -> Dict[str, Any]:
        """Filters out proposed canonical mappings that do not exist in the canonical schema registry."""
        valid_mapped = []
        unmapped_list = list(candidate_data.get("unmapped_fields", []))

        for entry in candidate_data.get("mapped_fields", []):
            canonical = entry.get("canonical_field", "")
            if canonical in self.canonical_registry:
                valid_mapped.append(entry)
            else:
                logger.warning(f"Filtered hallucinated target field: {canonical}")
                raw_field = entry.get("raw_field")
                if raw_field and raw_field not in unmapped_list:
                    unmapped_list.append(raw_field)

        candidate_data["mapped_fields"] = valid_mapped
        candidate_data["unmapped_fields"] = unmapped_list
        return candidate_data

    def propose_mappings(self, candidate_id: str, source_format: str, unmapped_fields: List[Dict[str, Any]], log_sample: str) -> Dict[str, Any]:
        """Generates, parses, validates, and filters candidate mappings."""
        prompt = self.build_structured_prompt(candidate_id, source_format, unmapped_fields, log_sample)
        
        raw_response = self.provider.generate(prompt)
        
        try:
            candidate_json = json.loads(raw_response)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM response as JSON: {e}")
            raise ValueError("LLM response is not valid JSON.")

        if not self.validate_candidate_structure(candidate_json):
            raise ValueError("LLM candidate output failed structural schema validation.")

        filtered_candidate = self.filter_hallucinated_fields(candidate_json)
        return filtered_candidate
