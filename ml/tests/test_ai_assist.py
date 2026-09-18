import pytest
import json
from ml.ai_assist.assistant import LocalAIAssistant, BaseLLMProvider, MockLLMProvider

def test_prompt_sanitization():
    assistant = LocalAIAssistant()
    raw_untrusted = 'Log line with "injection" attempt \\ payload\x00 test'
    sanitized = assistant.sanitize_untrusted_input(raw_untrusted)
    assert '\\"' in sanitized
    assert '\\\\' in sanitized
    assert '\x00' not in sanitized

def test_structural_schema_validation():
    assistant = LocalAIAssistant()
    valid_spec = {
        "candidate_id": "cand_123",
        "source_format": "syslog",
        "mapped_fields": [
            {
                "raw_field": "client_ip",
                "canonical_field": "src.ip",
                "confidence": 0.89,
                "reasoning": "High similarity score"
            }
        ],
        "unmapped_fields": ["unknown_hdr"]
    }
    assert assistant.validate_candidate_structure(valid_spec) is True

def test_structural_schema_validation_failure():
    assistant = LocalAIAssistant()
    invalid_spec = {
        "candidate_id": "cand_123",
        "source_format": "syslog",
        "mapped_fields": "not_a_list",
        "unmapped_fields": []
    }
    assert assistant.validate_candidate_structure(invalid_spec) is False

def test_filter_hallucinated_canonical_fields():
    assistant = LocalAIAssistant()
    raw_spec = {
        "candidate_id": "cand_001",
        "source_format": "json",
        "mapped_fields": [
            {
                "raw_field": "src_ip",
                "canonical_field": "src.ip",  # Valid
                "confidence": 0.9,
                "reasoning": "Valid"
            },
            {
                "raw_field": "fake_field",
                "canonical_field": "nonexistent.canonical.field",  # Hallucinated!
                "confidence": 0.9,
                "reasoning": "Hallucinated"
            }
        ],
        "unmapped_fields": []
    }
    
    filtered = assistant.filter_hallucinated_fields(raw_spec)
    assert len(filtered["mapped_fields"]) == 1
    assert filtered["mapped_fields"][0]["canonical_field"] == "src.ip"
    assert "fake_field" in filtered["unmapped_fields"]

def test_end_to_end_mock_provider():
    assistant = LocalAIAssistant(provider=MockLLMProvider())
    unmapped = [{"raw_field": "src_ip_val"}, {"raw_field": "act_code"}, {"raw_field": "custom_data"}]
    log_sample = "2026-09-18 src_ip_val=192.168.1.1 act_code=DENY custom_data=xyz"

    spec = assistant.propose_mappings(
        candidate_id="cand_test_01",
        source_format="kv",
        unmapped_fields=unmapped,
        log_sample=log_sample
    )

    assert spec["candidate_id"] == "cand_test_01"
    assert len(spec["mapped_fields"]) == 2
    canonical_targets = {m["canonical_field"] for m in spec["mapped_fields"]}
    assert "src.ip" in canonical_targets
    assert "event.action" in canonical_targets
    assert "custom_data" in spec["unmapped_fields"]

class MalformedJSONProvider(BaseLLMProvider):
    def generate(self, prompt: str) -> str:
        return "Invalid JSON text output from broken model"

def test_malformed_json_provider_raises_error():
    assistant = LocalAIAssistant(provider=MalformedJSONProvider())
    with pytest.raises(ValueError, match="LLM response is not valid JSON."):
        assistant.propose_mappings("cand_err", "kv", [], "sample log")
