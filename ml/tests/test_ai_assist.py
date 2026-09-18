import pytest
from ml.ai_assist.assistant import LocalAIAssistant

def test_prompt_sanitization():
    assistant = LocalAIAssistant()
    raw_untrusted = 'Log line with "injection" test \\ dangerous content'
    sanitized = assistant.sanitize_untrusted_input(raw_untrusted)
    assert '\\"' in sanitized
    assert '\\\\' in sanitized

def test_schema_validation_success():
    assistant = LocalAIAssistant()
    valid_spec = {
        "candidate_id": "cand_123",
        "source_format": "syslog",
        "mapped_fields": [
            {
                "raw_field": "client_ip",
                "canonical_field": "src.ip",
                "confidence": 0.89,
                "reasoning": "High similarity"
            }
        ],
        "unmapped_fields": ["custom_hdr"]
    }
    assert assistant.validate_candidate_spec(valid_spec) is True

def test_schema_validation_failure():
    assistant = LocalAIAssistant()
    invalid_spec = {
        "candidate_id": "cand_123",
    }
    assert assistant.validate_candidate_spec(invalid_spec) is False

def test_mock_propose_mappings():
    assistant = LocalAIAssistant()
    unmapped = [{"raw_field": "client_ip"}, {"raw_field": "unknown_value"}]
    log_sample = "2026-09-18 client_ip=192.168.1.1 unknown_value=abc"
    
    spec = assistant.propose_mappings_mock(
        candidate_id="cand_999",
        source_format="key_value",
        unmapped_fields=unmapped,
        log_sample=log_sample
    )
    
    assert spec["candidate_id"] == "cand_999"
    assert len(spec["mapped_fields"]) == 1
    assert spec["mapped_fields"][0]["canonical_field"] == "src.ip"
    assert "unknown_value" in spec["unmapped_fields"]
