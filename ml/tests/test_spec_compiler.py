import pytest
from ml.spec_compiler.compiler import SpecCompilerEngine
from ml.spec_compiler.schemas import TargetRuntime

def test_compiler_merge_overrides():
    compiler = SpecCompilerEngine()
    
    mock_package = {
        "source_id": "fw_log_stream",
        "deterministic_mappings": [
            {"raw_field": "src_ip", "canonical_field": "src.ip"}
        ],
        "ai_candidate_specs": [
            {
                "mapped_fields": [
                    {"raw_field": "dst_ip", "canonical_field": "dest.ip"},
                    {"raw_field": "act", "canonical_field": "event.action"}
                ]
            }
        ]
    }
    
    overrides = {"act": "event.outcome"}
    
    compiled = compiler.compile_spec(mock_package, reviewer_overrides=overrides, target_runtime=TargetRuntime.PYTHON_NATIVE)
    
    assert compiled.source_id == "fw_log_stream"
    assert len(compiled.mappings) == 3
    
    act_mapping = next(m for m in compiled.mappings if m.raw_field == "act")
    assert act_mapping.canonical_field == "event.outcome"
    assert act_mapping.override_applied is True
    
    assert "def parse_log(event: dict) -> dict:" in compiled.compiled_code
    assert compiled.spec_hash is not None

def test_compiler_vector_runtime():
    compiler = SpecCompilerEngine()
    mock_package = {
        "source_id": "syslog_stream",
        "deterministic_mappings": [{"raw_field": "host", "canonical_field": "src.host"}]
    }
    
    compiled = compiler.compile_spec(mock_package, target_runtime=TargetRuntime.VECTOR_REMAP)
    assert compiled.target_runtime == TargetRuntime.VECTOR_REMAP
    assert ".src.host = delete(.host)" in compiled.compiled_code
