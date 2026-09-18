import pytest
from ml.orchestrator.orchestrator import OnboardingOrchestrator

def test_orchestrator_end_to_end_success():
    orchestrator = OnboardingOrchestrator()
    sample_logs = [
        "2026-09-18T10:00:00Z client_ip=192.168.1.10 action=ALLOW dest_ip=10.0.0.1",
        "2026-09-18T10:00:01Z client_ip=10.0.0.5 action=DENY dest_ip=10.0.0.2"
    ]

    package = orchestrator.run_pipeline(source_id="src_fw_01", log_lines=sample_logs)

    assert package["source_id"] == "src_fw_01"
    assert "status" in package
    assert package["status"] in ["AUTO_APPROVED", "READY_FOR_REVIEW"]
    assert "deterministic_mappings" in package
    assert "ai_candidate_specs" in package
    assert package["metadata"]["total_fields"] >= 0

def test_orchestrator_empty_logs_raises_value_error():
    orchestrator = OnboardingOrchestrator()
    with pytest.raises(ValueError, match="log_lines list cannot be empty."):
        orchestrator.run_pipeline("src_empty", [])
