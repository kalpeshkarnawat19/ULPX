import pytest
from ml.spec_compiler.schemas import CompiledParserSpec, TargetRuntime
from ml.deployment.deployer import SpecDeploymentEngine

def test_deploy_and_rollback_success():
    deployer = SpecDeploymentEngine()
    
    spec_v1 = CompiledParserSpec(
        spec_id="spec_v1", source_id="firewall", version=1,
        target_runtime=TargetRuntime.PYTHON_NATIVE, mappings=[],
        compiled_code="def parse_log(e): return e", spec_hash="hash_1"
    )
    spec_v2 = CompiledParserSpec(
        spec_id="spec_v2", source_id="firewall", version=2,
        target_runtime=TargetRuntime.PYTHON_NATIVE, mappings=[],
        compiled_code="def parse_log(e): return {}", spec_hash="hash_2"
    )
    
    # Deploy V1
    res1 = deployer.deploy_spec(spec_v1, validation_passed=True)
    assert res1["status"] == "DEPLOYED"
    assert deployer.get_active_spec("firewall").spec_id == "spec_v1"
    
    # Deploy V2 (stores V1 in history)
    res2 = deployer.deploy_spec(spec_v2, validation_passed=True)
    assert res2["status"] == "DEPLOYED"
    assert deployer.get_active_spec("firewall").spec_id == "spec_v2"
    
    # Rollback back to V1
    rb = deployer.rollback("firewall")
    assert rb["status"] == "ROLLED_BACK"
    assert deployer.get_active_spec("firewall").spec_id == "spec_v1"

def test_deploy_failed_validation_raises():
    deployer = SpecDeploymentEngine()
    spec = CompiledParserSpec(
        spec_id="spec_fail", source_id="src", version=1,
        target_runtime=TargetRuntime.PYTHON_NATIVE, mappings=[],
        compiled_code="", spec_hash="hash"
    )
    with pytest.raises(ValueError, match="Test bench validation failed"):
        deployer.deploy_spec(spec, validation_passed=False)
