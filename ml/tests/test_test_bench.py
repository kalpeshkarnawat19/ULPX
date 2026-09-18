import pytest
from ml.spec_compiler.schemas import CompiledParserSpec, TargetRuntime, FieldMapping
from ml.test_bench.sandbox import SpecTestBench

def test_sandbox_benchmark_pass():
    bench = SpecTestBench()
    
    code = (
        "def parse_log(event: dict) -> dict:\n"
        "    parsed = {}\n"
        "    if 'src_ip' in event and event['src_ip']:\n"
        "        parsed['src.ip'] = event['src_ip']\n"
        "    return parsed"
    )
    
    spec = CompiledParserSpec(
        spec_id="spec_test_01",
        source_id="test_src",
        version=1,
        target_runtime=TargetRuntime.PYTHON_NATIVE,
        mappings=[FieldMapping(raw_field="src_ip", canonical_field="src.ip")],
        compiled_code=code,
        spec_hash="abc123hash"
    )
    
    samples = [{"src_ip": "192.168.1.1"}, {"src_ip": "10.0.0.1"}]
    report = bench.run_benchmark(spec, samples, iterations=5)
    
    assert report["passed"] is True
    assert report["success_rate"] >= 0.95
    assert report["total_runs"] == 10

def test_sandbox_empty_samples_raises():
    bench = SpecTestBench()
    spec = CompiledParserSpec(
        spec_id="spec_00", source_id="src", version=1, 
        target_runtime=TargetRuntime.PYTHON_NATIVE, mappings=[], 
        compiled_code="def parse_log(e): return {}", spec_hash="hash"
    )
    with pytest.raises(ValueError, match="sample_events list cannot be empty"):
        bench.run_benchmark(spec, [])
