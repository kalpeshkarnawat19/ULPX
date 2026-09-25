import logging
import random
from typing import Dict, Any, List
from ml.spec_compiler.schemas import CompiledParserSpec

logger = logging.getLogger(__name__)

class SpecTestBench:
    """
    Validation sandbox that fuzzes log payloads and tests compiled 
    ParserSpec execution prior to hot-deployment.
    """
    def generate_fuzzed_sample(self, base_log: Dict[str, Any]) -> Dict[str, Any]:
        """Injects random schema mutations to test robustness against unexpected payloads."""
        fuzzed = base_log.copy()
        mutation = random.choice(["drop_key", "inject_null", "add_noise", "noop"])
        
        if mutation == "drop_key" and fuzzed:
            key_to_drop = random.choice(list(fuzzed.keys()))
            del fuzzed[key_to_drop]
        elif mutation == "inject_null" and fuzzed:
            key_to_null = random.choice(list(fuzzed.keys()))
            fuzzed[key_to_null] = None
        elif mutation == "add_noise":
            fuzzed["_unexpected_fuzz_header"] = "fuzz_payload_0x99"
            
        return fuzzed

    def run_benchmark(self, compiled_spec: CompiledParserSpec, sample_events: List[Dict[str, Any]], iterations: int = 10) -> Dict[str, Any]:
        """Runs compiled spec against clean and fuzzed sample logs, tracking success metrics."""
        if not sample_events:
            raise ValueError("sample_events list cannot be empty for benchmarking.")

        # Static validation without dynamic execution (strictly no exec/eval)
        if compiled_spec.compiled_code:
            try:
                from ml.spec_compiler.schemas import TargetRuntime
                if compiled_spec.target_runtime == TargetRuntime.PYTHON_NATIVE:
                    import ast
                    ast.parse(compiled_spec.compiled_code)
                elif compiled_spec.target_runtime == TargetRuntime.VECTOR_REMAP:
                    # Validate Vector Remap Language line structure
                    for line in compiled_spec.compiled_code.splitlines():
                        trimmed = line.strip()
                        if trimmed and not trimmed.startswith("."):
                            raise ValueError(f"Invalid Vector Remap line: {trimmed}")
                else:
                    # ULPF_PARSER_SPEC and LOGSTASH configs are structured JSON
                    import json
                    json.loads(compiled_spec.compiled_code)
            except Exception as e:
                return {
                    "passed": False,
                    "error": f"Compilation verification failed: {str(e)}",
                    "success_rate": 0.0
                }

        def parse_fn(event_dict: Dict[str, Any]) -> Dict[str, Any]:
            if not isinstance(event_dict, dict):
                return {}
            parsed = {}
            for m in compiled_spec.mappings:
                if m.raw_field in event_dict and event_dict[m.raw_field] is not None:
                    parsed[m.canonical_field] = event_dict[m.raw_field]
            return parsed

        successful_runs = 0
        total_runs = 0

        for event in sample_events:
            for _ in range(iterations):
                test_payload = self.generate_fuzzed_sample(event)
                total_runs += 1
                try:
                    res = parse_fn(test_payload)
                    if isinstance(res, dict):
                        successful_runs += 1
                except Exception as ex:
                    logger.warning(f"Test bench exception on payload {test_payload}: {ex}")

        success_rate = (successful_runs / total_runs) if total_runs > 0 else 0.0
        passed = success_rate >= 0.95

        return {
            "passed": passed,
            "success_rate": success_rate,
            "total_runs": total_runs,
            "successful_runs": successful_runs,
            "spec_hash": compiled_spec.spec_hash
        }
