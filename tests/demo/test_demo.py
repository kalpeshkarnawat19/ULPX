"""Stage 21 deterministic non-frontend demo gate."""
from pathlib import Path
import importlib.util

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools/demo/rehearse.py"
spec = importlib.util.spec_from_file_location("demo_rehearsal", MODULE_PATH)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_rehearsal_is_repeatable_and_uses_measured_evidence():
    first = module.run_rehearsal()
    second = module.run_rehearsal()
    assert first == second
    assert first["frontend"] == "NOT_IMPLEMENTED"
    assert len(first["sources"]) == 2
    for source in first["sources"]:
        assert source["certification"] == "CERTIFIED"
        assert source["drift_state"] in {"STABLE", "SUSPECTED", "DRIFTED"}
        assert all(isinstance(value, (int, float)) for value in source["scores"].values())


def test_reset_script_targets_only_generated_demo_work():
    reset = (ROOT / "tools/demo/reset.ps1").read_text(encoding="utf-8")
    assert "work\\demo" in reset
    assert "fixtures" not in reset
    assert "Remove-Item" in reset


if __name__ == "__main__":
    test_rehearsal_is_repeatable_and_uses_measured_evidence()
    test_reset_script_targets_only_generated_demo_work()
    print("PASS Stage 21 demo-check gate")
