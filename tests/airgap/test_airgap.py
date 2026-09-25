"""Stage 20: verify the non-frontend pipeline remains local when networking is unavailable."""
from __future__ import annotations

import json
import socket
import sys
import ast
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ml.orchestrator.orchestrator import OnboardingOrchestrator  # noqa: E402
from ml.passport.passport import TelemetryPassportBuilder  # noqa: E402
from ml.validation.validator import ValidationEngine  # noqa: E402


def test_offline_artifacts_are_declared_and_local() -> None:
    manifest = json.loads((ROOT / "infra/airgap/artifact-manifest.json").read_text(encoding="utf-8"))
    assert manifest["deployment_mode"] == "air_gap"
    assert manifest["frontend"]["included"] is False
    assert all((ROOT / path).is_file() for path in manifest["schemas"])
    assert all((ROOT / model["path"]).is_file() and model["network_requirement"] == "none" for model in manifest["models"])
    for image in manifest["images"]:
        assert "/" not in image["tag"].split(":")[0], f"remote image reference: {image['tag']}"
        assert image["pull_policy"] == "never"

    compose = (ROOT / "infra/airgap/compose.offline.yml").read_text(encoding="utf-8")
    assert "pull_policy: never" in compose
    assert "internal: true" in compose
    assert "apps/web" not in compose and "web:" not in compose
    assert "http://" not in compose and "https://" not in compose


def test_runtime_sources_have_no_network_client_dependency() -> None:
    forbidden_python_imports = {"requests", "urllib", "httpx", "aiohttp", "websocket"}
    for path in (ROOT / "ml").rglob("*.py"):
        if "tests" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        assert not (imported & forbidden_python_imports), f"network dependency in {path.relative_to(ROOT)}"
    for path in list((ROOT / "apps").rglob("*.go")) + list((ROOT / "packages").rglob("*.go")):
        if path.name.endswith("_test.go"):
            continue
        content = path.read_text(encoding="utf-8")
        forbidden_go_calls = ("http.Get(", "http.Post(", "http.NewRequest(", "http.Client{", "net.Dial(")
        assert not any(call in content for call in forbidden_go_calls), f"outbound network client in {path.relative_to(ROOT)}"


def test_onboarding_validation_and_passport_run_with_connections_blocked() -> None:
    def blocked(*_args, **_kwargs):
        raise AssertionError("outbound networking is forbidden in air-gap validation")

    with patch.object(socket.socket, "connect", blocked):
        onboarding = OnboardingOrchestrator().run_pipeline(
            "airgap-demo", ["src_ip=10.0.0.5 dst_ip=10.0.0.10 action=deny"]
        )
        assert onboarding["source_id"] == "airgap-demo"

        report = ValidationEngine().validate_golden_source(ROOT / "fixtures/golden/syslog_firewall")
        assert report.passed
        passport = TelemetryPassportBuilder().build(
            report.source_id, report.parser_id, report.parser_version,
            report.to_evidence(run_id="airgap-syslog-firewall"),
        )
        assert passport["certification"]["status"] == "CERTIFIED"
        assert all(isinstance(score, (int, float)) for score in passport["scores"].values())


if __name__ == "__main__":
    test_offline_artifacts_are_declared_and_local()
    test_runtime_sources_have_no_network_client_dependency()
    test_onboarding_validation_and_passport_run_with_connections_blocked()
    print("PASS Stage 20 air-gap gate")
