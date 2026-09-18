PYTHON ?= python3

.PHONY: test-contracts test-ingest test-firewall test-parser test-ir test-lineage test-exporters test-passport test-detection-contracts test-dps test-profiler test-mapper test-ai-assist test-compiler test-onboarding test-validation test-drift test-ml test

test-contracts:
	$(PYTHON) tests/contracts/test_schemas.py

test-ingest:
	cd apps/ingest-gateway && go test -v -count=1 -run "TestNewRawEventEnvelope|TestLocalFSStore|TestIngestService|TestInMemoryBus|TestEnvelope|TestGoldenFixture" ./...

test-firewall:
	cd apps/ingest-gateway && go test -v -count=1 -run "TestFirewall" ./...

test-parser:
	cd packages/parser-runtime && go test -v -count=1 ./...

test-ir:
	cd apps/normalize-worker && go test -v -count=1 ./...

test-lineage:
	cd packages/parser-runtime && go test -v -count=1 -run "TestLineage" ./...
	cd apps/normalize-worker && go test -v -count=1 -run "TestLineage" ./...

test-exporters:
	cd packages/exporters && go test -v -count=1 ./...

test-detection-contracts:
	cd packages/detection-contracts && go test -v -count=1 -run "TestEngine" ./...

test-dps:
	cd packages/detection-contracts && go test -v -count=1 -run "TestDPS" ./...

test-passport:
	$(PYTHON) tests/contracts/test_schemas.py
	$(PYTHON) tests/passport/test_passport.py

test-profiler:
	$(PYTHON) -m pytest ml/tests/test_profiler.py -v

test-mapper:
	$(PYTHON) -m pytest ml/tests/test_semantic_mapper.py -v

test-ai-assist:
	$(PYTHON) -m pytest ml/tests/test_ai_assist.py -v

test-compiler:
	$(PYTHON) -m pytest ml/tests/test_spec_compiler.py -v

test-onboarding:
	$(PYTHON) -m pytest ml/tests/test_orchestrator.py ml/tests/test_deployer.py ml/tests/test_test_bench.py -v

test-validation:
	$(PYTHON) -m pytest ml/tests/test_validation.py -v

test-drift:
	$(PYTHON) -m pytest ml/tests/test_drift.py -v

test-ml:
	$(PYTHON) -m pytest ml/tests/ -v

test: test-contracts test-ingest test-firewall test-parser test-ir test-lineage test-exporters test-detection-contracts test-dps test-passport test-drift test-ml

