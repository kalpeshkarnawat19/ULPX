PYTHON ?= python3

.PHONY: test-contracts test-ingest test-firewall test-parser test-ir test-lineage test-exporters test-passport test

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

test-passport:
	$(PYTHON) tests/contracts/test_schemas.py
	$(PYTHON) tests/passport/test_passport.py

test: test-contracts test-ingest test-firewall test-parser test-ir test-lineage test-exporters test-passport

