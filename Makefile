PYTHON ?= python3

.PHONY: test-contracts test-ingest test-firewall test

test-contracts:
	$(PYTHON) tests/contracts/test_schemas.py

test-ingest:
	cd apps/ingest-gateway && go test -v -count=1 -run "TestNewRawEventEnvelope|TestLocalFSStore|TestIngestService|TestInMemoryBus|TestEnvelope|TestGoldenFixture" ./...

test-firewall:
	cd apps/ingest-gateway && go test -v -count=1 -run "TestFirewall" ./...

test: test-contracts test-ingest test-firewall
