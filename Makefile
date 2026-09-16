PYTHON ?= python3

.PHONY: test-contracts test-ingest test

test-contracts:
	$(PYTHON) tests/contracts/test_schemas.py

test-ingest:
	cd apps/ingest-gateway && go test -v -count=1 ./...

test: test-contracts test-ingest
