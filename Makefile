PYTHON ?= python3

.PHONY: test-contracts

test-contracts:
	$(PYTHON) tests/contracts/test_schemas.py
