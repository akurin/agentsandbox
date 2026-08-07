VENV ?= .venv
PY := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

.PHONY: help install test test-integration lint vm-image vm-prepare doctor clean

help:
	@echo "make install           create .venv and install agentsandbox (editable)"
	@echo "make test              run the fast test suite (no VM boot)"
	@echo "make test-integration  boot real guests and exercise them end to end"
	@echo "make lint              ruff check"
	@echo "make vm-image          build the golden guest disk image"
	@echo "make vm-prepare        bake the guest packages into that image (run once)"
	@echo "make doctor            check host prerequisites"

$(VENV):
	python3 -m venv $(VENV)

install: $(VENV)
	$(PIP) install -q -e ".[dev]"
	@echo "installed. try: $(VENV)/bin/asbx doctor"

test:
	$(PY) -m pytest -q

test-integration:
	$(PY) -m pytest -q tests_integration

lint:
	$(VENV)/bin/ruff check src tests --select F,E9

vm-image:
	./vm/build-image.sh

vm-prepare:
	./vm/prepare-image.sh

doctor:
	$(VENV)/bin/asbx doctor

clean:
	rm -rf build dist *.egg-info .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
