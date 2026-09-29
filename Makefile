.PHONY: check syntax lint test validate diff-check collect hardware-check version

PYTHON ?= python3

## check: run every source-level gate used by CI
check: syntax lint validate test diff-check

syntax:
	bash -n scripts/*.sh scripts/lib/*.sh
	$(PYTHON) -m py_compile scripts/*.py

lint:
	shellcheck -x scripts/*.sh scripts/lib/*.sh

validate:
	$(PYTHON) scripts/validate-evidence.py rescue-ai/v1/fixtures/valid-sanitized-opencode-go.json
	! $(PYTHON) scripts/validate-evidence.py rescue-ai/v1/fixtures/invalid-raw-ai-fields.json >/dev/null 2>&1

test:
	$(PYTHON) -m unittest discover -s tests -v

diff-check:
	git diff --check

collect:
	./scripts/collect-evidence.sh --output evidence.json

hardware-check:
	$(PYTHON) scripts/check-hardware-readiness.py --mode auto --output /tmp/rescue-hardware-readiness.json

version:
	@cat VERSION
