.PHONY: check syntax lint test validate docs diff-check collect hardware-check version

PYTHON ?= python3

## check: run every source-level gate used by CI
check: syntax lint validate docs test diff-check

syntax:
	bash -n scripts/*.sh scripts/lib/*.sh host/rescue-linux.sh
	$(PYTHON) -m py_compile scripts/*.py scripts/lib/*.py scripts/rescue_modules/*.py
	$(PYTHON) scripts/lib/repair_catalog.py
	@if command -v zsh >/dev/null 2>&1; then zsh -n host/RESCUE-MACOS.command && echo 'zsh -n host/RESCUE-MACOS.command: ok'; else echo 'zsh not installed: macOS launcher syntax check skipped'; fi
	@if command -v pwsh >/dev/null 2>&1; then pwsh -NoProfile -Command '$$e=$$null; [void][System.Management.Automation.Language.Parser]::ParseFile("host/rescue-windows.ps1",[ref]$$null,[ref]$$e); if ($$e -and $$e.Count) { $$e | ForEach-Object Message; exit 1 } else { "pwsh parse host/rescue-windows.ps1: ok" }'; else echo 'pwsh not installed: Windows launcher parse check skipped'; fi

lint:
	shellcheck -x scripts/*.sh scripts/lib/*.sh host/rescue-linux.sh

validate:
	$(PYTHON) scripts/validate-evidence.py rescue-ai/v1/fixtures/valid-*.json
	! $(PYTHON) scripts/validate-evidence.py rescue-ai/v1/fixtures/invalid-raw-ai-fields.json >/dev/null 2>&1
	! $(PYTHON) scripts/validate-evidence.py rescue-ai/v1/fixtures/invalid-text-value-1.1.json >/dev/null 2>&1
	! $(PYTHON) scripts/validate-evidence.py rescue-ai/v1/fixtures/invalid-1.2-fields-in-1.1.json >/dev/null 2>&1
	! $(PYTHON) scripts/validate-evidence.py rescue-ai/v1/fixtures/invalid-1.3-fields-in-1.2.json >/dev/null 2>&1
	! $(PYTHON) scripts/validate-evidence.py rescue-ai/v1/fixtures/invalid-android-serial.json >/dev/null 2>&1
	! $(PYTHON) scripts/validate-evidence.py rescue-ai/v1/fixtures/invalid-printer-queue.json >/dev/null 2>&1
	$(PYTHON) scripts/rescue-report.py --validate rescue-ai/v1/fixtures/run-report-valid-*.json
	for f in rescue-ai/v1/fixtures/run-report-invalid-*.json; do ! $(PYTHON) scripts/rescue-report.py --validate "$$f" >/dev/null 2>&1 || { echo "$$f was accepted"; exit 1; }; done

docs:
	$(PYTHON) scripts/check-docs.py

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
