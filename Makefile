.PHONY: validate collect hardware-check

validate:
	python3 scripts/validate-evidence.py rescue-ai/v1/fixtures/valid-sanitized-opencode-go.json

collect:
	./scripts/collect-evidence.sh --output evidence.json

hardware-check:
	python3 scripts/check-hardware-readiness.py --mode auto --output /tmp/rescue-hardware-readiness.json
