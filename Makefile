.PHONY: validate collect

validate:
	python3 scripts/validate-evidence.py rescue-ai/v1/fixtures/valid-sanitized-opencode-go.json

collect:
	./scripts/collect-evidence.sh --output evidence.json
