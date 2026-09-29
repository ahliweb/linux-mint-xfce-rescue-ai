#!/usr/bin/env python3
import json
import sys
from pathlib import Path

try:
    import jsonschema
except ImportError:
    print('jsonschema is required: sudo apt install python3-jsonschema', file=sys.stderr)
    raise SystemExit(2)

root = Path(__file__).resolve().parents[1]
schema = json.loads((root / 'rescue-ai/v1/rescue-evidence.schema.json').read_text())
data = json.loads(Path(sys.argv[1]).read_text())
jsonschema.Draft202012Validator(schema).validate(data)
print('evidence: valid')
