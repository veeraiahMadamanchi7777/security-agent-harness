#!/usr/bin/env python3
"""Validate Security Agent Harness JSONL findings without third-party dependencies.

Usage: python3 tools/validate_findings.py .github/sast-findings.jsonl
Exit code 0 means every nonempty line passed; 1 means validation failed.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / ".github" / "schemas" / "finding.schema.json"


def validate(record, schema):
    errors = []
    if not isinstance(record, dict):
        return ["finding must be a JSON object"]
    properties = schema["properties"]
    for field in schema["required"]:
        if field not in record:
            errors.append(f"missing required field: {field}")
    for key, value in record.items():
        if key not in properties:
            errors.append(f"unexpected field: {key}")
            continue
        spec = properties[key]
        types = spec.get("type")
        if types:
            types = types if isinstance(types, list) else [types]
            matches = {
                "string": lambda v: isinstance(v, str),
                "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
                "boolean": lambda v: isinstance(v, bool),
                "array": lambda v: isinstance(v, list),
                "null": lambda v: v is None,
            }
            if not any(matches[t](value) for t in types):
                errors.append(f"{key}: invalid type")
                continue
        if "enum" in spec and value not in spec["enum"]:
            errors.append(f"{key}: value not in allowed enum")
        if "pattern" in spec and not re.fullmatch(spec["pattern"], value):
            errors.append(f"{key}: invalid format")
        if "minimum" in spec and value < spec["minimum"]:
            errors.append(f"{key}: below minimum")
        if isinstance(value, list) and "items" in spec:
            item_spec = spec["items"]
            for i, item in enumerate(value):
                if "type" in item_spec and not isinstance(item, dict if item_spec["type"] == "object" else str):
                    errors.append(f"{key}[{i}]: invalid item type")
                    continue
                if isinstance(item, dict):
                    for required in item_spec.get("required", []):
                        if required not in item:
                            errors.append(f"{key}[{i}]: missing {required}")
                    if item_spec.get("additionalProperties") is False:
                        for field in item:
                            if field not in item_spec.get("properties", {}):
                                errors.append(f"{key}[{i}]: unexpected {field}")
                    for field, field_spec in item_spec.get("properties", {}).items():
                        if field in item and field_spec.get("type") == "integer":
                            if type(item[field]) is not int or item[field] < field_spec.get("minimum", 0):
                                errors.append(f"{key}[{i}].{field}: invalid integer")
    if record.get("sanitizer_present") is True and record.get("confidence") == "High":
        errors.append("sanitizer_present=true cannot have High confidence")
    return errors


def main(argv):
    if len(argv) != 2:
        print("Usage: python3 tools/validate_findings.py <findings.jsonl>", file=sys.stderr)
        return 2
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    path = Path(argv[1])
    if not path.is_file():
        print(f"Missing findings file: {path}", file=sys.stderr)
        return 1
    seen = set()
    count = 0
    failed = False
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        count += 1
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            print(f"line {number}: invalid JSON: {exc}")
            failed = True
            continue
        errors = validate(record, schema)
        if isinstance(record, dict):
            finding_id = record.get("id")
            if finding_id in seen:
                errors.append(f"duplicate finding id: {finding_id}")
            if finding_id is not None:
                seen.add(finding_id)
        for error in errors:
            print(f"line {number}: {error}")
        failed |= bool(errors)
    print(f"Validated {count} findings: {'FAIL' if failed else 'PASS'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
