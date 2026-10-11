#!/usr/bin/env python3
"""Validate this repository's finding contract and, optionally, source evidence.

This is deliberately a validator for the checked-in schema's keyword subset,
not a general-purpose JSON Schema implementation. Unknown keywords fail closed.
"""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / '.github/schemas/finding.schema.json'
TYPES = {
    'object': lambda v: isinstance(v, dict),
    'string': lambda v: isinstance(v, str),
    'integer': lambda v: type(v) is int,
    'boolean': lambda v: type(v) is bool,
    'array': lambda v: isinstance(v, list),
    'null': lambda v: v is None,
}
SUPPORTED = {'$schema', '$id', 'title', 'description', 'examples', 'type', 'properties',
             'required', 'additionalProperties', 'enum', 'pattern', 'minimum', 'items', 'minLength'}


def strict_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError(f'duplicate JSON key: {key}')
            result[key] = value
        return result
    def constant(value):
        raise ValueError(f'non-JSON constant: {value}')
    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)


def _check(value, spec, location='finding'):
    errors = []
    unsupported = set(spec) - SUPPORTED
    if unsupported:
        return [f'{location}: unsupported schema keywords: {sorted(unsupported)}']
    types = spec.get('type', [])
    types = [types] if isinstance(types, str) else types
    if types and not any(TYPES.get(t, lambda _: False)(value) for t in types):
        return [f'{location}: invalid type']
    if 'enum' in spec and value not in spec['enum']:
        errors.append(f'{location}: value not in allowed enum')
    if isinstance(value, str):
        if 'pattern' in spec and not re.fullmatch(spec['pattern'], value):
            errors.append(f'{location}: invalid format')
        if len(value) < spec.get('minLength', 0):
            errors.append(f'{location}: too short')
    if type(value) is int and value < spec.get('minimum', value):
        errors.append(f'{location}: below minimum')
    if isinstance(value, dict):
        properties = spec.get('properties', {})
        for key in spec.get('required', []):
            if key not in value:
                errors.append(f'{location}: missing required field: {key}')
        for key, item in value.items():
            if key in properties:
                errors.extend(_check(item, properties[key], f'{location}.{key}'))
            elif spec.get('additionalProperties') is False:
                errors.append(f'{location}: unexpected field: {key}')
    if isinstance(value, list) and 'items' in spec:
        for i, item in enumerate(value):
            errors.extend(_check(item, spec['items'], f'{location}[{i}]'))
    return errors


def safe_source(root, name):
    if not isinstance(name, str) or not name or '\\' in name:
        raise ValueError('source path must be a relative POSIX path')
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or ':' in name:
        raise ValueError('source path must stay inside target')
    resolved = (root / name).resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise ValueError('source path escapes target (including symlinks)')
    return resolved


def validate_evidence(record, root):
    errors = []
    try:
        lines = safe_source(root, record['file']).read_text(encoding='utf-8').splitlines()
        line = record['line']
        if not 1 <= line <= len(lines):
            return ['evidence: line is outside source file']
        if record.get('evidence_redacted'):
            if record['skill'] != 'sast-secrets' or record['evidence'] != '[REDACTED credential literal]':
                errors.append('evidence: unsupported redaction')
            count = record.get('evidence_line_count')
            digest = record.get('evidence_sha256')
            if type(count) is not int or not 1 <= count <= 3 or line + count - 1 > len(lines):
                errors.append('evidence: redaction requires a valid line count')
            elif digest != hashlib.sha256('\n'.join(lines[line - 1:line - 1 + count]).encode('utf-8')).hexdigest():
                errors.append('evidence: redacted snippet hash does not match source')
        else:
            evidence = record['evidence'].splitlines()
            if not 1 <= len(evidence) <= 3 or '\n'.join(evidence) != '\n'.join(lines[line - 1:line - 1 + len(evidence)]):
                errors.append('evidence: snippet does not match source at the reported line')
        for step in record.get('taint_path', []):
            count = len(safe_source(root, step['file']).read_text(encoding='utf-8').splitlines())
            if not 1 <= step['line'] <= count:
                errors.append('taint_path: line outside source file')
    except (OSError, UnicodeError, ValueError, KeyError, TypeError) as exc:
        errors.append(f'evidence: {exc}')
    return errors


def validate(record, schema, root=None):
    errors = _check(record, schema)
    if not isinstance(record, dict):
        return errors
    for key in schema['required']:
        if isinstance(record.get(key), str) and not record[key].strip():
            errors.append(f'{key}: must not be blank')
    if record.get('sanitizer_present') is True and record.get('confidence') == 'High':
        errors.append('sanitizer_present=true cannot have High confidence')
    if 'attack_vector' in record:
        for field in ('attack_steps', 'prerequisites', 'business_invariant', 'impact', 'missing_control', 'assumptions', 'test_idea'):
            if field not in record:
                errors.append(f'attack analysis: missing {field}')
        if not record.get('attack_steps'):
            errors.append('attack analysis: attack_steps must not be empty')
    if not errors and root is not None:
        errors.extend(validate_evidence(record, Path(root)))
    return errors


def read_findings(path, root=None):
    schema = strict_json(SCHEMA.read_text(encoding='utf-8'))
    rows, errors, seen = [], [], set()
    for number, line in enumerate(Path(path).read_text(encoding='utf-8').splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = strict_json(line)
        except ValueError as exc:
            errors.append(f'line {number}: invalid JSON: {exc}')
            continue
        issues = validate(record, schema, root)
        finding_id = record.get('id') if isinstance(record, dict) else None
        if isinstance(finding_id, str):
            if finding_id in seen:
                issues.append(f'duplicate finding id: {finding_id}')
            seen.add(finding_id)
        errors.extend(f'line {number}: {issue}' for issue in issues)
        rows.append(record)
    if not errors:
        for record in rows:
            duplicate = record.get('duplicate_of')
            if duplicate is not None and (duplicate not in seen or duplicate == record['id']):
                errors.append(f"{record['id']}: duplicate_of must reference a different finding")
    return rows, errors


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('findings', type=Path)
    parser.add_argument('--source-root', type=Path, help='also verify file paths, line numbers and exact snippets')
    args = parser.parse_args((argv or sys.argv)[1:])
    try:
        rows, errors = read_findings(args.findings, args.source_root)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f'Validation failed: {exc}', file=sys.stderr)
        return 1
    for error in errors:
        print(error, file=sys.stderr)
    print(f"Validated {len(rows)} findings: {'FAIL' if errors else 'PASS'}")
    return int(bool(errors))


if __name__ == '__main__':
    sys.exit(main())
