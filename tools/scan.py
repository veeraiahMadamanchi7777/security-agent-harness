#!/usr/bin/env python3
"""Run the Java AST candidate scan, evidence gate, and reproducible report pipeline."""
import argparse
import hashlib
import html
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
from urllib.parse import quote

try:
    from .validate_findings import ROOT, SCHEMA, read_findings, strict_json, validate
except ImportError:
    from validate_findings import ROOT, SCHEMA, read_findings, strict_json, validate

SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Informational']
COVERED = {'sqli', 'rce', 'pathtraversal', 'deserial', 'openredirect', 'xss', 'ssrf', 'ldap', 'templateinject', 'xxe', 'crypto', 'secrets'}
REVIEW_ONLY = ['idor', 'auth', 'business-logic', 'csrf', 'cors', 'oauth', 'graphql', 'websocket',
               'file-upload', 'cache', 'headers', 'logging', 'massassignment', 'dependency', 'api-abuse', 'attack-chain']
OUTPUTS = ['facts.json', 'graph.json', 'review-queue.json', 'findings.jsonl', 'report.md', 'report.html', 'report.sarif', 'summary.json']


def write_json(path, obj):
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + '\n', encoding='utf-8')


def coverage():
    return [dict(skill='sast-' + skill, status='partial-candidate-analysis' if skill in COVERED else 'review-required',
                 instructions='.github/skills/sast-' + skill + '/SKILL.md')
            for skill in sorted(COVERED | set(REVIEW_ONLY))]


def graph(facts, findings):
    nodes, edges = [], []
    for method in facts.get('methods', []):
        nodes.append(dict(id=method['id'], kind='entry-point' if method['entryPoint'] else 'method',
                          file=method['file'], line=method['line'], label=method['signature']))
    for i, call in enumerate(facts.get('calls', [])):
        target = 'unresolved-call-' + str(i)
        nodes.append(dict(id=target, kind='unresolved-call', label=call['targetName'], file=call['file'], line=call['line']))
        edges.append(dict(source=call['from'], target=target, kind='syntactic-call'))
    for finding in findings:
        previous = None
        for i, step in enumerate(finding.get('taint_path', [])):
            current = finding['id'] + ':' + str(i)
            nodes.append(dict(id=current, kind='taint-evidence', **step))
            if previous is not None:
                edges.append(dict(source=previous, target=current, kind='candidate-flow', finding=finding['id']))
            previous = current
    return dict(nodes=nodes, edges=edges, semantics='Syntactic call candidates and conservative taint evidence; not a proven runtime call graph.')


def sarif(findings, summary):
    rules = sorted({f['skill'] for f in findings})
    results = []
    for f in findings:
        if f.get('status') == 'dismissed':
            continue
        message = f"{f['id']} [{f.get('status', 'candidate')}] {f['cwe']}: {f['sink']}. {f['remediation']}"
        result = dict(ruleId=f['skill'], ruleIndex=rules.index(f['skill']),
                      level='error' if f['severity'] in ('Critical', 'High') else 'warning' if f['severity'] == 'Medium' else 'note',
                      message=dict(text=message),
                      locations=[dict(physicalLocation=dict(artifactLocation=dict(uri=quote(f['file'], safe='/'), uriBaseId='%SRCROOT%'),
                                                           region=dict(startLine=f['line'], startColumn=f.get('column', 1))))],
                      properties=dict(status=f.get('status', 'candidate'), confidence=f['confidence'], cwe=f['cwe']),
                      partialFingerprints={'finding/v1': hashlib.sha256((f['skill'] + '\0' + f['file'] + '\0' + str(f['line']) + '\0' + f['sink']).encode()).hexdigest()})
        results.append(result)
    return {'$schema': 'https://json.schemastore.org/sarif-2.1.0.json', 'version': '2.1.0', 'runs': [dict(
        tool=dict(driver=dict(name='security-agent-harness', version='0.2.0', rules=[dict(id=r, shortDescription=dict(text=r)) for r in rules])),
        invocations=[dict(executionSuccessful=summary['complete'], toolExecutionNotifications=[dict(level='error', message=dict(text=e)) for e in summary['errors']])],
        results=results)]}


def render_reports(directory, facts, findings, summary):
    title = 'Java security candidate report'
    status = 'Analysis completed within documented scope' if summary['complete'] else 'INCOMPLETE — scan errors must be resolved'
    intro = f"{status}. {len(findings)} findings; {summary['parsed_files']}/{summary['discovered_files']} Java files parsed."
    warning = 'Candidates are not confirmed vulnerabilities. Zero findings is not a security certification. Severity is provisional.'
    md = [f'# {title}', '', intro, '', warning, '', '## Findings', '']
    esc = lambda x: html.escape(str(x), quote=True)
    sections = []
    for f in findings:
        heading = f"{f['id']} · {f['severity']} · {f.get('status', 'candidate')} · {f['cwe']}"
        location = f"{f['file']}:{f['line']} ({f.get('method', '')})"
        md.extend([f'### {heading}', '', location, '', f"Source: {f['source']}", '', f"Sink: {f['sink']}", '',
                   '    ' + f['evidence'].replace('\n', '\n    '), '', 'Remediation: ' + f['remediation'], '',
                   'Review: ' + ' '.join(f.get('false_positive_indicators', [])), ''])
        steps = ''.join(f"<li>{esc(s['file'])}:{s['line']} — {esc(s['step'])}</li>" for s in f.get('taint_path', []))
        attack = ''
        if f.get('attack_vector'):
            md.extend(['Attack vector: ' + f['attack_vector'], '', 'Business invariant: ' + f['business_invariant'], '',
                       'Prerequisites: ' + '; '.join(f['prerequisites']), '', 'Attack steps:', ''] +
                      [f'{i}. {step}' for i, step in enumerate(f['attack_steps'], 1)] +
                      ['', 'Impact: ' + f['impact'], '', 'Missing control: ' + f['missing_control'], '',
                       'Assumptions: ' + '; '.join(f['assumptions']), '', 'Regression test: ' + f['test_idea'], ''])
            attack = (f"<h3>Attack vector</h3><p>{esc(f['attack_vector'])}</p><p><strong>Business invariant:</strong> {esc(f['business_invariant'])}</p>"
                      f"<p><strong>Prerequisites:</strong> {esc('; '.join(f['prerequisites']))}</p><ol>" +
                      ''.join('<li>' + esc(step) + '</li>' for step in f['attack_steps']) +
                      f"</ol><p><strong>Impact:</strong> {esc(f['impact'])}</p><p><strong>Missing control:</strong> {esc(f['missing_control'])}</p>"
                      f"<p><strong>Assumptions:</strong> {esc('; '.join(f['assumptions']))}</p><p><strong>Regression test:</strong> {esc(f['test_idea'])}</p>")
        sections.append(f"<article><h2>{esc(heading)}</h2><p>{esc(location)}</p><p>Confidence: {esc(f['confidence'])}</p>"
                        f"<p>Source: {esc(f['source'])}<br>Sink: {esc(f['sink'])}</p><pre>{esc(f['evidence'])}</pre>"
                        f"<ol>{steps}</ol>{attack}<p><strong>Remediation:</strong> {esc(f['remediation'])}</p>"
                        f"<p><strong>Review:</strong> {esc(' '.join(f.get('false_positive_indicators', [])))}</p></article>")
    if not findings:
        md.extend(['No candidates were emitted within this rule set and scan scope.', ''])
        sections.append('<p>No candidates were emitted within this rule set and scan scope.</p>')
    md.extend(['## Errors', ''] + (['- ' + e for e in summary['errors']] or ['None.']) + ['', '## Coverage and required review', ''])
    rows = []
    for item in coverage():
        md.append(f"- {item['skill']}: {item['status']}")
        rows.append(f"<tr><td>{esc(item['skill'])}</td><td>{esc(item['status'])}</td></tr>")
    md.extend(['', '## Limitations', ''] + ['- ' + x for x in facts.get('limitations', [])])
    md.extend(['', '## Excluded paths', ''] + ['- ' + x for x in facts.get('excludedPaths', [])])
    ai = summary.get('ai_review', {'status': 'disabled'})
    md.extend(['', '## AI security and business-logic review', '', 'Status: ' + ai['status'], '',
               'Coverage is model-reported; completed review is not proof of complete detection.', ''] +
              ['- ' + q for q in ai.get('unresolved_questions', [])])
    (directory / 'report.md').write_text('\n'.join(md) + '\n', encoding='utf-8')
    errors = ''.join('<li>' + esc(e) + '</li>' for e in summary['errors']) or '<li>None.</li>'
    limitations = ''.join('<li>' + esc(e) + '</li>' for e in facts.get('limitations', []))
    exclusions = ''.join('<li>' + esc(e) + '</li>' for e in facts.get('excludedPaths', []))
    page = f'''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>{title}</title><style>body{{font:16px/1.6 system-ui;max-width:1050px;margin:40px auto;padding:0 24px;color:#142638;background:#f4f7fa}}article{{background:white;padding:20px;margin:20px 0;border:1px solid #cbd5df;border-radius:8px}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#edf2f6;padding:16px}}td{{padding:6px 18px;border-bottom:1px solid #ccd6df}}.notice{{padding:16px;background:#fff1c9}}h1,h2{{line-height:1.25}}</style>
<h1>{title}</h1><p>{esc(intro)}</p><p class="notice">{esc(warning)}</p>{''.join(sections)}
<h2>AI security and business-logic review</h2><p>Status: {esc(ai['status'])}. Coverage is model-reported, not proof of complete detection.</p><ul>{''.join('<li>' + esc(q) + '</li>' for q in ai.get('unresolved_questions', []))}</ul>
<h2>Errors</h2><ul>{errors}</ul><h2>Static coverage and required review</h2><table><tr><th>Skill</th><th>Status</th></tr>{''.join(rows)}</table>
<h2>Limitations</h2><ul>{limitations}</ul><h2>Excluded paths</h2><ul>{exclusions}</ul></html>'''
    (directory / 'report.html').write_text(page, encoding='utf-8')


def run(args):
    target = args.target.resolve()
    if not target.is_dir():
        raise ValueError('Target must be an existing directory')
    output = args.output.resolve()
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError('Output must be a new or empty directory (prevents stale or overwritten reports)')
    binary = ROOT / 'harness-core/build/install/harness-core/bin' / ('harness-core.bat' if os.name == 'nt' else 'harness-core')
    if not args.no_build:
        wrapper = ROOT / 'harness-core' / ('gradlew.bat' if os.name == 'nt' else 'gradlew')
        subprocess.run([str(wrapper), '--no-daemon', 'installDist'], cwd=wrapper.parent, check=True, timeout=args.timeout)
    if not binary.is_file():
        raise ValueError('Analyzer is not built. Run without --no-build, or run harness-core/gradlew installDist.')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.scan-', dir=output.parent) as temporary:
        stage = Path(temporary)
        raw = stage / 'raw.json'
        command = [str(binary), str(target), str(raw)] + (['--include-tests'] if args.include_tests else [])
        completed = subprocess.run(command, capture_output=True, text=True, timeout=args.timeout)
        if not raw.is_file():
            raise ValueError('Analyzer failed before producing results: ' + completed.stderr.strip())
        facts = strict_json(raw.read_text(encoding='utf-8'))
        findings = facts.pop('findings')
        errors = list(facts.get('errors', []))
        if completed.returncode and not errors:
            errors.append(f'Analyzer exited with code {completed.returncode}')
        schema = strict_json(SCHEMA.read_text(encoding='utf-8'))
        for name, digest in facts.get('sourceSha256', {}).items():
            if hashlib.sha256((target / name).read_bytes()).hexdigest() != digest:
                raise ValueError('Source changed during analysis; rerun on a stable checkout: ' + name)
        # Never pass invalid generated findings to a report.
        validation_errors = [f"{f.get('id', '?')}: {e}" for f in findings for e in validate(f, schema, target)]
        if validation_errors:
            raise ValueError('Generated findings failed evidence validation: ' + '; '.join(validation_errors))
        ai_state = {'status': 'disabled'}
        artifacts = list(OUTPUTS)
        if args.ai_review != 'off':
            try:
                try:
                    from .ai_review import review
                except ImportError:
                    from ai_review import review
                ai_findings, ai_state = review(target, stage / 'ai-review', facts, findings, args)
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                # Keep the source packet, prompts and diagnostics available for inspection/retry.
                output.mkdir(exist_ok=True)
                if (stage / 'ai-review').exists():
                    shutil.copytree(stage / 'ai-review', output / 'ai-review')
                write_json(output / 'summary.json', dict(complete=False, errors=[str(exc)], ai_review={'status': 'failed'}))
                raise
            static_locations = {(f['skill'], f['file'], f['line']): i for i, f in enumerate(findings)}
            for finding in ai_findings:
                key = (finding['skill'], finding['file'], finding['line'])
                if key in static_locations:
                    index = static_locations.pop(key)
                    finding['id'] = findings[index]['id']
                    findings[index] = finding
                else:
                    # Distinct business controls can be missing at the same line.
                    findings.append(finding)
            artifacts.append('ai-review')
            if ai_state['status'] == 'partial':
                errors.append('AI review did not cover all source batches/files; inspect ai-review/state.json')
        if args.reviewed_findings:
            reviewed, issues = read_findings(args.reviewed_findings, target)
            if issues:
                raise ValueError('Reviewed findings failed validation: ' + '; '.join(issues))
            # Reviewed entries replace candidates by ID only when their location and rule agree.
            by_id = {f['id']: f for f in findings}
            for f in reviewed:
                old = by_id.get(f['id'])
                if old and any(old.get(k) != f.get(k) for k in ('skill', 'file', 'line', 'sink')):
                    raise ValueError(f"Reviewed finding ID collision: {f['id']}")
                by_id[f['id']] = f
            findings = list(by_id.values())
        findings.sort(key=lambda f: (SEVERITIES.index(f['severity']), f['file'], f['line'], f['id']))
        finding_path = stage / 'findings.jsonl'
        finding_path.write_text(''.join(json.dumps(f, sort_keys=True) + '\n' for f in findings), encoding='utf-8')
        _, issues = read_findings(finding_path, target)
        if issues:
            raise ValueError('Final finding quality gate failed: ' + '; '.join(issues))
        threshold = len(SEVERITIES) if args.fail_on == 'none' else SEVERITIES.index(args.fail_on)
        gate = any(f.get('status') != 'dismissed' and SEVERITIES.index(f['severity']) <= threshold for f in findings) if args.fail_on != 'none' else False
        summary = dict(engine=facts['engine'], complete=bool(facts['complete']) and not errors,
                       parsed_files=facts['parsedFiles'], discovered_files=facts['discoveredFiles'],
                       findings=len(findings), candidates=sum(f.get('status', 'candidate') == 'candidate' for f in findings),
                       confirmed=sum(f.get('status') == 'confirmed' for f in findings), errors=errors,
                       severity_gate_failed=gate, fail_on=args.fail_on,
                       coverage=coverage(), artifacts=artifacts, ai_review=ai_state)
        write_json(stage / 'facts.json', facts)
        write_json(stage / 'graph.json', graph(facts, findings))
        write_json(stage / 'review-queue.json', dict(coverage=coverage(), candidate_ids=[f['id'] for f in findings if f.get('status', 'candidate') == 'candidate']))
        render_reports(stage, facts, findings, summary)
        write_json(stage / 'report.sarif', sarif(findings, summary))
        # Recheck at publication: findings and reports must refer to the scanned source snapshot.
        for name, digest in facts.get('sourceSha256', {}).items():
            if hashlib.sha256((target / name).read_bytes()).hexdigest() != digest:
                raise ValueError('Source changed during report generation: ' + name)
        summary['source_sha256'] = facts.get('sourceSha256', {})
        write_json(stage / 'summary.json', summary)
        output.mkdir(exist_ok=True)
        for name in artifacts:
            (stage / name).replace(output / name)
    print(f"{summary['findings']} findings ({summary['candidates']} candidates); complete={summary['complete']}; reports: {output}")
    return 2 if not summary['complete'] else 1 if gate else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target', type=Path)
    parser.add_argument('--output', type=Path, default=Path('scan-results'))
    parser.add_argument('--include-tests', action='store_true')
    parser.add_argument('--no-build', action='store_true', help='use the existing local analyzer distribution')
    parser.add_argument('--reviewed-findings', type=Path, help='validated reviewer findings, replacing matching candidate IDs')
    parser.add_argument('--fail-on', choices=['none'] + SEVERITIES, default='none', help='fail on candidates/confirmed findings at or above this severity')
    parser.add_argument('--timeout', type=int, default=300)
    parser.add_argument('--ai-review', choices=['off', 'prepare', 'codex'], default='off',
                        help='prepare local source/prompt packets or run opt-in Codex security and business-logic review')
    parser.add_argument('--business-context', type=Path, help='application roles, intended business rules, trust boundaries and workflows')
    parser.add_argument('--ai-command', default='codex', help='Codex executable name or path')
    parser.add_argument('--ai-model', help='optional model override; otherwise use the CLI default')
    parser.add_argument('--ai-timeout', type=int, default=600, help='timeout in seconds for each AI pass')
    parser.add_argument('--ai-batch-bytes', type=int, default=120000, help='maximum source bytes per AI analysis batch')
    parser.add_argument('--ai-max-batches', type=int, default=12, help='explicit bound on AI source-review calls, plus one critic call')
    parser.add_argument('--ai-critic-bytes', type=int, default=400000, help='maximum critic packet bytes; oversized packets fail explicitly')
    args = parser.parse_args(argv)
    try:
        return run(args)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f'Scan failed: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
