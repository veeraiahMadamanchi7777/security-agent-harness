import collections
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools.scan import ROOT, OUTPUTS, render_reports, sarif
from tools.validate_findings import read_findings, validate, SCHEMA, strict_json
from test_validate_findings import sample

SCHEMA_DATA = json.loads(SCHEMA.read_text())
BINARY = ROOT / 'harness-core/build/install/harness-core/bin/harness-core'


class HardenedValidationTests(unittest.TestCase):
    def test_unhashable_id_reports_error(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / 'f.jsonl'
            p.write_text(json.dumps(dict(sample(), id=[])) + '\n')
            self.assertTrue(read_findings(p)[1])

    def test_nested_type_is_validated(self):
        f = dict(sample(), taint_path=[dict(step=123, file=False, line=1)])
        self.assertEqual(2, len(validate(f, SCHEMA_DATA)))

    def test_bool_is_not_line_number(self):
        self.assertTrue(validate(dict(sample(), line=True), SCHEMA_DATA))

    def test_nonstandard_json_rejected(self):
        for value in ('{"id":"a","id":"b"}', '{"line":NaN}', '{"line":Infinity}'):
            with self.assertRaises(ValueError):
                strict_json(value)

    def test_blank_evidence_rejected(self):
        self.assertTrue(validate(dict(sample(), evidence=' '), SCHEMA_DATA))

    def test_source_evidence_and_escape(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'A.java').write_text('statement.executeQuery(sql);\n')
            f = dict(sample(), file='A.java', line=1)
            self.assertEqual([], validate(f, SCHEMA_DATA, root))
            self.assertTrue(validate(dict(f, evidence='fabricated'), SCHEMA_DATA, root))
            self.assertTrue(validate(dict(f, file='../A.java'), SCHEMA_DATA, root))
            self.assertTrue(validate(dict(f, line=99), SCHEMA_DATA, root))

    def test_redaction_cannot_skip_arbitrary_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'A.java').write_text('class A {}\n')
            f = dict(sample(), file='A.java', line=1, evidence_redacted=True)
            self.assertTrue(validate(f, SCHEMA_DATA, root))

    def test_ids_over_999_supported(self):
        self.assertEqual([], validate(dict(sample(), id='SQLI-1000'), SCHEMA_DATA))

    def test_redacted_evidence_is_tied_to_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            snippet = 'String password = "fixture-only-password";'
            (root / 'A.java').write_text(snippet + '\n')
            f = dict(sample(), file='A.java', line=1, skill='sast-secrets', evidence='[REDACTED credential literal]',
                     evidence_redacted=True, evidence_line_count=1, evidence_sha256=hashlib.sha256(snippet.encode()).hexdigest())
            self.assertEqual([], validate(f, SCHEMA_DATA, root))
            (root / 'A.java').write_text('String password = System.getenv("PASSWORD");\n')
            self.assertTrue(validate(f, SCHEMA_DATA, root))

    def test_report_escapes_target_code(self):
        with tempfile.TemporaryDirectory() as temp:
            f = dict(sample(), evidence='<script>alert(1)</script>', file='<img src=x onerror=alert(1)>.java')
            summary = dict(complete=True, parsed_files=1, discovered_files=1, errors=[])
            render_reports(Path(temp), {}, [f], summary)
            page = (Path(temp) / 'report.html').read_text()
            self.assertNotIn('<script>', page)
            self.assertNotIn('<img src=', page)
            self.assertIn('&lt;script&gt;', page)
            self.assertIn('Content-Security-Policy', page)

    def test_sarif_incomplete_run(self):
        data = sarif([], dict(complete=False, errors=['parse failed']))
        self.assertFalse(data['runs'][0]['invocations'][0]['executionSuccessful'])


@unittest.skipUnless(BINARY.exists(), 'Build Java distribution before integration tests')
class ScanIntegrationTests(unittest.TestCase):
    def invoke(self, target, output, *extra):
        return subprocess.run([sys.executable, str(ROOT / 'tools/scan.py'), str(target), '--output', str(output), '--no-build', *extra],
                              capture_output=True, text=True, timeout=60)

    def test_fixture_benchmark_and_artifacts(self):
        expected = json.loads((ROOT / 'tests/fixtures/expected.json').read_text())
        with tempfile.TemporaryDirectory() as temp:
            for case, counts in expected.items():
                with self.subTest(case=case):
                    target = ROOT / 'tests/fixtures' / case
                    output = Path(temp) / case
                    run = self.invoke(target, output)
                    self.assertEqual(0, run.returncode, run.stdout + run.stderr)
                    self.assertEqual(set(OUTPUTS), {p.name for p in output.iterdir()})
                    findings, errors = read_findings(output / 'findings.jsonl', target)
                    self.assertEqual([], errors)
                    self.assertEqual(counts, dict(collections.Counter(f['skill'] for f in findings)))
                    self.assertTrue(all(f['status'] == 'candidate' for f in findings))
                    graph = json.loads((output / 'graph.json').read_text())
                    ids = {n['id'] for n in graph['nodes']}
                    self.assertTrue(all(e['source'] in ids and e['target'] in ids for e in graph['edges']))
                    report = json.loads((output / 'report.sarif').read_text())
                    self.assertEqual(len(findings), len(report['runs'][0]['results']))

    def test_severity_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            run = self.invoke(ROOT / 'tests/fixtures/vulnerable', Path(temp) / 'out', '--fail-on', 'High')
            self.assertEqual(1, run.returncode, run.stderr)
            self.assertTrue(json.loads((Path(temp) / 'out/summary.json').read_text())['severity_gate_failed'])

    def test_invalid_java_is_incomplete_not_clean(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / 'src'; target.mkdir()
            (target / 'Broken.java').write_text('class Broken { nope(')
            run = self.invoke(target, root / 'out')
            self.assertEqual(2, run.returncode, run.stderr)
            summary = json.loads((root / 'out/summary.json').read_text())
            self.assertFalse(summary['complete'])
            self.assertIn('INCOMPLETE', (root / 'out/report.html').read_text())

    def test_reports_are_deterministic(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ('a', 'b'):
                run = self.invoke(ROOT / 'tests/fixtures/vulnerable', root / name)
                self.assertEqual(0, run.returncode, run.stderr)
            for artifact in OUTPUTS:
                self.assertEqual((root / 'a' / artifact).read_bytes(), (root / 'b' / artifact).read_bytes(), artifact)

    def test_refuses_existing_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'keep.txt').write_text('keep')
            run = self.invoke(ROOT / 'tests/fixtures/safe', root)
            self.assertEqual(2, run.returncode)
            self.assertEqual('keep', (root / 'keep.txt').read_text())

    def test_reviewed_findings_can_dismiss_candidates(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); target = ROOT / 'tests/fixtures/vulnerable'
            self.assertEqual(0, self.invoke(target, root / 'initial').returncode)
            findings, _ = read_findings(root / 'initial/findings.jsonl')
            for f in findings:
                f['status'] = 'dismissed'
            reviewed = root / 'reviewed.jsonl'
            reviewed.write_text(''.join(json.dumps(f) + '\n' for f in findings))
            run = self.invoke(target, root / 'reviewed', '--reviewed-findings', str(reviewed), '--fail-on', 'High')
            self.assertEqual(0, run.returncode, run.stderr)

    def test_stale_review_evidence_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); reviewed = root / 'reviewed.jsonl'
            reviewed.write_text(json.dumps(sample()) + '\n')
            run = self.invoke(ROOT / 'tests/fixtures/vulnerable', root / 'out', '--reviewed-findings', str(reviewed))
            self.assertEqual(2, run.returncode)
            self.assertFalse((root / 'out/report.html').exists())


if __name__ == '__main__':
    unittest.main()
