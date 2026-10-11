import json
import tempfile
import unittest
from pathlib import Path
from tools.validate_findings import validate, main, SCHEMA

SCHEMA_DATA = json.loads(SCHEMA.read_text(encoding="utf-8"))


def sample():
    return {
        "id": "SQLI-001", "skill": "sast-sqli", "cwe": "CWE-89",
        "owasp": "A03:2021-Injection",
        "severity": "High", "confidence": "Medium",
        "file": "src/UserDao.java", "line": 12,
        "method": "findUser", "class": "com.example.UserDao",
        "evidence": "statement.executeQuery(sql);",
        "sink": "Statement.executeQuery()", "source": "request parameter",
        "sanitizer_present": False, "remediation": "Use a prepared statement",
    }


class FindingValidationTests(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(validate(sample(), SCHEMA_DATA), [])

    def test_missing_required(self):
        item = sample()
        del item["source"]
        self.assertTrue(any("source" in error for error in validate(item, SCHEMA_DATA)))

    def test_bad_cwe_and_line(self):
        item = sample()
        item["cwe"] = "89"
        item["line"] = 0
        self.assertEqual(len(validate(item, SCHEMA_DATA)), 2)

    def test_sanitizer_confidence(self):
        item = sample()
        item["sanitizer_present"] = True
        item["confidence"] = "High"
        self.assertTrue(validate(item, SCHEMA_DATA))

    def test_taint_step_validation(self):
        item = sample()
        item["taint_path"] = [{"step": "controller", "file": "A.java", "line": 0}]
        self.assertTrue(validate(item, SCHEMA_DATA))

    def test_duplicate_ids(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "findings.jsonl"
            row = json.dumps(sample())
            path.write_text(row + "\n" + row + "\n", encoding="utf-8")
            self.assertEqual(main(["validate_findings.py", str(path)]), 1)

    def test_empty_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "findings.jsonl"
            path.write_text("", encoding="utf-8")
            self.assertEqual(main(["validate_findings.py", str(path)]), 0)


if __name__ == "__main__":
    unittest.main()
