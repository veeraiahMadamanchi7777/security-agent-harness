# Example run: OWASP WebGoat

Executable scanner run against [OWASP WebGoat](https://github.com/WebGoat/WebGoat), an intentionally vulnerable Spring Boot app (commit `4e98f1c`, shallow clone).

```bash
git clone --depth 1 https://github.com/WebGoat/WebGoat.git /path/to/WebGoat
python3 tools/scan.py /path/to/WebGoat --output scan-results/webgoat
python3 tools/validate_findings.py scan-results/webgoat/findings.jsonl --source-root /path/to/WebGoat
```

The analyzer needs a JDK 17 toolchain (`apt-get install openjdk-17-jdk-headless`); the build fails if only JDK 21 is installed.

## Result

- Scan complete: 335/335 non-test Java files parsed, exit code 0.
- 22 candidates (21 High, 1 Medium). The validator passed all 22 against the source.

| Skill | Count | Where |
|---|---|---|
| sast-sqli | 11 | `lessons/sqlinjection/**` |
| sast-pathtraversal | 6 | `ProfileUploadRetrieval`, `ProfileZipSlip`, `webwolf/FileServer` |
| sast-secrets | 2 | `SolutionConstants`, `JWTRefreshEndpoint` |
| sast-deserial | 1 | `InsecureDeserializationTask` |
| sast-ssrf | 1 | `SSRFTask2` |
| sast-crypto | 1 | `HashingAssignment` (Medium) |

All findings are `candidate` status, not confirmed. WebGoat also has lessons for XXE, XSS, IDOR, JWT/auth, CSRF and open redirects. The deterministic rules did not flag these, or they are outside their documented coverage, so `review-queue.json` marks them for skill-based review.
