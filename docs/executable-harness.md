# Executable harness: scope and verification

The executable pipeline is usable end to end: collect Java AST facts → trace bounded source/sink candidates → verify findings and source evidence → apply reviewer findings → generate reports → enforce an optional severity gate. This does not complete every analysis described by the research skills or guarantee detection of all vulnerabilities.

## Architecture

- `harness-core` uses JavaParser 3.27.0 on Java 17. It parses source without executing the target application, build scripts, annotation processors, or dependencies. Missing framework jars do not prevent syntactic analysis.
- `JavaAnalyzer` records class/method facts, Spring and servlet entry-point candidates, call names, source digests, errors and exclusions. It follows local expression/assignment flows and unique same-class helper calls and returns. Branches and two loop iterations are conservatively joined. Recursion and call depth are bounded.
- `Rule` defines 12 candidate families. A match includes an actual source location, source/sink description, evidence, provisional severity, confidence, remediation guidance and review caveats. All built-in findings are candidates, never automatically confirmed vulnerabilities.
- `tools/validate_findings.py` implements the checked-in finding schema's keyword subset recursively, rejects unknown schema keywords, duplicate JSON keys/IDs, non-JSON constants, invalid nested types and unsafe source paths. With `--source-root`, it verifies exact snippets and taint line locations. Redacted credential snippets require a matching SHA-256 digest and 1–3-line extent.
- `tools/scan.py` orchestrates the trusted harness build, analyzer, quality gate and report generation. It checks source digests before validation and publication. No reports are published after a finding/evidence validation failure. Parse failures produce explicitly incomplete reports and exit 2. Reports require a fresh output directory to avoid stale success artifacts.
- Reviewer JSONL can replace candidates with matching IDs/locations/rules or add findings with new IDs. Reports preserve `candidate`, `confirmed` and `dismissed` status. The harness validates evidence, not the reviewer's exploitability judgment. Dismissed findings do not trigger severity gates and are omitted from SARIF results.

## Partial rule coverage

| Family | Implemented candidate patterns | Important gaps/context |
|---|---|---|
| SQL/JPQL injection | Tainted query text passed to JDBC statements/connections, EntityManager and selected JdbcTemplate calls | No ORM-wide dispatch or complete query-language model; parameter binding with constant SQL is not flagged |
| Command execution | Tainted Runtime.exec arguments and ProcessBuilder construction | Construction alone is not execution; argument injection and shell semantics need review |
| Path traversal | Tainted file constructors and selected Files operations | Base-directory checks, canonicalization, aliases and symlink behavior need review |
| SSRF | URL openConnection/openStream and selected RestTemplate/WebClient URL calls | Redirects, DNS and network policies need review |
| Open redirect | HttpServletResponse-style sendRedirect with tainted destination | Custom routing helpers and implicit redirect strings are not modeled |
| XSS | Tainted writes to a writer obtained from a response | Context encoding/content type need review; arbitrary file writers are not HTML sinks |
| LDAP injection | Tainted DirContext.search filter text | Other LDAP APIs and DN construction not modeled |
| Script injection | Tainted ScriptEngine.eval | Not comprehensive template-engine coverage |
| Deserialization | ObjectInputStream construction from tainted input | Construction alone is not readObject; filters and gadget reachability need review |
| XXE | Selected XML parse APIs with tainted input | Parser factory configuration unresolved; not a claim external entities are enabled |
| Weak crypto | Selected weak literal Cipher/MessageDigest algorithms | Cryptographic purpose, keys, IVs and nonliteral algorithms require review |
| Hardcoded credentials | Named variables initialized with non-placeholder string literals | Test credentials can be false positives; obfuscated/config-file secrets are not covered |

Sources: explicit Spring `RequestParam`, `PathVariable`, `RequestBody`, `RequestHeader`, `CookieValue`, `ModelAttribute`, `RequestPart` annotations, and selected servlet request accessor calls. An annotation is a source candidate, not proof of exposure in deployment.

Type matching is syntactic, not complete symbol resolution. External methods conservatively propagate taint and lower confidence; same-class overloads are not disambiguated. There is no complete control-flow/path-feasibility analysis, cross-file dynamic dispatch, heap/alias/field taint, implicit flows, or framework-wide lifecycle model. Traces contain conservative evidence steps and must not be interpreted as proven feasible runtime paths.

The report's review queue explicitly lists IDOR, auth, business logic, CSRF, CORS, OAuth, GraphQL, WebSocket, file-upload policy, cache behavior, headers, logging, mass assignment, dependency CVEs, API abuse and attack chains as requiring review. Their existing skill instructions remain available. The default CLI does not call a model. `--ai-review codex` adds the source-aware AI review described below; no dependency vulnerability database or runtime exploit testing is used.

## Controlled verification

Reproduce locally:

```sh
cd harness-core
./gradlew --no-daemon test installDist
cd ..
python3 -m unittest discover -s tests -v
python3 tools/scan.py tests/fixtures/vulnerable --no-build --output scan-results/fixture-check
python3 tools/validate_findings.py scan-results/fixture-check/findings.jsonl --source-root tests/fixtures/vulnerable
```

The Java suite exercises assignments, overwritten taint, branch joins, same-class helpers/returns, recursion bounds, numeric conversion, servlet sources, comments/strings, parse errors, empty scope, exclusions, symlinks, determinism, credential redaction and HTTP-vs-file writers. Python tests cover schema edge cases, evidence, source escapes, redacted evidence hashes, HTML escaping, SARIF structure, exact fixture counts, graph integrity, exit codes, report determinism and reviewer integration.

The controlled vulnerable fixture expects exactly one candidate for each of the 12 implemented families. The paired safer fixture expects zero candidates. These hand-authored fixtures are not running applications and are not a measurement of general-world precision or recall. They establish regression behavior for the documented patterns.

## WebGoat robustness run

A read-only scan was run against [OWASP WebGoat](https://github.com/WebGoat/WebGoat/tree/10cecda8b93f9ea1439188a6257dfb7fc9c954d5), commit `10cecda8b93f9ea1439188a6257dfb7fc9c954d5`, excluding test/integration-test and generated directories:

- 323/323 discovered Java files parsed successfully.
- 22 candidates emitted and source-evidence validated.
- No application/build code from WebGoat executed.
- A file-writer XSS false positive discovered during initial inspection was corrected and regression tested.
- Spot checks included concatenated SQL in `SqlInjectionLesson5b`, request-derived native deserialization in `InsecureDeserializationTask`, and request-derived file construction in `ProfileUploadRetrieval`.
- The report is not an exhaustive WebGoat answer key. Candidates include controls/configuration uncertainties, and the scan misses vulnerabilities outside its documented rules. No full precision/recall or exploitability claim is made.

The generated SARIF and findings were also independently validated using `jsonschema` 4.23.0 against the [SARIF 2.1.0 schema](https://json.schemastore.org/sarif-2.1.0.json) and repository finding schema. HTML escaping and report content are tested; a visual browser preview was unavailable because local-file navigation was blocked.

## Operational behavior

Java 17, Python 3.10+, and initial network access for pinned Gradle/build dependencies are required. The wrapper verifies the Gradle distribution SHA-256. After building, `--no-build` scans offline. Source reports remain local unless the caller uploads them; the CI example uploads only its controlled fixture report. Raw source snippets may contain sensitive context even though credential-rule evidence is redacted.

Exit 0 means the configured scan and quality gate completed within supported scope, not that the application is secure. Exit 1 means a candidate/confirmed finding meets the chosen severity threshold. Exit 2 means the scan is incomplete or failed. Independent validator exits are 0 for valid findings, 1 for validation failures, and 2 for invalid command usage.

## AI business-logic and attack review

`--ai-review codex` snapshots Java source plus selected XML, YAML, properties, SQL and build configuration, then reviews explicit source batches with a signed-in Codex CLI. Supply application requirements using `--business-context`. The model receives source as untrusted text; source AGENTS/config instructions, shell tools and web search are disabled. No target code is run. This mode sends the selected text to the model and consumes account usage. `--ai-review prepare` only creates local packets.

Every AI proposal must include an attack vector, ordered abuse steps, prerequisites, business invariant, missing control, impact, assumptions, remediation and a regression-test idea. Each analysis response is schema- and source-validated before a separate synthesis/critic pass can accept it. Neither the generator nor critic can emit a confirmed status. Evidence validation establishes file/snippet correspondence, not exploitability.

The critic receives proposed findings, business context, analysis observations and complete source files referenced by candidate evidence. It does not automatically see every unrelated file: omitted cross-file controls remain an uncertainty. Every analysis batch records model-reported reviewed files; any omitted batch/file or unreadable supporting source yields partial status and exit 2. Batch/critic size limits fail explicitly, not by truncating code. API/CLI failures retain packets and logs under `ai-review/` with an incomplete summary.

The local snapshot, manifest, prompts, outputs, logs and state provide a reviewable record. They may contain sensitive source/configuration and should not be published automatically. The [official Codex non-interactive documentation](https://developers.openai.com/codex/noninteractive) describes the schema-constrained CLI output used by this integration.

The deterministic CI suite uses mocked AI responses to test contracts, critic rejection, missing context, fabricated evidence, snapshot scope and attack-report rendering without requiring model credentials. Live model behavior is nondeterministic and must be evaluated separately against controlled source fixtures; no general-world recall claim is made.
