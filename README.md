# security-agent-harness

Modular Java security analysis harness for GitHub Copilot agents, prompt files, agent skills, and scan reporting.

## What This Provides

This repository combines an executable Java AST candidate scanner with a structured AI review harness. The executable collects source facts, tracks a bounded subset of Java data flows, validates findings against source evidence, and generates reports. Copilot skills guide the deeper security review that static candidates cannot replace. No component guarantees discovery of every vulnerability.

## Run the executable scanner

Requirements: Java 17 and Python 3.10 or newer. The checked-in Gradle 8.13 wrapper downloads build dependencies on first use. The scan itself is local and does not execute the target project's build or application.

```bash
python3 tools/scan.py /path/to/java-project --output scan-results/my-project
```

The output directory must be new or empty. Use a different directory for each run. After building once, add `--no-build` to reuse the installed analyzer. Add `--include-tests` to include test and fixture directories. Build/generated/vendor directories and symlinks are always excluded and listed in the report.

```bash
# Gate CI on provisional High-or-higher candidates, not only confirmed findings.
python3 tools/scan.py /path/to/java-project --output scan-results/ci --fail-on High

# Independently verify the finding contract and actual source evidence.
python3 tools/validate_findings.py scan-results/ci/findings.jsonl --source-root /path/to/java-project
```

Exit codes: **0** = scan completed within supported scope and passed the selected gate; **1** = severity gate failed; **2** = build, scan, source, or quality-gate failure. Parse failures and empty Java scope are incomplete scans, never successful clean scans. Candidate severity is provisional and is not a computed CVSS score.

Outputs:

| Artifact | Purpose |
|---|---|
| `findings.jsonl` | Validated candidates with source, sink, location, taint evidence, review caveats, and fix guidance |
| `facts.json` | Classes, imports, annotations, methods, entry points, syntactic calls, exclusions, errors, limitations |
| `graph.json` | Method/call candidates and conservative taint evidence edges, not proven runtime paths |
| `review-queue.json` | Candidate IDs and explicit coverage/review status for each vulnerability skill |
| `report.md`, `report.html` | Ranked review reports; HTML escapes source content and uses no scripts or remote assets |
| `report.sarif` | SARIF 2.1.0 results for compatible code-scanning tools |
| `summary.json` | Completion status, severity gate, counts, source digests, and artifact inventory |

### AI review for business gaps and attack vectors

To review the source with AI as well as the deterministic rules, use a signed-in Codex CLI:

```bash
python3 tools/scan.py /path/to/java-project --ai-review codex \
  --business-context /path/to/business-rules.md --output scan-results/full-review
```

Start with [the business-context template](examples/business-context.md). The optional business-rules file should describe roles, ownership/tenant rules, prices/payments/refunds, workflow states, permissions, concurrency requirements, limits, and intended invariants. Without it, the AI must distinguish inferred rules from known requirements.

This mode sends selected source/configuration text and business context to the model through your Codex account. It uses account usage and requires network access. Review runs are text-only: no target execution, shell tools, web browsing or source-provided agent instructions. An analysis pass reviews each bounded source batch; a separate synthesis/critic pass challenges proposed attack scenarios and missing controls. Supply `--ai-model` to select a model; otherwise the CLI default is used.

The AI reviews security categories **and** business abuse: ownership/tenant bypass, price manipulation, negative quantities/amounts, workflow/payment/approval bypass, replay, refund/coupon/OTP abuse, race conditions and quota abuse. Each finding includes:

- Attack vector and ordered hypothetical attack steps.
- Required access and other prerequisites.
- The violated business invariant, missing control and potential impact.
- Exact code evidence, assumptions, remediation and a defensive regression-test idea.

All AI findings remain candidates until independently reviewed. The validator checks their source evidence; it does not prove the attack will work. Missing files, oversized batches, timeouts, malformed responses and fabricated evidence cannot silently become a clean AI review.

Artifacts are saved under `<output>/ai-review/`: `source/`, `manifest.json`, business context, prompts, model responses, logs, proposed/accepted findings and `state.json`. Failure diagnostics and the packet are retained even if AI processing fails. Source snapshots and prompts can contain sensitive information; handle the directory like the original source repository.

```bash
# Prepare local source and prompt packets without contacting any model.
python3 tools/scan.py /path/to/java-project --ai-review prepare --output scan-results/packet

# Demonstrate business review on the included intentionally vulnerable checkout/wallet fixture.
python3 tools/scan.py tests/fixtures/business --no-build --ai-review codex \
  --business-context tests/fixtures/business/BUSINESS.md --output scan-results/business-review
```

Default limits are 120KB of source per batch, 12 source batches plus one critic call, and 600 seconds per call. `--ai-batch-bytes`, `--ai-max-batches`, `--ai-critic-bytes`, and `--ai-timeout` make these limits explicit. No source is silently truncated. A completed AI run means its requested passes finished; it does not guarantee all vulnerabilities were found. The base command without `--ai-review` still runs locally without a model.

### Detection coverage

The built-in rules emit **candidates** for SQL/JPQL injection, command construction/execution, path traversal, SSRF, open redirects, writer-based XSS, LDAP filter injection, script evaluation, native deserialization, XML parser use with untrusted input, weak crypto literals, and named hardcoded credential literals. File and ProcessBuilder construction are review points; their presence alone does not prove file access or command execution. XML parser configuration and output encoding require review. The script rule does not cover every template engine.

Sources are explicitly bound Spring parameters and servlet request accessors. Propagation supports local assignments, conservative branches, two loop iterations, and unique same-class helper calls/returns up to depth eight. API/type matching is syntactic. Numeric parsing is recognized; unknown encoders/sanitizers remain reviewable. Neither helper reachability nor runtime exploitability is proven.

**Not automatically covered:** cross-file dispatch, aliases/heap/field taint, implicit binding, all frameworks, dependency CVEs, IDOR, authorization/authentication, business logic, CSRF/CORS, OAuth, GraphQL/WebSocket policy, cache behavior, and deployment configuration. Existing skills remain available for these reviews; `review-queue.json` marks them as requiring review rather than claiming they passed. See [coverage and validation](docs/executable-harness.md).

### Reviewer handoff

All built-in findings have `status: candidate`, never `confirmed`. Review source, runtime configuration and false-positive indicators before changing status to `confirmed` or `dismissed`. Confidence and severity are distinct from review status. Keep the same ID/location/rule when editing an emitted finding. Review additional categories with the existing skills, giving new findings unique IDs.

```bash
python3 tools/scan.py /path/to/java-project --no-build \
  --reviewed-findings reviewed.jsonl --output scan-results/reviewed
```

Reviewed findings are validated against current source before report publication. They replace matching candidate IDs; mismatched ID collisions or fabricated evidence fail. A status label is the reviewer's assertion, not an independent proof by the harness. Reports can contain sensitive source snippets; credential findings themselves redact their literal.

### Verify the harness

```bash
cd harness-core
./gradlew --no-daemon test installDist
cd ..
python3 -m unittest discover -s tests -v
python3 tools/scan.py tests/fixtures/vulnerable --no-build --output scan-results/benchmark
```

CI runs the Java suite, Python validator/report tests, the full fixture benchmark, and the evidence gate. The manual **Java security candidate scan** workflow scans this repository and saves reports; adapt its checkout/path to scan your Java application. It does not upload source or reports to an AI provider.

## Layout

```text
.github/
├── copilot-instructions.md
├── agents/
│   ├── security-orchestrator.agent.md
│   ├── security-lead.agent.md
│   ├── security-engineer.agent.md
│   ├── security-researcher.agent.md
│   ├── security-critic.agent.md
│   ├── security-remediator.agent.md
│   ├── security-html-reporter.agent.md
│   └── security-auditor.agent.md
├── prompts/
│   ├── scan.prompt.md
│   ├── team-scan.prompt.md
│   └── orchestrated-scan.prompt.md
├── schemas/
│   └── finding.schema.json
├── skills/
│   ├── sast-analysis/
│   ├── sast-function-tree/
│   ├── sast-function-review/
│   ├── sast-taint-tree/
│   ├── sast-sqli/
│   ├── sast-rce/
│   ├── sast-idor/
│   ├── sast-auth/
│   ├── sast-xxe/
│   ├── sast-ssrf/
│   ├── sast-crypto/
│   ├── sast-deserial/
│   ├── sast-pathtraversal/
│   ├── sast-business-logic/
│   ├── sast-secrets/
│   ├── sast-csrf/
│   ├── sast-xss/
│   ├── sast-cors/
│   ├── sast-oauth/
│   ├── sast-graphql/
│   ├── sast-websocket/
│   ├── sast-ldap/
│   ├── sast-file-upload/
│   ├── sast-cache/
│   ├── sast-headers/
│   ├── sast-logging/
│   ├── sast-openredirect/
│   ├── sast-templateinject/
│   ├── sast-massassignment/
│   ├── sast-dependency/
│   ├── sast-researcher/
│   ├── sast-api-abuse/
│   ├── sast-attack-chain/
│   └── sast-report/
├── chatmodes/
│   └── security-auditor.chatmode.md
└── hooks/
    ├── pre-commit.md
    └── pre-push.md
```

## Use In VS Code

1. Open a Java project that includes this `.github/` directory.
2. In Copilot Chat, select `security-orchestrator` for the strict sequential workflow.
3. Run `/orchestrated-scan` to run lead, engineer, researcher, critic, remediator, and HTML reporter stages one after another until complete.
4. Use `security-lead` with `/team-scan` when you want a looser human-style team workflow.
5. Run `/scan` with `security-auditor` when you want the original single-agent pipeline.
6. Optionally invoke individual skills such as `/sast-sqli`, `/sast-auth`, or `/sast-report` when focusing on one area.

## Agent Team

- `security-orchestrator`: runs the team sequentially, records progress in `.github/sast-orchestration.md`, and continues until final Markdown and HTML reports are complete.
- `security-lead`: scopes the assessment, tracks assumptions, coordinates handoffs, and summarizes progress like a human review lead.
- `security-engineer`: validates concrete Java vulnerabilities with source-to-sink evidence and low false-positive tolerance.
- `security-researcher`: performs adversarial hypothesis generation, variant analysis, API abuse review, and exploit-chain research.
- `security-critic`: challenges findings for missing evidence, duplicates, false positives, and severity inflation.
- `security-remediator`: turns accepted findings into Java-specific fix plans, regression tests, and rollout notes.
- `security-html-reporter`: generates `.github/sast-report.html`, a static self-contained HTML report for stakeholders.
- `security-auditor`: runs the original all-in-one SAST pipeline and writes the standard scan artifacts.

## Review Pipeline

1. `security-orchestrator` creates or updates `.github/sast-orchestration.md`.
2. `sast-analysis` maps the application architecture, entry points, trust boundaries, and shared security controls.
3. `sast-function-tree` creates `.github/sast-function-tree.md`, a call tree for each reachable entry point.
4. `sast-function-review` creates `.github/sast-function-review.md`, a human-depth review of high-risk functions and suspicious unknowns.
5. `sast-taint-tree` creates `.github/sast-taint-trees.md`, explicit source-to-sink trees for risky paths.
6. Vulnerability skills review specific classes such as SQL injection, RCE, IDOR, auth bypass, SSRF, XXE, crypto, deserialization, path traversal, CSRF, XSS, CORS, OAuth/OIDC, GraphQL, WebSocket, LDAP injection, file upload, cache poisoning, security headers, logging exposure, open redirect, template injection, mass assignment, dependency risk, API abuse, and business logic flaws.
7. `sast-attack-chain` combines related weaknesses into realistic exploit paths.
8. Findings are normalized into `.github/sast-findings.jsonl` using `.github/schemas/finding.schema.json`.
9. `security-critic` reviews quality and severity and writes `.github/sast-critique.md`.
10. `security-remediator` writes `.github/sast-remediation.md`.
11. `sast-report` deduplicates and ranks findings into `.github/sast-report.md`.
12. `security-html-reporter` produces `.github/sast-report.html`.

## Finding Standard

Confirmed findings must include source, sink, missing control, exploit scenario, impact, false-positive analysis, remediation, severity, and confidence. Hypotheses are allowed, but they must be labeled separately from confirmed vulnerabilities.
