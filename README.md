# security-agent-harness

Modular Java security analysis harness for GitHub Copilot agents, prompt files, agent skills, and scan reporting.

## What This Provides

This repository defines a VS Code/GitHub Copilot security review agent for Java projects. It is not an executable scanner; it is a structured instruction harness that guides an AI review agent through architecture recon, vulnerability-specific analysis, attack-chain reasoning, and final report consolidation.

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
