# Implemented harness layout

```text
.github/
├── copilot-instructions.md              ← Always-on global security review rules
├── agents/
│   ├── security-orchestrator.agent.md   ← Sequential controller that runs all stages to completion
│   ├── security-lead.agent.md           ← Human-style assessment lead and coordinator
│   ├── security-engineer.agent.md       ← Source-to-sink vulnerability validator
│   ├── security-researcher.agent.md     ← Deeper hypothesis, variant, and chain analysis
│   ├── security-critic.agent.md         ← False-positive, duplicate, and severity critique
│   ├── security-remediator.agent.md     ← Fix strategy, tests, and rollout planning
│   ├── security-html-reporter.agent.md  ← Static stakeholder HTML report
│   └── security-auditor.agent.md        ← Original full-pipeline agent
├── prompts/
│   ├── scan.prompt.md                   ← /scan full pipeline prompt
│   ├── team-scan.prompt.md              ← /team-scan human-style multi-agent workflow
│   └── orchestrated-scan.prompt.md      ← /orchestrated-scan strict sequential workflow
├── schemas/
│   └── finding.schema.json              ← JSONL finding contract
├── skills/                              ← Each skill has SKILL.md and optional references/
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
│   └── security-auditor.chatmode.md     ← Compatibility wrapper for older VS Code custom chat modes
└── hooks/
    ├── pre-commit.md
    └── pre-push.md
```

## Pipeline

1. `security-orchestrator` records stage progress in `.github/sast-orchestration.md`.
2. `sast-analysis` maps architecture, entry points, trust boundaries, and security controls.
3. `sast-function-tree` creates `.github/sast-function-tree.md` for reachable entry-point call trees.
4. `sast-function-review` reviews high-risk function nodes in human depth.
5. `sast-taint-tree` creates source-to-sink taint trees for risky paths.
6. Vulnerability skills independently verify exploitability for their issue class.
7. `sast-attack-chain` combines related weaknesses into compound exploit paths.
8. Findings are appended to `.github/sast-findings.jsonl` using `.github/schemas/finding.schema.json`.
9. `security-critic` filters false positives, duplicate root causes, and severity inflation.
10. `security-remediator` creates `.github/sast-remediation.md`.
11. `sast-report` deduplicates, ranks severity, and produces the final Markdown report.
12. `security-html-reporter` creates `.github/sast-report.html`.
