---
mode: agent
description: Run the human-style multi-agent Java security review workflow.
---

# /team-scan — Multi-Agent Security Review

Run the security review as a small human-style team. Use the current workspace unless the user provides a narrower scope.

For a strict one-after-another workflow that continues until all artifacts are complete, use `.github/prompts/orchestrated-scan.prompt.md`.

## Team Flow

1. `security-lead`: scope the review, record assumptions, and create the work plan.
2. `security-engineer`: validate concrete Java source-to-sink findings using the relevant `sast-*` skills.
3. `security-researcher`: generate adversarial hypotheses, variant analysis, API abuse paths, and exploit chains.
4. `security-critic`: challenge every finding for false positives, duplicates, weak evidence, and severity inflation.
5. `security-remediator`: create `.github/sast-remediation.md` for accepted findings.
6. `security-html-reporter`: create `.github/sast-report.html` from the accepted scan artifacts.

## Artifacts

- `.github/sast-context.md`
- `.github/sast-findings.jsonl`
- `.github/sast-report.md`
- `.github/sast-remediation.md`
- `.github/sast-report.html`

## Rules

- Keep confirmed findings separate from hypotheses.
- Use `.github/schemas/finding.schema.json` for JSONL findings.
- Do not invent paths, line numbers, endpoints, payloads, CVEs, or exploitability.
- If no confirmed vulnerabilities are found, produce a clean report with coverage and residual-risk notes.
