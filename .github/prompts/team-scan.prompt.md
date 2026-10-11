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

## Executable evidence handoff

When the executable harness is installed, first run `python3 <harness-root>/tools/scan.py <target-root> --output <new-output-directory>` to collect AST facts, conservative taint candidates, and the explicit review queue. Do not treat `candidate` findings as confirmed vulnerabilities or mark review-only categories as passed. Resolve incomplete scans before claiming scan completion.

Use the existing skills to review the candidate evidence and unsupported categories. Put reviewed findings in a separate JSONL file. Run `python3 <harness-root>/tools/scan.py <target-root> --no-build --reviewed-findings <reviewed.jsonl> --output <another-new-output-directory>` to validate evidence and produce consolidated reports. The executable supports only documented partial analysis; human/agent review is still required.
