---
mode: agent
description: Run the sequential security orchestrator from scope through HTML report completion.
---

# /orchestrated-scan — Sequential Security Review Orchestrator

Run the full security review one stage after another until complete. Use the current workspace unless the user provides a narrower scope.

Maintain `.github/sast-orchestration.md` as the progress ledger.

## Ordered Stages

### 1. Lead / Scope

Use the `security-lead` role.

Tasks:

- Determine scan scope and assumptions.
- Run the `sast-analysis` methodology.
- Write `.github/sast-context.md`.
- Record stage completion in `.github/sast-orchestration.md`.

Gate:

- Scope is explicit.
- Architecture context exists or a no-context limitation is documented.

### 2. Function Tree / Human Review

Use `sast-function-tree`, `sast-function-review`, and `sast-taint-tree`.

Tasks:

- Build `.github/sast-function-tree.md` from every reachable entry point.
- Review each high-risk function node and write `.github/sast-function-review.md`.
- Build taint trees for risky paths and write `.github/sast-taint-trees.md`.
- Queue unreviewed or unknown nodes explicitly; do not silently skip them.

Gate:

- Function tree exists.
- High-risk function queue exists, even if empty.
- Function review exists.
- Taint trees exist for high-risk paths, or safe/no-trace reasons are documented.

### 3. Engineer / Validate

Use the `security-engineer` role.

Tasks:

- Run relevant vulnerability skills.
- Use the function tree, function review, and taint trees as the primary map.
- Confirm source-to-sink paths.
- Append confirmed findings to `.github/sast-findings.jsonl` using `.github/schemas/finding.schema.json`.
- Record no-finding coverage notes when a class has no confirmed issue.

Gate:

- Findings JSONL exists, or a no-confirmed-findings note is recorded.
- Every confirmed finding has source, sink, missing control, severity, and confidence.

### 4. Researcher / Expand

Use the `security-researcher` role.

Tasks:

- Search for variants of validated findings.
- Explore API abuse, business logic, and attack-chain hypotheses.
- Promote only evidence-backed items into findings.
- Keep hypotheses separate from confirmed findings.

Gate:

- Variant and attack-chain review is recorded.
- No speculative item is mixed with confirmed findings.

### 5. Critic / Quality Gate

Use the `security-critic` role.

Tasks:

- Review every finding and hypothesis.
- Mark each as accept, revise, merge, downgrade to hypothesis, or reject.
- Write `.github/sast-critique.md`.

Gate:

- Every finding has a critique decision.
- Duplicate and rejected items are not carried forward as accepted findings.

### 6. Remediator / Fix Plan

Use the `security-remediator` role.

Tasks:

- Create `.github/sast-remediation.md`.
- Include implementation guidance, tests, rollout notes, and regression risks.

Gate:

- Every accepted finding has remediation guidance or a documented reason no code fix is required.

### 7. Report / HTML

Use `sast-report` and the `security-html-reporter` role.

Tasks:

- Write `.github/sast-report.md`.
- Write `.github/sast-report.html`.
- Include scope, methodology, findings, critique decisions, remediation roadmap, and limitations.

Gate:

- Markdown report exists.
- HTML report exists.
- Final report does not include rejected findings as confirmed vulnerabilities.

## Run Rules

- Run stages strictly in order.
- Do not skip a stage unless its gate is satisfied by an explicit no-action result.
- Do not invent paths, line numbers, endpoints, payloads, CVEs, or exploitability.
- Do not stop after analysis if later stages remain.
- If blocked, update `.github/sast-orchestration.md` and return the blocker with the next required action.

## Final Output

At completion, return:

- Stage checklist.
- Artifact list.
- Finding counts by severity.
- Top remediation themes.
- Residual limitations.
