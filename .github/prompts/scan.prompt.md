---
mode: agent
description: Run the full Java SAST security scan pipeline.
---

# /scan — Java Security Audit Pipeline

Run a complete static application security test against the current Java repository. Use `.github/copilot-instructions.md` as always-on policy and invoke the skills under `.github/skills/` in the phases below.

## Inputs

- **Target:** the current workspace repository unless the user names a specific path.
- **Scope:** Java application code, configuration that affects Java application security, and build files used to identify dependencies.
- **Outputs:**
  - `.github/sast-context.md` for Phase 1 architecture context
  - `.github/sast-findings.jsonl` for normalized Phase 2 findings
  - `.github/sast-report.md` for the final ranked report

If the workspace is not a Git repository, continue scanning the files present in the workspace.

## Phase 1 — Architecture Recon

Run `sast-analysis` first.

1. Detect frameworks, entry points, trust boundaries, taint sources, security filters, and high-risk integrations.
2. Write the Architecture Context Document exactly in the format defined by `sast-analysis` to `.github/sast-context.md`.
3. Do not report vulnerabilities in Phase 1 unless they are needed as priority focus areas for Phase 2.

## Phase 2 — Vulnerability Analysis

Run the human-depth function review skills first:

- `sast-function-tree`
- `sast-function-review`
- `sast-taint-tree`

Then run these vulnerability skills. They may run independently or in parallel when the agent supports parallel work:

- `sast-sqli`
- `sast-rce`
- `sast-idor`
- `sast-auth`
- `sast-xxe`
- `sast-ssrf`
- `sast-crypto`
- `sast-deserial`
- `sast-pathtraversal`
- `sast-business-logic`
- `sast-secrets`
- `sast-csrf`
- `sast-xss`
- `sast-cors`
- `sast-oauth`
- `sast-graphql`
- `sast-websocket`
- `sast-ldap`
- `sast-file-upload`
- `sast-cache`
- `sast-headers`
- `sast-logging`
- `sast-openredirect`
- `sast-templateinject`
- `sast-massassignment`
- `sast-dependency`
- `sast-researcher`
- `sast-api-abuse`
- `sast-attack-chain`

For each skill:

1. Read `.github/sast-context.md` if present; otherwise perform standalone analysis.
2. Read `.github/sast-function-tree.md`, `.github/sast-function-review.md`, and `.github/sast-taint-trees.md` when present.
3. Use the skill's `SKILL.md` and any relevant `references/` files.
4. Taint-track source to sink before reporting. For researcher-style skills, verify each semantic abuse path with file and line evidence.
5. Emit only confirmed or strongly supported findings.
6. Append one JSON object per finding to `.github/sast-findings.jsonl`, conforming to `.github/schemas/finding.schema.json`.

If no findings are confirmed for a skill, record a short note in the final report's coverage section instead of fabricating a finding.

## Phase 3 — Report

Run `sast-report`.

1. Read `.github/sast-context.md` and `.github/sast-findings.jsonl`.
2. Validate required fields against `.github/schemas/finding.schema.json`.
3. Deduplicate findings that share the same root cause.
4. Rank by severity, confidence, exploitability, and reachable attack surface.
5. Write the final report to `.github/sast-report.md`.

## Scan Discipline

- Never invent file paths, line numbers, endpoints, or code snippets.
- Prefer `rg` for search commands.
- Exclude generated code, vendored dependencies, build outputs, and test fixtures unless the application exposes them at runtime.
- Report one finding per root cause.
- If a potentially dangerous API is not reachable from attacker-controlled input, document it only as coverage context, not as a vulnerability.
