# SKILL: sast-report — Finding Consolidation & Risk Ranking

## Purpose

Phase 3 of the security pipeline. Consolidate Phase 2 finding output, validate it against `.github/schemas/finding.schema.json`, deduplicate overlapping findings, rank by exploitability, and produce a final report that engineers can act on.

---

## Inputs

- `.github/sast-context.md` — Phase 1 architecture context, if available
- `.github/sast-findings.jsonl` — one JSON object per Phase 2 finding
- `.github/schemas/finding.schema.json` — required normalized finding schema
- Source files referenced by each finding, used to verify evidence and line numbers

If `.github/sast-findings.jsonl` is absent or empty, produce a report stating that no confirmed findings were emitted and include coverage notes instead of inventing issues.

---

## Phase 1: Validation

For each finding object:

1. Confirm all required fields exist: `id`, `skill`, `cwe`, `severity`, `confidence`, `file`, `line`, `evidence`, `sink`, `source`, `sanitizer_present`, and `remediation`.
2. Confirm `file` exists in the repository.
3. Confirm `line` points to the sink or immediately adjacent vulnerable expression.
4. Confirm `evidence` matches the referenced file.
5. Reject or downgrade findings with missing source-to-sink evidence.

Use these checks:

```bash
# Confirm referenced files exist
while read -r finding; do echo "$finding"; done < .github/sast-findings.jsonl

# Spot-check evidence manually with line-numbered output
nl -ba path/to/File.java | sed -n 'LINE_START,LINE_ENDp'
```

Do not fabricate missing evidence. If a finding cannot be validated, move it to "Rejected / Needs Manual Review" with the reason.

---

## Phase 2: Deduplication

Deduplicate by root cause, not by sink count.

Treat findings as duplicates when they share:

- same tainted source and same validation failure
- same vulnerable helper method called by multiple endpoints
- same security misconfiguration affecting multiple paths
- same dependency and same vulnerable version

Keep the finding with the clearest exploit path as primary. Mark duplicates using `duplicate_of` when writing normalized output.

Do not merge findings when:

- different attacker roles are required
- different sinks produce meaningfully different impact
- one issue is configuration-level and another is code-level
- remediations are different

---

## Phase 3: Ranking

Sort findings by:

1. Severity: Critical, High, Medium, Low, Informational
2. Confidence: High, Medium, Low
3. Reachability: public unauthenticated endpoint before authenticated endpoint before background job
4. Impact: RCE/auth bypass/data exfiltration before integrity-only before hardening
5. Ease of remediation when risk is otherwise equal

Escalate priority when:

- unauthenticated HTTP input reaches the sink
- exploit requires a single request
- sensitive data or admin functionality is affected
- the vulnerable code is shared across many endpoints

Downgrade priority when:

- exploitation requires admin access
- strong sanitizer exists but is incomplete
- the path is reachable only through scheduled/internal flows
- the finding is dependency-only with no reachable vulnerable feature

---

## Phase 4: Final Report Format

Write `.github/sast-report.md` using this structure:

````markdown
# Security Scan Report

## Executive Summary

- Target: [workspace or repo path]
- Scan date: [date if available]
- Framework: [from architecture context]
- Confirmed findings: [count]
- Critical: [count], High: [count], Medium: [count], Low: [count], Informational: [count]

## Top Risks

1. [Severity] [VulnType] in `file:line` — [one-sentence exploit path]

## Findings

### [SEVERITY] VulnType — ShortDescription

**ID:** SKILL-NNN
**File:** `path/to/File.java:LINE`
**CWE:** CWE-XXX | **OWASP:** A0X:2021-Category
**CVSS (estimated):** X.X (vector)
**Confidence:** High | Medium | Low
**Skill:** `sast-name`

**Taint Path:**
`Source (File.java:LINE)` → `intermediate step (File.java:LINE)` → `Sink (File.java:LINE)`

**Vulnerable Code:**
```java
// line-numbered snippet
```

**Why Exploitable:**
Concrete attack path and impact.

**Proof-of-Concept:**
Request, payload, or reproduction steps when feasible.

**Remediation:**
Specific fix for this code path.

**References:** links or identifiers
```

## Rejected / Needs Manual Review

| Candidate | Reason |
|-----------|--------|

## Coverage Notes

- Skills run:
- Files or directories skipped:
- Phase 1 context availability:
- Residual risk:
````

---

## Self-Contained Check

This skill can run standalone when `.github/sast-findings.jsonl` exists. If Phase 1 context is absent, note that final ranking used only per-finding evidence.
