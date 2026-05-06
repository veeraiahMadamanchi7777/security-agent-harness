---
name: sast-function-review
description: Perform human-depth security review of each function node in the function tree, checking trust, controls, state, and exploitability.
---

# SKILL: sast-function-review — Per-Function Human Security Review

## Purpose

Review every function in `.github/sast-function-tree.md` like a human security engineer reading code line by line. The goal is to catch flaws that vulnerability-specific searches miss: missing invariants, misplaced trust, inconsistent controls, risky helper reuse, and subtle business logic issues.

Write the main artifact to `.github/sast-function-review.md`. Append confirmed findings to `.github/sast-findings.jsonl` using `.github/schemas/finding.schema.json`.

## Inputs

- `.github/sast-function-tree.md`.
- `.github/sast-context.md`.
- `.github/schemas/finding.schema.json`.
- [`references/function-review-checklist.md`](references/function-review-checklist.md).

## Method

### 1. Review Function by Function

For each function node, answer:

- What actor can reach this function?
- What data is trusted at entry?
- What data becomes security-sensitive inside the function?
- What controls are expected?
- What controls are actually present?
- What sinks or state transitions occur?
- What assumptions are pushed to the caller?
- What downstream function receives tainted or privileged data?

### 2. Compare Sibling Functions

Compare similar functions:

- Same controller/resource.
- Same service class.
- Same repository pattern.
- Same object type.
- Same workflow state.

Flag negative space:

- One update endpoint checks ownership, another does not.
- One query scopes by tenant, another only by ID.
- One upload path normalizes filenames, another writes raw names.

### 3. Review Trust Hand-Offs

Pay special attention when:

- Controller passes `userId`, `tenantId`, `role`, or `status` to service.
- Service assumes controller already authorized.
- Repository assumes caller scoped data correctly.
- Mapper copies request DTO fields into persistent entity.
- Helper function is reused in a more privileged context.

### 4. Emit Findings Only With Proof

A confirmed finding still needs:

- Source.
- Sink or violated invariant.
- Missing control.
- File and line.
- Exploit scenario.
- False-positive analysis.

If evidence is incomplete, record it as a function-review hypothesis in `.github/sast-function-review.md`.

## Output Format

Write `.github/sast-function-review.md`:

```markdown
# Function Review

## Summary
- Functions reviewed:
- High-risk functions:
- Confirmed findings:
- Hypotheses:

## Reviewed Functions

### `<Class.method>` lines `<start-end>`
- Reachability:
- Actor:
- Inputs:
- Trust assumptions:
- Controls present:
- Controls missing or unclear:
- Sinks/state changes:
- Downstream calls:
- Decision: Pass | Finding | Hypothesis | Needs context
- Notes:
```

## Completion Gate

The skill is complete when every high-priority node from `.github/sast-function-tree.md` is reviewed and every unreviewed lower-priority node is listed with a reason.
