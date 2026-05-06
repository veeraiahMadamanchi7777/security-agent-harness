---
name: sast-taint-tree
description: Convert risky function-tree paths into explicit Java taint trees from attacker-controlled sources through functions to sinks and violated controls.
---

# SKILL: sast-taint-tree — Source-to-Sink Taint Tree Tracing

## Purpose

For risky function paths, build explicit taint trees that show how attacker-controlled data, identity, authority, or state flows across functions.

Write the main artifact to `.github/sast-taint-trees.md`. Append confirmed findings to `.github/sast-findings.jsonl` when a taint tree proves a vulnerability.

## Inputs

- `.github/sast-function-tree.md`.
- `.github/sast-function-review.md`.
- `.github/sast-context.md`.
- Relevant vulnerability skill references.
- [`references/taint-tree-format.md`](references/taint-tree-format.md).

## Method

### 1. Select Taint Roots

Start from:

- Request params, path variables, headers, cookies, request bodies, multipart files.
- Message payloads.
- Webhook callbacks.
- Config or database values that are attacker-influenced or tenant-controlled.
- JWT claims or request attributes derived from external tokens.
- File contents, XML/YAML/serialized payloads, URL inputs.

### 2. Trace Across Functions

For each selected root:

- Track variable names and object fields.
- Track DTO-to-entity mapping.
- Track ID, tenant, role, status, price, path, URL, query, template, XML, command, token, and secret fields.
- Record sanitizers, validators, and authorization checks at the exact function where they occur.
- Continue until sink, state mutation, response exposure, or proof that the flow is safely terminated.

### 3. Build Taint Trees

Use tree notation:

```text
TAINT-001 <source> → <sink>
Source: Controller.method(@PathVariable id)
└─ Service.method(id, principal)
   ├─ Control: authenticated only
   ├─ Missing: owner/tenant predicate
   └─ Repository.findById(id)
      └─ Sink: returns object to response
Decision: Finding | Safe | Hypothesis
```

### 4. Decide

- **Finding**: source reaches sensitive sink or invariant violation without sufficient control.
- **Safe**: strong control terminates the flow.
- **Hypothesis**: flow is suspicious but a caller, sanitizer, or sink is not fully confirmed.

## Output Format

Write `.github/sast-taint-trees.md`:

```markdown
# Taint Trees

## Summary
- Taint roots reviewed:
- Trees built:
- Findings:
- Safe terminations:
- Hypotheses:

## Trees

### TAINT-001 `<short title>`
- Source:
- Actor:
- Sink or invariant:
- Decision:
- Tree:
- Controls:
- Missing control:
- Evidence:
- Follow-up:
```

## Completion Gate

The skill is complete when every high-risk function-tree path has either a taint tree, a safe termination explanation, or a documented reason it could not be traced.
