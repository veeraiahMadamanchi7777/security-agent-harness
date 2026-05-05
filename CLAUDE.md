# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **security code analysis harness** for Java applications — a modular SAST (Static Application Security Testing) system implemented as GitHub Copilot skills/prompts. There is no executable code; the deliverables are Markdown files that instruct AI agents how to perform security audits.

## Repository Layout (Planned)

All content lives under `.github/`:

```
.github/
├── copilot-instructions.md          ← Always-on global rules applied to every session
├── agents/
│   └── security-auditor.agent.md    ← Agent entrypoint for running the SAST pipeline
├── skills/                          ← 19 vulnerability skills plus analysis/report consolidation
│   ├── sast-analysis/               ← Phase 1: architecture recon, entry points, data flows
│   ├── sast-sqli/                   ← SQL Injection
│   ├── sast-rce/                    ← Remote Code Execution
│   ├── sast-idor/                   ← Insecure Direct Object Reference
│   ├── sast-auth/                   ← Auth/session/JWT/privilege bypass
│   ├── sast-xxe/                    ← XML External Entity
│   ├── sast-ssrf/                   ← Server-Side Request Forgery
│   ├── sast-crypto/                 ← Weak cryptography
│   ├── sast-deserial/               ← Deserialization (ObjectInputStream, gadget chains)
│   ├── sast-pathtraversal/          ← Path traversal / file ops
│   ├── sast-business-logic/         ← Invariants, state machines, race conditions
│   ├── sast-secrets/                ← Hardcoded credentials/tokens
│   ├── sast-csrf/                   ← Cross-site request forgery
│   ├── sast-openredirect/           ← User-controlled redirects
│   ├── sast-templateinject/         ← Server-side template injection
│   ├── sast-massassignment/         ← Unsafe request binding to sensitive fields
│   ├── sast-dependency/             ← Known-vulnerable dependencies
│   ├── sast-researcher/             ← AI-assisted hypothesis and variant analysis
│   ├── sast-api-abuse/              ← API abuse and business logic research
│   ├── sast-attack-chain/           ← Compound exploit chain analysis
│   └── sast-report/                 ← Consolidates findings, severity ranking, 200-component report
├── prompts/
│   └── scan.prompt.md               ← /scan command → triggers full pipeline
├── chatmodes/
│   └── security-auditor.chatmode.md ← VS Code chat mode that loads all skills
└── hooks/
    ├── pre-commit.md
    └── pre-push.md
```

## Architecture

The system runs in **three phases**:

1. **Phase 1 — Architecture recon** (`sast-analysis`): Maps the target Java application's entry points (Spring annotations, filters, listeners), trust boundaries, and data flows. Produces shared context consumed by Phase 2 skills.

2. **Phase 2 — Parallel vulnerability analysis** (all `sast-*` skills except `sast-analysis` and `sast-report`): Each skill runs independently, referencing Phase 1 output and its own `references/` docs when present.

3. **Phase 3 — Reporting** (`sast-report`): Consolidates all skill outputs, deduplicates, ranks by severity, and produces a structured 200-component report.

## Authoring Guidelines

- **SKILL.md files** define the agent's methodology: what to grep for, what patterns indicate a vulnerability, how to distinguish true positives from false positives, and what output format to produce.
- **`references/` docs** are Java-specific reference material (e.g., dangerous APIs, sink patterns) that the skill loads at runtime — keep them factual and concise.
- **`copilot-instructions.md`** is always-on context; put rules here that apply across all skills (e.g., output format standards, severity definitions, scope constraints).
- **`scan.prompt.md`** orchestrates the pipeline; it should invoke skills in order and pass Phase 1 output forward.
- Skills must be self-contained — a skill should be runnable independently without requiring other skills to have already executed (Phase 1 output should be optional/fallback-safe).
