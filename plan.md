.github/
├── copilot-instructions.md              ← Always-on global security rules
│
├── skills/                              ← Each = one SKILL.md + optional scripts/refs
│   ├── sast-analysis/
│   │   ├── SKILL.md                     ← Phase 1: map architecture, entry points, data flows
│   │   └── references/
│   │       └── java-entry-points.md     ← Spring annotations, filters, listeners
│   │
│   ├── sast-sqli/
│   │   ├── SKILL.md                     ← Phase 1 recon → Phase 2 verify exploitability
│   │   └── references/java-sqli.md
│   │
│   ├── sast-rce/
│   │   ├── SKILL.md                     ← Command injection, reflection, eval
│   │   └── references/java-rce.md
│   │
│   ├── sast-idor/
│   │   ├── SKILL.md                     ← Ownership checks, ID in request
│   │   └── references/java-idor.md
│   │
│   ├── sast-auth/
│   │   ├── SKILL.md                     ← Auth bypass, session, JWT, privilege
│   │   └── references/java-auth.md
│   │
│   ├── sast-xxe/
│   │   ├── SKILL.md                     ← XML parsers, DTD, external entities
│   │   └── references/java-xxe.md
│   │
│   ├── sast-ssrf/
│   │   ├── SKILL.md                     ← URL fetching, user-controlled hosts
│   │   └── references/java-ssrf.md
│   │
│   ├── sast-crypto/
│   │   ├── SKILL.md                     ← Weak algos, homemade crypto, bad modes
│   │   └── references/java-crypto.md
│   │
│   ├── sast-deserial/
│   │   ├── SKILL.md                     ← ObjectInputStream, gadget chains
│   │   └── references/java-deserial.md
│   │
│   ├── sast-pathtraversal/
│   │   ├── SKILL.md                     ← File ops, path sanitization
│   │   └── references/java-path.md
│   │
│   ├── sast-business-logic/
│   │   ├── SKILL.md                     ← Invariants, state machines, race conditions
│   │   └── references/java-bizlogic.md
│   │
│   ├── sast-secrets/
│   │   ├── SKILL.md                     ← Hardcoded creds, tokens, keys
│   │   └── references/java-secrets.md
│   │
│   └── sast-report/
│       ├── SKILL.md                     ← Consolidates all, ranks by severity, 200-component report
│       └── references/report-format.md
│
├── prompts/
│   └── scan.prompt.md                   ← /scan → triggers full pipeline
│
├── chatmodes/
│   └── security-auditor.chatmode.md     ← VS Code chat mode, loads all skills
│
└── hooks/
    ├── pre-commit.md
    └── pre-push.md