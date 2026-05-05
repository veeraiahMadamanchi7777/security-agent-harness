# SKILL: sast-attack-chain — Exploit Chain & Compound Risk Analysis

## Purpose

Identify cases where individually moderate findings combine into a higher-impact exploit chain. This skill reads Phase 2 findings and source context, then reasons like a security researcher about attacker progression.

Do not inflate severity without a concrete chain. Each chain must identify the starting access level, every required step, and the final impact.

---

## Phase 1: Inputs

Read:

- `.github/sast-context.md`
- `.github/sast-findings.jsonl`
- source files referenced by existing findings
- security configuration and endpoint mappings

If no findings exist yet, run this as a hypothesis pass over high-risk entry points and record only coverage notes unless a complete chain is confirmed.

---

## Phase 2: Chain Patterns

### 2.1 — Public Endpoint to Sensitive Internal Action

Look for:

- public endpoint accepts URL, path, ID, or expression
- service uses that value to reach internal service, file, admin API, or database
- response leaks data or changes state

Examples:

- open redirect + OAuth callback confusion
- SSRF + cloud metadata access
- path traversal + secret file read
- IDOR + exported PII

### 2.2 — Authenticated Low-Privilege to Admin Impact

Look for:

- user-controlled `role`, `tenantId`, `ownerId`, `status`, `price`, or approval fields
- missing object ownership checks
- mass assignment into entity followed by save
- admin-only service callable from non-admin endpoint

### 2.3 — Injection to Credential or Token Theft

Look for:

- SQLi exposing password reset tokens, API keys, session IDs, OAuth tokens
- template injection reading environment variables or config
- XXE reading local config or cloud credentials
- deserialization reaching filesystem/network gadgets

### 2.4 — Weak Secret to Auth Bypass

Look for:

- hardcoded JWT/HMAC/session signing keys
- weak crypto in remember-me tokens
- predictable password reset or invitation tokens
- insecure random used for auth-sensitive values

### 2.5 — Parser Confusion to Validation Bypass

Look for:

- URL validation accepts one host while client follows another
- path validation checks raw input before decoding
- redirect validation allows protocol-relative URLs
- extension/content-type check bypass before file processing

---

## Phase 3: Chain Validation

For each proposed chain, document:

```text
Attacker: unauthenticated | authenticated user | low-privileged tenant user | admin
Step 1: source and endpoint
Step 2: intermediate primitive gained
Step 3: second sink or trust-boundary crossing
Impact: data read, code execution, privilege escalation, account takeover, tenant breakout
Required conditions: config, roles, feature flags, deployment assumptions
Evidence: file:line for every step
```

Reject the chain if any step depends on speculation that cannot be tied to code or configuration.

---

## Phase 4: Severity Adjustment

Escalate a chain when:

- all steps are reachable by the same attacker
- the chain crosses privilege or tenant boundaries
- the first step is unauthenticated
- the final impact is RCE, auth bypass, sensitive data exfiltration, or financial/state manipulation

Do not escalate when:

- one step requires admin access already
- steps require incompatible roles or tenants
- the second primitive is not reachable in the same deployment
- impact is purely theoretical

---

## Finding Format

Emit findings using `.github/schemas/finding.schema.json`.

Use skill value: `sast-attack-chain`.

Recommended ID prefix: `CHAIN-001`.

Use the CWE of the dominant root cause. Common choices:

- `CWE-863` for authorization bypass chains
- `CWE-918` for SSRF-led chains
- `CWE-22` for traversal-led chains
- `CWE-89` for SQLi-led chains
- `CWE-200` for information exposure chains

Set `taint_path` to include each chain step with file and line evidence.

---

## Self-Contained Check

This skill is most valuable after other Phase 2 skills have emitted findings. If run earlier, treat it as a chain-hypothesis pass and avoid confirmed output unless every step is directly verified.
