---
name: sast-api-abuse
description: Review Java APIs for abuse cases including missing rate limits, enumeration, replay, excessive data exposure, and workflow manipulation.
---

# SKILL: sast-api-abuse — API Abuse & Business Logic Research

## References

Load [`references/java-api-abuse.md`](references/java-api-abuse.md) at the start of this skill for horizontal/vertical authorization patterns, tenant isolation source table, token lifecycle flaws, excessive data exposure patterns, state machine bypass reference, and false positives.

## Purpose

Find security flaws in API semantics that do not map cleanly to a single dangerous sink: authorization gaps, tenant breakout, replay, workflow bypass, excessive data exposure, and unsafe state transitions.

This is a researcher-style skill. It should compare endpoints, models, services, and authorization patterns to discover inconsistencies.

---

## Phase 1: API Surface Mapping

Use `.github/sast-context.md` when available. Otherwise discover API routes:

```bash
rg "@RestController|@Controller|@RequestMapping|@GetMapping|@PostMapping|@PutMapping|@PatchMapping|@DeleteMapping" --glob "*.java"
rg "@PreAuthorize|@PostAuthorize|@Secured|@RolesAllowed|hasRole|hasAuthority|authenticated|permitAll" --glob "*.java"
```

Group endpoints by resource:

- user/account/profile
- organization/tenant/workspace
- order/payment/invoice/subscription
- admin/config/settings
- invite/token/password reset
- file/import/export/report

---

## Phase 2: Abuse Patterns

### 2.1 — Horizontal Authorization Bypass

Look for object IDs from request paths or bodies used without ownership predicates:

```bash
rg "@PathVariable.*(id|Id)|@RequestParam.*(id|Id)|getParameter\\(.*id" --glob "*.java"
rg "findById\\(|getReferenceById\\(|deleteById\\(|existsById\\(" --glob "*.java"
rg "ownerId|userId|accountId|tenantId|organizationId|workspaceId" --glob "*.java" -i
```

Confirm whether repository queries include the authenticated principal's owner/tenant/account constraint.

### 2.2 — Vertical Authorization Bypass

Compare admin-looking endpoints and services:

```bash
rg "admin|role|authority|permission|privilege|superuser|moderator" --glob "*.java" -i
rg "@PreAuthorize|hasRole|hasAuthority|@RolesAllowed" --glob "*.java"
```

Flag only when a non-admin reachable path invokes admin behavior without equivalent authorization.

### 2.3 — Tenant Isolation Breaks

Look for tenant IDs accepted from the request:

```bash
rg "tenantId|tenant_id|orgId|organizationId|workspaceId|accountId" --glob "*.java" -i
rg "TenantContext|SecurityContext|Principal|Authentication|getName\\(" --glob "*.java"
```

High-risk signals:

- repository method lacks tenant predicate
- tenant context is set from a header without verification
- request body `tenantId` overwrites server-side tenant
- cache key omits tenant ID

### 2.4 — Replay / Token Lifecycle Bugs

```bash
rg "resetToken|verificationToken|inviteToken|otp|nonce|code|magicLink|activation" --glob "*.java" -i
rg "expires|expiry|used|consumed|revoked|delete|invalidate" --glob "*.java" -i
```

Check:

- token expiry exists and is enforced
- token is single-use
- token is scoped to purpose, user, and tenant
- token generation uses cryptographic randomness

### 2.5 — State Machine Bypass

```bash
rg "status|state|phase|approve|reject|cancel|refund|ship|complete|close|reopen" --glob "*.java" -i
```

Look for direct state updates that skip allowed transitions, actor checks, or invariant validation.

### 2.6 — Excessive Data Exposure

```bash
rg "return .*Repository|findAll\\(|ResponseEntity\\.ok\\(|toDto|Mapper|@JsonIgnore|password|secret|token|ssn|dob" --glob "*.java" -i
```

Check whether APIs return entities directly, expose sensitive fields, or omit role/tenant filters on collection endpoints.

---

## Phase 3: Research Checks

For each candidate, compare:

- create vs update vs delete auth checks for the same resource
- list vs detail endpoint filtering
- UI route assumptions vs API enforcement
- service methods called by both admin and non-admin controllers
- DTO fields vs entity fields
- repository predicates with and without tenant/owner filters

Try to create a concrete abuse case:

```http
PATCH /api/orders/{other_users_order_id}
Content-Type: application/json

{"status":"APPROVED","price":1}
```

Only report if the code shows the server would accept or act on the abusive request.

---

## Finding Format

Follow the canonical format from `copilot-instructions.md`. Example:

```
### [HIGH] API Abuse — Token Not Invalidated After Use (Replay Attack)

**ID:** APIABUSE-001
**File:** `src/main/java/com/example/PasswordResetService.java:58`
**CWE:** CWE-613 | **OWASP:** A07:2021-Identification and Authentication Failures
**CVSS (estimated):** 8.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)
**Confidence:** High
**Skill:** `sast-api-abuse`

**Taint Path:**
`POST /api/password-reset {"token":"X","newPassword":"Y"}` → `PasswordResetService.reset(token) (PasswordResetService.java:54)` → `tokenRepo.findByToken(token) (PasswordResetService.java:56)` → password updated → token **not deleted** `(PasswordResetService.java:58-62)`

**Vulnerable Code:**
```java
public void reset(String token, String newPassword) {
    ResetToken rt = tokenRepo.findByToken(token).orElseThrow();
    userRepo.updatePassword(rt.getUserId(), encode(newPassword));
    // Token is never deleted or marked used — replayable indefinitely
}
```

**Why Exploitable:**
The reset token is validated but never invalidated after use. An attacker who intercepts or obtains the token can replay it to change the password again at any time, effectively maintaining persistent account access.

**Proof-of-Concept:**
```http
POST /api/password-reset HTTP/1.1
Content-Type: application/json

{"token":"abc123","newPassword":"firstReset"}

# Same token reused:
POST /api/password-reset HTTP/1.1
{"token":"abc123","newPassword":"secondReset"}  # succeeds
```

**Remediation:**
```java
public void reset(String token, String newPassword) {
    ResetToken rt = tokenRepo.findByToken(token).orElseThrow();
    userRepo.updatePassword(rt.getUserId(), encode(newPassword));
    tokenRepo.delete(rt);  // invalidate immediately after use
}
```

**References:** https://cwe.mitre.org/data/definitions/613.html, OWASP A07:2021
```

Use skill value `sast-api-abuse`. Recommended ID prefix: `APIABUSE-NNN`.
Common CWEs: `CWE-639` (IDOR), `CWE-863` (incorrect authorization), `CWE-284` (improper access control), `CWE-613` (token expiry), `CWE-200` (excessive data exposure).

JSONL line (append to `.github/sast-findings.jsonl`):
```json
{"id":"APIABUSE-001","skill":"sast-api-abuse","cwe":"CWE-613","owasp":"A07:2021-Identification and Authentication Failures","severity":"High","confidence":"High","file":"src/main/java/com/example/PasswordResetService.java","line":58,"method":"reset","class":"com.example.PasswordResetService","evidence":"userRepo.updatePassword(rt.getUserId(), encode(newPassword));\n// Token is never deleted or marked used","sink":"password updated without token invalidation","source":"POST /api/password-reset token parameter","taint_path":[],"sanitizer_present":false,"sanitizer_detail":"","remediation":"Call tokenRepo.delete(rt) immediately after successful password update","references":["https://cwe.mitre.org/data/definitions/613.html"],"false_positive_indicators":["token has short expiry enforced at DB level"],"duplicate_of":null}
```

---

## Self-Contained Check

This skill can run standalone, but it is strongest with Phase 1 endpoint context and existing findings from `sast-auth`, `sast-idor`, `sast-massassignment`, and `sast-business-logic`.
