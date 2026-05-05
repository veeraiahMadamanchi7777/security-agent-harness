# SKILL: sast-api-abuse — API Abuse & Business Logic Research

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

Emit findings using `.github/schemas/finding.schema.json`.

Use skill value: `sast-api-abuse`.

Recommended ID prefix: `APIABUSE-001`.

Common CWEs:

- `CWE-639` for IDOR / user-controlled key authorization bypass
- `CWE-863` for incorrect authorization
- `CWE-284` for improper access control
- `CWE-352` for CSRF-like browser abuse
- `CWE-613` for session/token expiration bugs
- `CWE-200` for excessive data exposure

---

## Self-Contained Check

This skill can run standalone, but it is strongest with Phase 1 endpoint context and existing findings from `sast-auth`, `sast-idor`, `sast-massassignment`, and `sast-business-logic`.
