# Java Security Research Reference — Variant Analysis, Trust Boundaries & Parser Differentials

## Variant Analysis Methodology

### Finding Siblings of a Confirmed Sink

When a confirmed vulnerability is found at sink `X`, search for all call sites that share the same:

1. **Same validation helper** — if `validateInput(x)` is the missing check, find all callers that skip it:
   ```bash
   # Find all methods that call the same DAO/repository method without calling the validator
   grep -rn "findById\|executeQuery\|getForObject" --include="*.java" |
     grep -v "validateOwnership\|checkPermission\|assertAuthorized"
   ```

2. **Same input binding pattern** — if `@RequestParam String id` feeds a vulnerable sink, find all similar bindings:
   ```bash
   grep -rn "@RequestParam\|@PathVariable\|@RequestBody" --include="*.java" -A3 |
     grep -A3 "findById\|findByUsername\|loadByKey"
   ```

3. **Same service/DAO class** — if `UserService.findById` is vulnerable, all methods of `UserService` that accept external input deserve review.

### Negative Space Review

Look for **missing** security controls rather than present dangerous APIs:

| What to Search For | Pattern | Risk if Absent |
|------------------|---------|---------------|
| Ownership check after `findById` | `findById` not followed by `auth.getId().equals(entity.getOwnerId())` | IDOR |
| Tenant isolation | `findAll()` or `findByX()` without `AND tenant_id = :tenantId` | Tenant data leak |
| Canonical path check after `new File()` | `new File(base, name)` not followed by `getCanonicalPath().startsWith(base)` | Path traversal |
| Nonce/CSRF check before state change | POST/PUT/DELETE handlers without `@CsrfRequired` or token validation | CSRF |
| Authorization annotation on controller method | `@GetMapping`/`@PostMapping` without `@PreAuthorize` or Spring Security rule | Auth bypass |
| Input validation before use in SQL | Method body with SQL string not preceded by `@Valid` or explicit validator | SQLi |

## Trust Boundary Patterns

### Dangerous Trust Sources

| Input Source | Trust Level | Check Required |
|-------------|------------|---------------|
| `request.getParameter()` / `@RequestParam` | UNTRUSTED | Validate all values |
| `request.getHeader()` | UNTRUSTED | Especially `X-Forwarded-For`, `X-Tenant-ID`, `X-User-ID` |
| `@RequestBody` JSON fields | UNTRUSTED | Validate and use DTOs |
| `@PathVariable` | UNTRUSTED | Validate type and ownership |
| `request.getCookies()` | UNTRUSTED | Cookies are user-controlled |
| `@CookieValue` | UNTRUSTED | Same as above |
| JWT `sub`/`role` claims — from properly verified token | TRUSTED | Only if signature verified with correct algorithm |
| JWT claims — from unverified or re-read request attribute | UNTRUSTED | Re-reading from request attribute loses verification guarantee |
| Database values — originally from user input | SEMI-TRUSTED | Sanitized at write time; validate again before re-use in SQL/command |
| Config properties (`@Value`) | TRUSTED | Static config — not user controlled |

### Common Trust Boundary Violations

```java
// VIOLATION 1 — tenantId from request header, not JWT
String tenantId = request.getHeader("X-Tenant-ID");  // UNTRUSTED — user controls this
TenantContext.setCurrentTenant(tenantId);

// VIOLATION 2 — userId re-read from request attribute after filter sets it
// (filter might not run for all paths, or attribute is user-settable)
Long userId = (Long) request.getAttribute("userId");  // check what sets this attribute

// VIOLATION 3 — role from JWT body field, not claims
String role = jwtBody.get("role").asText();  // relies on unverified claim if JWT not fully validated

// VIOLATION 4 — price from request body for server-side calculation
BigDecimal price = orderRequest.getPrice();  // client never controls price — fetch from DB
```

## Parser Differential Attacks

Exploitable when two components parse the same input with different rules:

| Differential | Attack Vector |
|-------------|--------------|
| `java.net.URL` vs `java.net.URI` URL parsing | URL normalizes differently — validation with URI, fetch with URL |
| Spring URL pattern vs Shiro pattern | `/admin/` matches Shiro but not Spring → auth bypass |
| Spring URL pattern vs Tomcat | Trailing semicolon `;x` stripped by Tomcat but not matched by Spring Security |
| JSON parsed twice | First parse for validation with strict parser, second for use with lenient parser |
| Path decoded once for check, twice for use | `%252F` → first decode `%2F`, check passes; second decode `/` → traversal |
| Unicode normalization | NFC vs NFD normalization differences between validator and processor |

```java
// EXAMPLE: URL path decoded once by validator, twice by servlet container
String path = request.getPathInfo();  // may be decoded once
if (path.contains("..")) throw new SecurityException();  // checks decoded path
// Attacker sends: /files/..%252F../etc/passwd
// Decoded once: /files/../%2F../etc/passwd — passes "../" check? Depends on order
// Decoded twice by container: /files/../../etc/passwd — traversal succeeds
```

## Stateful Workflow Abuse Patterns

### Direct State Transition Bypass

```
Normal flow:    PENDING → CONFIRMED → PAID → SHIPPED → DELIVERED
Abuse attempt:  PENDING → SHIPPED (skipping CONFIRMED, PAID)
                DELIVERED → REFUNDED (bypassing merchant approval)
```

Check for:
- `status` field settable via `@RequestBody` without transition validation
- Endpoints for late-flow actions not checking predecessor states
- Lack of `@PreAuthorize` or status check before advancing state

### Payment Race Window

```
1. User initiates payment → payment_intent created
2. Server checks payment_intent status (PENDING)
3. [Race window] — attacker sends refund request before webhook confirms payment
4. Refund processed against unconfirmed payment → negative balance
```

Look for missing idempotency keys on payment operations and race conditions between webhook processing and direct API calls.

## Hypothesis Tracking Template

For each research hypothesis, document:

```
[HYPOTHESIS] CWE-XXX — ShortDescription

Premise: <observed pattern that may be vulnerable>
Suspected source: <where attacker input enters>
Suspected sink: <dangerous operation if tainted>
Confidence blocker: <what would need to be true for this to be a real finding>
Confirmation step: grep -rn "<pattern>" --include="*.java"
Disprove condition: <what would confirm this is NOT vulnerable>
Status: [UNCONFIRMED | CONFIRMED → emit finding | DISPROVED]
```

## Research Automation Patterns

```bash
# Find all @RequestMapping methods without @PreAuthorize or @Secured
grep -rn "@GetMapping\|@PostMapping\|@PutMapping\|@DeleteMapping\|@RequestMapping" \
  --include="*.java" -B2 | grep -B2 -v "@PreAuthorize\|@Secured\|@RolesAllowed"

# Find all repository findById calls — check each for ownership assertion
grep -rn "\.findById\|\.findOne\b" --include="*.java" -A5 | \
  grep -v "equals.*getId\|assertOwner\|checkAccess\|userId\|ownerId"

# Find all headers read as trust signals
grep -rn "getHeader.*[Tt]enant\|getHeader.*[Uu]ser\|getHeader.*[Rr]ole\|getHeader.*[Aa]dmin" \
  --include="*.java"

# Find static fields on Spring singleton beans — potential shared state race
grep -rn "@Service\|@Component\|@Repository" --include="*.java" -A 20 | \
  grep -v "final\|static final" | grep "private.*List\|private.*Map\|private.*Set"
```
