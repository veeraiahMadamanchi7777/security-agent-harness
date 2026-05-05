# SKILL: sast-researcher — AI-Assisted Security Research Patterns

## Purpose

Add a researcher-style review pass on top of the vulnerability-specific SAST skills. This skill uses semantic reasoning, hypothesis generation, variant analysis, and negative testing to find issues that simple grep patterns often miss.

This skill must still obey the global evidence standard: do not report a confirmed vulnerability unless the source, sink, exploit path, missing defense, file, and line number are verified.

---

## Phase 1: Build Exploit Hypotheses

Read `.github/sast-context.md` if available. Create a short list of hypotheses before scanning deeply:

- Which public or weakly authenticated endpoints mutate state?
- Which endpoints accept identifiers, URLs, filenames, templates, expressions, filters, or serialized objects?
- Which services cross trust boundaries: database, filesystem, network, queue, cache, identity provider, payment, admin operations?
- Which helpers centralize validation, authorization, tenant scoping, or sanitization?
- Which code paths look intentionally flexible: generic search, export, import, webhook, callback, proxy, report builder, admin console, rules engine?

Write hypotheses as concrete source-to-sink questions:

```text
Can attacker input from UserController.search(filter) influence OrderRepository dynamic query construction?
Can tenantId from the request override the authenticated user's tenant in BillingService?
Can webhook URL validation be bypassed through redirects, DNS rebinding, or parser confusion?
```

---

## Phase 2: Researcher Pattern Library

### 2.1 — Variant Analysis

When one risky pattern is found, search for siblings:

```bash
# Same sink family in nearby services
rg "executeQuery|createNativeQuery|Runtime\\.exec|sendRedirect|RestTemplate|WebClient|ObjectInputStream|DocumentBuilderFactory" --glob "*.java"

# Same validation helper used elsewhere
rg "validate[A-Za-z]*(Url|Path|Tenant|Owner|Role|Input|Redirect|File|Xml|Query)" --glob "*.java"

# Same endpoint shape in adjacent controllers
rg "@(Get|Post|Put|Patch|Delete)Mapping|@RequestMapping" --glob "*.java"
```

Ask:

- Is the same sanitizer applied consistently?
- Did one method add an auth check while a sibling forgot it?
- Does a helper validate for one sink but get reused for a different sink with different rules?

### 2.2 — Negative Space Review

Look for code that should exist but is missing:

- mutating endpoint with no authorization check
- tenant-aware repository method without tenant predicate
- update flow that lacks ownership check before save
- file read/write without canonical path containment check
- outbound URL fetch without host allowlist and private-IP rejection
- XML parser creation without XXE hardening features
- deserialization without class allowlist
- redirect without same-origin or fixed-destination enforcement

Search for nearby positive examples, then compare:

```bash
rg "hasRole|hasAuthority|@PreAuthorize|ownerId|tenantId|organizationId|accountId" --glob "*.java"
rg "canonical|normalize|startsWith|toRealPath|allowedHosts|ALLOWED_|allowlist|whitelist" --glob "*.java"
```

### 2.3 — Trust Boundary Mismatch

Find places where the code trusts data from the wrong side of a boundary:

- client-supplied `userId`, `accountId`, `tenantId`, `role`, `price`, `status`, `isAdmin`
- headers used as identity without gateway verification
- request body fields copied into persisted entities
- callbacks/webhooks treated as trusted internal events
- queue messages or scheduled jobs that process externally supplied content

```bash
rg "userId|accountId|tenantId|orgId|organizationId|role|roles|price|amount|status|approved|verified|enabled|isAdmin" --glob "*.java" -i
rg "X-User|X-Role|X-Tenant|X-Forwarded|X-Api|Authorization" --glob "*.java"
```

### 2.4 — Parser Differential / Canonicalization Bugs

Prioritize code that parses the same value more than once or validates with one parser and consumes with another:

- `URL` vs `URI` host parsing
- string prefix checks before filesystem normalization
- regex validation before framework routing
- JSON/XML/YAML object typing differences
- path decoding before or after normalization
- redirect validation before URL decoding

```bash
rg "URL\\(|URI\\.|URLDecoder|URLEncoder|Paths\\.get|Path\\.of|normalize\\(|toRealPath|Pattern\\.compile|matches\\(" --glob "*.java"
```

### 2.5 — Stateful Workflow Abuse

Review workflows where order matters:

- approve before ownership validation
- pay/refund/cancel race windows
- password reset token reuse
- invitation acceptance across tenants
- role changes without re-authentication
- optimistic locking missing around balance or inventory

```bash
rg "approve|reject|cancel|refund|transfer|withdraw|deposit|invite|accept|reset|verify|activate|deactivate|lock|unlock" --glob "*.java" -i
rg "@Transactional|synchronized|LockMode|Version|SELECT .* FOR UPDATE|ReentrantLock" --glob "*.java"
```

---

## Phase 3: Try to Disprove Each Candidate

Before emitting a finding, actively search for reasons it may be safe:

1. Is the endpoint unreachable or test-only?
2. Is authentication enforced globally in security config?
3. Is authorization checked in a service, repository predicate, aspect, filter, or interceptor?
4. Is the input overwritten by server-side identity before the sink?
5. Is validation allowlist-based and applied after decoding/canonicalization?
6. Is the sink actually using a parameterized or safe API?

Only report candidates that survive this challenge.

---

## Finding Format

Emit findings using `.github/schemas/finding.schema.json`.

Use skill value: `sast-researcher`.

Recommended ID prefix: `RESEARCH-001`.

Use the most specific CWE available. If the issue is a confused-deputy or trust-boundary flaw without a better fit, use `CWE-863` or `CWE-284`.

---

## Self-Contained Check

This skill runs best after Phase 1 context exists, but it can run standalone by focusing on controllers, services, repositories, filters, and security configuration.
