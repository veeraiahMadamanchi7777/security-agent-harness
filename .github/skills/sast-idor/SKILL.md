# SKILL: sast-idor — Insecure Direct Object Reference Detection

## Purpose

Identify endpoints where attacker-controlled resource identifiers (IDs, UUIDs, filenames, tokens) are used to access or modify resources without verifying that the requesting user owns or has permission to access that specific resource.

---

## Phase 1: Sink / Pattern Discovery

### 1.1 — ID-Based Resource Access Patterns

```bash
# Path variables that look like IDs — high IDOR density
grep -rn "@PathVariable.*[Ii]d\b\|@PathVariable.*[Uu]uid\|@PathVariable.*[Kk]ey\b\|@PathVariable.*[Nn]um\b" --include="*.java"

# Query params used as IDs
grep -rn "@RequestParam.*[Ii]d\b\|@RequestParam.*[Uu]uid\|@RequestParam.*[Nn]um" --include="*.java"

# Path patterns with ID segments
grep -rn "@GetMapping.*/{[^}]*[Ii]d[^}]*}\|@PostMapping.*/{[^}]*[Ii]d[^}]*}\|@DeleteMapping.*/{[^}]*[Ii]d[^}]*}\|@PutMapping.*/{[^}]*[Ii]d[^}]*}" --include="*.java"

# findById / getById / findOne — common IDOR sinks
grep -rn "\.findById(\|\.getById(\|\.findOne(\|\.getReferenceById(\|\.load(" --include="*.java"

# Delete/update by ID without ownership check
grep -rn "\.deleteById(\|\.delete(\|\.update(\|\.save(\|\.patch(" --include="*.java" -B10 | grep -B10 "@PathVariable\|@RequestParam"
```

### 1.2 — File / Document Access by Name or Path

```bash
# File download endpoints with user-supplied names
grep -rn "getFile\|downloadFile\|readFile\|openStream\|new File(" --include="*.java" -B5 | grep -B5 "@PathVariable\|@RequestParam\|getParameter"

# Document/blob stores keyed by user-supplied name
grep -rn "\.getObject(\|\.getBlob(\|S3Client.*getObject\|BlobServiceClient\|getBlobClient" --include="*.java" -B5 | grep -B5 "getParameter\|@PathVariable\|@RequestParam"
```

### 1.3 — Token / Key Reference

```bash
# Order, invoice, payment reference by token
grep -rn "findByToken\|findByReference\|findByOrderId\|findByInvoiceNumber\|findByTransactionId" --include="*.java" -B5 | grep -B5 "getParameter\|@PathVariable\|@RequestParam\|@RequestBody"

# Activation / reset tokens used to load user records
grep -rn "findByResetToken\|findByActivationToken\|findByVerificationToken\|findByConfirmToken" --include="*.java"
```

---

## Phase 2: Ownership Check Detection

For each sink found in Phase 1, determine if an ownership check exists:

### 2.1 — Positive Ownership Check Patterns (Safe)

```bash
# Principal comparison in code
grep -rn "getCurrentUser\|getAuthentication\|SecurityContextHolder\|getPrincipal\|getUsername\|getUserId\|currentUserId\|loggedInUser" --include="*.java" -A10 | grep -A10 "\.getId()\|\.getUserId()\|\.getOwnerId()\|\.getCreatedBy()"

# Spring Security method-level expressions
grep -rn "@PreAuthorize.*#.*\.id\s*==\|@PreAuthorize.*authentication\.name\|@PreAuthorize.*principal\|@PostAuthorize.*returnObject\." --include="*.java"
# e.g.: @PreAuthorize("#order.userId == authentication.principal.id")

# JPA query scope — query filters by userId
grep -rn "findByIdAndUserId\|findByIdAndOwnerId\|findByIdAndCreatedBy\|findByIdAndAccount" --include="*.java"

# Explicit comparison in service layer
grep -rn "\.getUserId()\s*!=\s*\|\.getOwnerId()\s*!=\s*\|\.equals(currentUser\|\.getId()\s*!=\s*principal\." --include="*.java"
```

### 2.2 — Missing Ownership Check (IDOR Candidate)

If a `findById()` call is found and **none** of the patterns above appear in the same method or class, this is a strong IDOR candidate. Manually review:

1. Does the method use `SecurityContextHolder` to get the current user?
2. Is there a `@PreAuthorize` annotation on the controller method?
3. Does the repository query include a `userId`/`ownerId` clause?
4. Is there any explicit ID comparison after retrieval?

If NO to all four → **report as IDOR**.

---

## Phase 3: Privilege Level Analysis

### 3.1 — Horizontal vs. Vertical IDOR

**Horizontal IDOR:** User A accesses User B's resource (same privilege level)
- Pattern: `GET /api/accounts/{accountId}` where accountId is user-controlled and no owner check exists

**Vertical IDOR:** Lower-privilege user accesses admin resource
- Pattern: `GET /api/admin/reports/{reportId}` where auth check only verifies login, not admin role

```bash
# Admin-scoped endpoints without role check
grep -rn "@GetMapping.*/admin/\|@PostMapping.*/admin/\|@DeleteMapping.*/admin/" --include="*.java" -B2 | grep -B2 "@PreAuthorize\|@Secured\|@RolesAllowed" | grep -v "@PreAuthorize\|@Secured\|@RolesAllowed"

# hasRole check absent on admin paths
grep -rn 'antMatchers\|requestMatchers' --include="*.java" -A3 | grep -v "hasRole\|hasAuthority\|authenticated\|permitAll"
```

### 3.2 — Mass Assignment IDOR

When `@ModelAttribute` or `@RequestBody` binds a full object, an attacker may supply fields they shouldn't control (e.g., `userId`, `role`, `accountId`):

```bash
# @ModelAttribute binding to entity/POJO directly
grep -rn "@ModelAttribute\|@RequestBody" --include="*.java" -A2 | grep -A2 "User\b\|Account\b\|Order\b\|Entity\b"

# Check if the entity has sensitive fields like userId, role, isAdmin
grep -rn "setUserId\|setRole\|setAdmin\|setAccountId\|setTenantId\|setOwnerId" --include="*.java" | grep -v "//\|test\|Test"
```

---

## Phase 4: Severity Assessment

| Pattern | Severity |
|---------|---------|
| Unauthenticated endpoint + no owner check | CRITICAL |
| Authenticated + horizontal IDOR (user-level resource) | HIGH |
| Authenticated + vertical IDOR (admin resource) | CRITICAL |
| Mass assignment of `userId`/`role` | HIGH |
| File access by user-supplied filename (path traversal variant) | HIGH |
| Token-based access without binding to session user | HIGH |
| IDOR on read-only endpoint (data disclosure only) | MEDIUM |
| IDOR behind non-guessable UUID (reduced likelihood) | MEDIUM |

---

## Finding Format Example

```
### [HIGH] IDOR — Account Record Access Without Ownership Check

**File:** `src/main/java/com/example/AccountController.java:34`
**CWE:** CWE-639
**CVSS:** 8.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Taint Path:**
GET /api/accounts/{accountId} → AccountController.getAccount(accountId) → accountRepository.findById(accountId)
No ownership check between JWT principal and returned account.

**Vulnerable Code:**
```java
@GetMapping("/api/accounts/{accountId}")
public Account getAccount(@PathVariable Long accountId) {
    return accountRepository.findById(accountId)
        .orElseThrow(() -> new ResourceNotFoundException("Account not found"));
    // No check that the authenticated user owns this account
}
```

**Proof of Concept:**
Authenticated as User A (accountId=100):
```
GET /api/accounts/101 HTTP/1.1
Authorization: Bearer <User_A_JWT>
```
Returns User B's account data.

**Remediation:**
```java
@GetMapping("/api/accounts/{accountId}")
public Account getAccount(@PathVariable Long accountId, Authentication auth) {
    Account account = accountRepository.findByIdAndUserId(accountId, auth.getPrincipal().getId())
        .orElseThrow(() -> new AccessDeniedException("Not your account"));
    return account;
}
```
Or use `@PreAuthorize` with SpEL expression binding to the resource owner.

**References:** CWE-639, OWASP A01:2021
```
