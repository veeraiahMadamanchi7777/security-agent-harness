# Java API Abuse Reference — Authorization Patterns, Tenant Isolation & Token Lifecycle

## Horizontal Authorization Bypass (IDOR) Patterns

### Direct Object Reference Without Ownership Check

```java
// DANGEROUS — ID from path, no ownership check
@GetMapping("/invoices/{id}")
public Invoice getInvoice(@PathVariable Long id) {
    return invoiceRepository.findById(id).orElseThrow();
    // Any authenticated user can read any invoice by ID
}

// SAFE — ownership-bound query
@GetMapping("/invoices/{id}")
public Invoice getInvoice(@PathVariable Long id, Authentication auth) {
    Long currentUserId = ((UserDetails) auth.getPrincipal()).getId();
    return invoiceRepository.findByIdAndOwnerId(id, currentUserId)
        .orElseThrow(() -> new AccessDeniedException("Not your invoice"));
}
```

### Dangerous Repository Query Patterns

| Pattern | Risk |
|---------|------|
| `findById(id)` with no ownership assertion | IDOR — user can access any record |
| `findAll()` with no tenant/user filter | Full data exposure |
| `deleteById(id)` with no ownership check | Anyone can delete any record |
| `findByEmail(email)` returning full entity | Enumeration + data exposure |
| Derived queries without `AndUserId` or `AndOwnerId` | Missing ownership predicate |

```bash
# Grep for repository calls missing ownership predicates
grep -rn "\.findById\b\|\.findOne\b\|\.deleteById\b" --include="*.java" -A3 |
  grep -v "findByIdAnd\|OrElseThrow.*AccessDenied\|checkOwnership\|assertOwner"
```

## Vertical Authorization Bypass

### Admin Actions Reachable by Regular Users

```java
// DANGEROUS — admin action without role check
@PostMapping("/api/users/{id}/promote")
public void promoteToAdmin(@PathVariable Long id) {
    userService.setRole(id, Role.ADMIN);  // no @PreAuthorize
}

// SAFE
@PostMapping("/api/users/{id}/promote")
@PreAuthorize("hasRole('ADMIN')")
public void promoteToAdmin(@PathVariable Long id) {
    userService.setRole(id, Role.ADMIN);
}
```

### URL-Based Authorization Bypass Patterns

| Bypass Technique | Example | Cause |
|-----------------|---------|-------|
| Path parameter variation | `/admin/users` vs `/Admin/Users` | Case-insensitive URL matching |
| Trailing slash | `/admin/` vs `/admin` | Pattern mismatch |
| Encoded characters | `/admin%2Fusers` | Path decode inconsistency |
| Semicolon bypass (Tomcat) | `/admin;foo/users` | Servlet path vs Security path |
| Double slash | `//admin/users` | URL normalization inconsistency |
| Verb override | POST with `X-HTTP-Method-Override: DELETE` | Method override not validated |

## Tenant Isolation Patterns

### Correct Tenant Context Sources

| Source | Trust Level | Notes |
|--------|------------|-------|
| JWT claim `tenantId` (verified token) | TRUSTED | Verified by signature — cannot be forged |
| Established from user record in DB after JWT auth | TRUSTED | DB authoritative |
| `X-Tenant-ID` request header | UNTRUSTED | User-supplied — can be set to any value |
| Subdomain parsed from `Host` header | SEMI-TRUSTED | Requires strict parsing and validation |
| Request body field `tenantId` | UNTRUSTED | Always verify against authenticated user's tenant |

### Multi-Tenant Query Patterns

```java
// DANGEROUS — no tenant isolation
public List<Document> getAllDocuments() {
    return documentRepository.findAll();  // returns documents from all tenants
}

// DANGEROUS — tenant from request, not JWT
public List<Document> getDocuments(String tenantId) {  // tenantId from @RequestParam
    return documentRepository.findByTenantId(tenantId);  // caller controls scope
}

// SAFE — tenant from authenticated context
public List<Document> getDocuments(Authentication auth) {
    String tenantId = ((TenantAwarePrincipal) auth.getPrincipal()).getTenantId();
    return documentRepository.findByTenantId(tenantId);
}

// SAFE — Spring Data JPA with @Filter or Row Level Security
@FilterDef(name = "tenantFilter", parameters = @ParamDef(name = "tenantId", type = String.class))
@Filter(name = "tenantFilter", condition = "tenant_id = :tenantId")
@Entity
public class Document { ... }
```

## Token Lifecycle Flaws

### Single-Use Token Not Invalidated

```java
// DANGEROUS — token valid indefinitely after use
public void resetPassword(String token, String newPassword) {
    PasswordResetToken prt = tokenRepository.findByToken(token).orElseThrow();
    userRepository.updatePassword(prt.getUserId(), passwordEncoder.encode(newPassword));
    // Token not deleted — replayable
}

// SAFE
public void resetPassword(String token, String newPassword) {
    PasswordResetToken prt = tokenRepository.findByToken(token).orElseThrow();
    if (prt.getExpiresAt().isBefore(Instant.now())) throw new TokenExpiredException();
    userRepository.updatePassword(prt.getUserId(), passwordEncoder.encode(newPassword));
    tokenRepository.delete(prt);  // invalidate immediately
}
```

### Token Expiry Not Checked

```java
// DANGEROUS — no expiry check
Optional<InviteToken> token = inviteRepository.findByToken(tokenValue);
if (token.isPresent()) {
    createUserAccount(token.get());  // token may be 2 years old
}

// SAFE
token.filter(t -> t.getExpiresAt().isAfter(Instant.now()))
     .orElseThrow(() -> new TokenExpiredException("Invite link expired"));
```

### Tokens Shared Across Contexts

| Risk | Pattern |
|------|---------|
| Password reset token used for email verification | Same token serves two purposes |
| Session token reuse after role change | Old session token still grants old role |
| OAuth token accepted from wrong audience | `aud` claim not verified |

## Excessive Data Exposure

### `findAll()` Without Filtering

```java
// DANGEROUS — returns all entities, may include other tenants/users
@GetMapping("/api/users")
public List<User> getAllUsers() {
    return userRepository.findAll();  // admin-only operation exposed without role check
}

// Also dangerous — full entity with sensitive fields serialized
public class User {
    private String passwordHash;   // never expose
    private String secretToken;    // never expose
    private String internalNotes;  // may be sensitive
    // Jackson serializes all fields by default
}
```

### DTO Projection Pattern

```java
// SAFE — projection interface exposes only needed fields
public interface UserPublicView {
    Long getId();
    String getUsername();
    String getAvatarUrl();
    // No email, no passwordHash, no internalNotes
}

List<UserPublicView> findAllByDepartment(String department);
```

## State Machine Bypass Reference

| State Machine | Common Skip | Risk |
|--------------|-------------|------|
| Order: PENDING → PAID → SHIPPED | PENDING → SHIPPED | Fraudulent shipment without payment |
| Account: UNVERIFIED → VERIFIED | Direct call to verify endpoint | Skip email verification |
| Approval: DRAFT → SUBMITTED → APPROVED | DRAFT → APPROVED | Bypass approval workflow |
| Subscription: TRIAL → ACTIVE | Direct ACTIVE status set | Free subscription |
| Refund: REQUESTED → APPROVED → PROCESSED | REQUESTED → PROCESSED | Bypass manual approval |

## API Abuse False Positives

| Pattern | Reason Not Vulnerable |
|---------|----------------------|
| `findById` followed by `SecurityUtils.assertOwnership(entity, auth)` | Ownership check present |
| `findAll()` with `@PreAuthorize("hasRole('ADMIN')")` | Admin-only access |
| `findByTenantId(SecurityContext.getTenantId())` | Tenant derived from auth context |
| Repository query using `findByIdAndUserId(id, auth.getId())` | Ownership baked into query |
| Token with `@Column(unique=true)` + delete after use | Single-use enforced |
