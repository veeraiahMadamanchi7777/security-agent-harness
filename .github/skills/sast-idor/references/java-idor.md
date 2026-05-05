# Java IDOR Reference — Patterns & Defenses

## Common IDOR Entry Points

| Pattern | Risk |
|---------|------|
| `@PathVariable Long id` → `repo.findById(id)` | High — no ownership check |
| `@PathVariable String uuid` → `repo.findByUuid(uuid)` | Medium — UUIDs are harder to guess but still IDOR |
| `@RequestParam Long userId` → loads other user's data | High |
| `@RequestBody` with `id` field → used to load resource | High |
| File download by filename → `new File(base, filename)` | High (also path traversal) |

## Ownership Check Patterns

### JPA Repository with Owner Filter (Best)
```java
// Repository method scoped to owner — safe
Optional<Account> findByIdAndUserId(Long id, Long userId);
```

### @PreAuthorize with SpEL (Good)
```java
@PreAuthorize("#order.userId == authentication.principal.id")
public Order getOrder(Order order) { ... }

@PreAuthorize("@orderSecurity.isOwner(#orderId, authentication)")
public Order getOrder(@PathVariable Long orderId) { ... }
```

### Manual Check in Service (Acceptable)
```java
Account account = accountRepo.findById(id).orElseThrow();
if (!account.getUserId().equals(currentUser.getId())) {
    throw new AccessDeniedException("Not your account");
}
```

### PostAuthorize (Post-Fetch Check)
```java
@PostAuthorize("returnObject.userId == authentication.principal.id")
public Account getAccount(Long id) {
    return accountRepo.findById(id).orElseThrow();
}
// Note: still fetches from DB — information not leaked, but DB load happens
```

## Mass Assignment Risk Fields

If `@RequestBody` binds to an entity or DTO that contains these fields, and those fields are settable, mass assignment IDOR exists:

| Field Name | Risk |
|-----------|------|
| `userId`, `user_id` | User's data scoped to wrong account |
| `accountId`, `tenantId`, `orgId` | Multi-tenancy isolation bypass |
| `ownerId`, `createdBy` | Resource ownership override |
| `role`, `roles`, `permissions` | Privilege escalation |
| `isAdmin`, `admin`, `is_admin` | Admin flag injection |
| `verified`, `approved`, `enabled` | Account status manipulation |
| `balance`, `credits`, `score` | Financial manipulation |
| `price`, `discountPercent` | Pricing manipulation |

## Secure DTO Pattern (Defense)

```java
// WRONG: Bind directly to entity (mass assignment risk)
@PostMapping("/orders")
public Order createOrder(@RequestBody Order order) { ... }  // Order has userId, status, etc.

// RIGHT: Use DTO with only user-settable fields
public record CreateOrderRequest(Long productId, int quantity, String shippingAddress) {}

@PostMapping("/orders")
public Order createOrder(@RequestBody @Valid CreateOrderRequest req, Authentication auth) {
    Order order = new Order();
    order.setProductId(req.productId());
    order.setQuantity(req.quantity());
    order.setUserId(auth.getPrincipal().getId());  // set from auth, never from request
    order.setStatus(OrderStatus.PENDING);          // set server-side, never from request
    return orderRepo.save(order);
}
```

## Multi-Tenancy IDOR

In multi-tenant systems, horizontally-isolated data often fails to check tenantId:

```java
// Dangerous: only checks by resource ID
List<Report> reports = reportRepo.findByProjectId(projectId);

// Safe: scoped to current tenant
Long tenantId = SecurityUtils.getCurrentTenantId();
List<Report> reports = reportRepo.findByProjectIdAndTenantId(projectId, tenantId);
```

## Indirect Object Reference (More Secure Alternative)

Map user-facing IDs to internal IDs in session:
```java
// User sees: /orders/abc-123
// Server maps: "abc-123" → internalId=456 scoped to this user's session
// No IDOR possible because mapping is per-user
```
