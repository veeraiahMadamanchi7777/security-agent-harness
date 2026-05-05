# Java Business Logic Reference — Race Conditions, Numeric Flaws & State Machines

## Race Condition Patterns

### TOCTOU (Time-of-Check to Time-of-Use)

| Pattern | Risk | Notes |
|---------|------|-------|
| Read balance → check → deduct (separate operations) | HIGH | Concurrent threads both pass check |
| Load entity → modify → save (no lock) | HIGH | Lost update without `@Version` |
| Check file existence → open file | MEDIUM | TOCTOU on filesystem |
| Check permissions → perform action (in-memory only) | HIGH | Permission revoked between steps |
| Rate-limit counter read → use → increment (non-atomic) | HIGH | Counter bypass |

### Non-Atomic Operations on Shared State

```java
// DANGEROUS — @Service is a Spring singleton; field shared across all requests
@Service
public class CartService {
    private List<Item> cart = new ArrayList<>();  // mutable singleton field — race condition
    public void addItem(Item item) { cart.add(item); }
}

// DANGEROUS — HashMap in concurrent context
private Map<String, Session> sessions = new HashMap<>();  // not thread-safe
sessions.put(token, session);  // concurrent modification → corrupt state

// SAFE alternatives
private ConcurrentHashMap<String, Session> sessions = new ConcurrentHashMap<>();
// Or use stateless beans — all state in DB or session scope
```

### Transaction Isolation Reference

| Isolation Level | Prevents | Does NOT Prevent |
|----------------|---------|-----------------|
| `READ_UNCOMMITTED` | Nothing | Dirty reads, non-repeatable reads, phantom reads |
| `READ_COMMITTED` (default JPA) | Dirty reads | Non-repeatable reads, phantom reads, TOCTOU |
| `REPEATABLE_READ` | Dirty + non-repeatable reads | Phantom reads |
| `SERIALIZABLE` | All anomalies | Performance |

**Key insight:** Default Spring `@Transactional` uses `READ_COMMITTED` — does not prevent two concurrent transactions from both reading the same balance and both passing a `>= amount` check.

### Locking Patterns

```java
// SAFE — Pessimistic write lock (SELECT FOR UPDATE)
@Repository
public interface AccountRepository extends JpaRepository<Account, Long> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<Account> findById(Long id);
}

// SAFE — Optimistic locking (version field)
@Entity
public class Account {
    @Version
    private Long version;  // JPA throws OptimisticLockingFailureException on conflict
}

// SAFE — Atomic DB update
@Query("UPDATE Account a SET a.balance = a.balance - :amt WHERE a.id = :id AND a.balance >= :amt")
@Modifying
int decrementBalance(@Param("id") Long id, @Param("amt") BigDecimal amt);
// Returns 0 = insufficient funds; 1 = success
```

## Numeric & Arithmetic Flaws

### Integer Overflow

```java
// DANGEROUS — Java int overflows at 2^31-1 = 2,147,483,647
int totalPrice = quantity * unitPrice;  // quantity=100000, unitPrice=100000 → overflows to negative!
if (totalPrice < 0) // might allow "free" order or massive negative balance

// DANGEROUS — long arithmetic that rolls over
long totalBytes = fileCount * fileSize;  // if fileCount=Long.MAX_VALUE/2+1, any fileSize > 1 overflows

// SAFE
Math.multiplyExact(quantity, unitPrice)  // throws ArithmeticException on overflow
BigDecimal for all currency arithmetic
```

### Floating-Point Currency Errors

```java
// DANGEROUS — floating point cannot represent all decimals exactly
double price = 0.1 + 0.2;  // → 0.30000000000000004, not 0.3
if (price == 0.3) { ... }  // never true

// DANGEROUS — rounding errors accumulate in financial calculations
double total = 0.0;
for (Item item : cart) total += item.getPrice();  // cumulative floating-point error

// SAFE
BigDecimal price = new BigDecimal("0.10").add(new BigDecimal("0.20"));  // exactly 0.30
// Always construct from String, not double: new BigDecimal(0.1) is still imprecise
```

### Negative Amount Bypass

```java
// DANGEROUS — unsigned assumption
public void withdraw(BigDecimal amount) {
    if (balance.compareTo(amount) >= 0) {
        balance = balance.subtract(amount);  // amount=-100 → adds 100 to balance
    }
}

// SAFE
if (amount.compareTo(BigDecimal.ZERO) <= 0) throw new IllegalArgumentException("amount must be positive");
if (balance.compareTo(amount) < 0) throw new InsufficientFundsException();
balance = balance.subtract(amount);
```

## State Machine Bypass

### Direct State Manipulation

```java
// DANGEROUS — status can be set directly from request body
@PutMapping("/orders/{id}")
public Order update(@PathVariable Long id, @RequestBody Order order) {
    return orderRepository.save(order);  // can set order.status = "SHIPPED" without validation
}

// SAFE — enforce state transitions
public void advanceOrder(Long orderId, OrderStatus newStatus) {
    Order order = orderRepository.findById(orderId).orElseThrow();
    if (!VALID_TRANSITIONS.get(order.getStatus()).contains(newStatus)) {
        throw new InvalidStateTransitionException(order.getStatus(), newStatus);
    }
    order.setStatus(newStatus);
    orderRepository.save(order);
}

private static final Map<OrderStatus, Set<OrderStatus>> VALID_TRANSITIONS = Map.of(
    OrderStatus.PENDING, Set.of(OrderStatus.CONFIRMED, OrderStatus.CANCELLED),
    OrderStatus.CONFIRMED, Set.of(OrderStatus.SHIPPED, OrderStatus.CANCELLED),
    OrderStatus.SHIPPED, Set.of(OrderStatus.DELIVERED)
);
```

### Workflow Step Skipping

High-risk patterns where users can jump directly to a later step:
- Payment confirmation without completing payment provider callback verification
- Email verification bypass by hitting the "account verified" endpoint directly
- Multi-factor auth bypass by skipping to the post-MFA endpoint if URL is guessable
- Coupon/discount applied after price check but before final charge (timing gap)

## Rate Limit & Quota Bypass

```java
// DANGEROUS — counter check and increment non-atomic
int current = rateLimitStore.get(userId);
if (current < LIMIT) {
    rateLimitStore.put(userId, current + 1);  // race: two threads both read current=0, both pass check
    processRequest();
}

// SAFE — atomic increment with CAS or Redis INCR
// Redis: INCR key; if result > limit, reject and DECR
// Java: AtomicInteger.incrementAndGet(); if > limit, reject
Long result = redisTemplate.opsForValue().increment("rl:" + userId);
if (result > LIMIT) { throw new RateLimitExceededException(); }
```

## Business Logic False Positives

| Pattern | Why Not Vulnerable |
|---------|-------------------|
| `@Transactional(isolation = SERIALIZABLE)` | Full isolation prevents TOCTOU |
| `@Lock(PESSIMISTIC_WRITE)` on repository method | DB-level row lock prevents concurrent modification |
| `@Version` field on entity with optimistic lock retry | Conflict detection prevents lost updates |
| Atomic DB update query with predicate | Single SQL statement — inherently atomic |
| `synchronized` on single-node deployment | Thread-safe, but won't scale to multi-node |
