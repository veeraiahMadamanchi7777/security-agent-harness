---
name: sast-business-logic
description: Review Java applications for broken invariants, workflow bypasses, race conditions, quota abuse, and state-machine flaws.
---

# SKILL: sast-business-logic — Business Logic & Race Condition Detection

## References

Load [`references/java-business-logic.md`](references/java-business-logic.md) at the start of this skill for TOCTOU patterns, transaction isolation levels, locking recipes, numeric flaw examples, state machine bypass patterns, and false positive indicators.

## Purpose

Identify vulnerabilities that arise from incorrect implementation of business rules, state machine invariants, concurrency issues, numeric edge cases, and workflow bypass opportunities. These are not traditional "injection" bugs — they require understanding the intended business behavior.

---

## Phase 1: Race Condition Detection

### 1.1 — Check-Then-Act Patterns (TOCTOU)

```bash
# Existence check followed by operation (classic TOCTOU)
grep -rn "\.exists()\b" --include="*.java" -A5 | grep -A5 "createNewFile\|mkdir\|write\|delete\|rename"

# Balance / inventory check followed by deduction
grep -rn "getBalance\b\|getQuantity\b\|getCredits\b\|getStock\b" --include="*.java" -A10 | \
  grep -A10 "deduct\|subtract\|decrement\|update\|save\b\|withdraw\b" | \
  grep -v "synchronized\|@Lock\|@Transactional.*SERIALIZABLE\|@Transactional.*REPEATABLE_READ\|pessimistic\|PessimisticLock\|OptimisticLock\|@Version\b"

# findById followed by mutating save — no locking
grep -rn "\.findById(\b" --include="*.java" -A10 | grep -A10 "\.save(\|\.saveAndFlush(\|\.update("
# Check: is there a @Version field, pessimistic lock, or SERIALIZABLE transaction?
```

### 1.2 — Non-Atomic Operations in Shared State

```bash
# Singleton beans with mutable instance fields (Spring beans are singletons by default)
grep -rn "@Service\|@Component\|@Repository\b" --include="*.java" -A30 | grep -A30 "private.*[^static].*=\s*[^null]" | grep -v "final\b\|static\b"

# Static mutable counters/maps without synchronization
grep -rn "private static.*Map\|private static.*List\|private static.*int\|private static.*long\|private static.*Counter" --include="*.java" | grep -v "final\b\|ConcurrentHashMap\|CopyOnWriteArrayList\|AtomicInteger\|AtomicLong"

# HashMap used in concurrent context
grep -rn "new HashMap\b\|new ArrayList\b" --include="*.java" -B5 | grep -B5 "@Service\|@Component\|static\b" | grep -v "//\|test"

# Double-checked locking without volatile (broken in old Java)
grep -rn "if.*==.*null\b" --include="*.java" -A5 | grep -A5 "synchronized\b" -A5 | grep -A5 "if.*==.*null\b"
```

### 1.3 — Transaction Isolation Issues

```bash
# @Transactional with READ_UNCOMMITTED (reads dirty data)
grep -rn "@Transactional.*READ_UNCOMMITTED\|Isolation\.READ_UNCOMMITTED" --include="*.java"

# @Transactional with READ_COMMITTED on financial operations (still allows non-repeatable reads)
grep -rn "@Transactional" --include="*.java" -A5 | grep -A5 "isolation.*READ_COMMITTED\|Isolation\.READ_COMMITTED" | \
  grep "balance\|payment\|order\|credit\|debit\|stock\|inventory\|fund\|transfer" -i

# Missing @Transactional on multi-step operations
grep -rn "save\b\|saveAll\b\|delete\b\|update\b" --include="*.java" -B5 | grep -B5 "@Transactional" | grep -v "@Transactional"

# Optimistic locking without retry (OLE not handled)
grep -rn "@Version\b" --include="*.java" -l
# Check calling code: does it catch OptimisticLockingFailureException and retry?
grep -rn "OptimisticLockingFailureException\|ObjectOptimisticLockingFailureException\|StaleObjectStateException" --include="*.java"
```

---

## Phase 2: Numeric & Arithmetic Logic Flaws

### 2.1 — Integer Overflow / Underflow

```bash
# Casting long/double to int without range check
grep -rn "(int)\s*[a-zA-Z]" --include="*.java" | grep -v "//\|length\|size()\|hashCode\|index"

# Integer arithmetic on financial amounts (should use BigDecimal)
grep -rn "double.*price\|double.*amount\|double.*total\|float.*price\|float.*amount" --include="*.java" | grep -v "//\|test"
grep -rn "int.*balance\|int.*amount\|int.*price" --include="*.java" | grep -v "//\|test\|count\|index\|size"

# Negative number bypass
grep -rn "quantity\b\|amount\b\|count\b\|price\b" --include="*.java" -B3 | grep -B3 "getParameter\|@RequestParam\|@RequestBody" | \
  grep -v "if.*<=.*0\|if.*<.*1\|validate\|positive\|Positive\|Min(0\|Min(1"
```

### 2.2 — Floating Point Comparison Issues

```bash
# Exact float/double equality comparison
grep -rn "==.*\.\|\..*==\b" --include="*.java" | grep "double\|float\|Double\|Float" | grep -v "//\|test\|null\b\|NaN\|Infinity"

# BigDecimal compared with == instead of compareTo
grep -rn "BigDecimal\b" --include="*.java" -A5 | grep "==.*BigDecimal\|BigDecimal.*==" | grep -v "//\|null\b"
```

### 2.3 — Time-Based Logic

```bash
# System.currentTimeMillis vs. Instant.now() for expiry checks
grep -rn "System\.currentTimeMillis()" --include="*.java" | grep "expire\|expiry\|valid\|timeout\|deadline" -i

# Date comparison that doesn't account for timezone
grep -rn "new Date()\|Calendar\.getInstance()" --include="*.java" | grep -v "//\|test"

# Token expiry with clock skew ignored
grep -rn "getExpiration\b\|isExpired\b\|expiredAt\b\|expiresAt\b" --include="*.java" -B5 | grep -B5 "before\b\|after\b\|compareTo\b"
```

---

## Phase 3: Workflow / State Machine Bypass

### 3.1 — Order Status / State Transition Bypass

```bash
# State machine without enforced transitions
grep -rn "setStatus\b\|setState\b\|setOrderStatus\b\|setPaymentStatus\b" --include="*.java" | grep -v "//\|test\|Test"
# Check: is there a whitelist of valid from→to transitions?

# Skipping workflow steps
grep -rn "step\b\|stage\b\|phase\b\|workflow\b" --include="*.java" -B5 | grep -B5 "@PathVariable\|@RequestParam\|@RequestBody"

# Status set directly from user input (mass assignment)
grep -rn "@RequestBody\b\|@ModelAttribute\b" --include="*.java" -A20 | grep -A20 "setStatus\|setState\|setRole\|setApproved\|setVerified\|setAdmin"
```

### 3.2 — Payment / Financial Logic

```bash
# Negative payment amount (negative transfer to steal credits)
grep -rn "transfer\b\|withdraw\b\|charge\b\|debit\b\|payment\b" --include="*.java" -B5 | \
  grep -B5 "@RequestParam\|@RequestBody\|@PathVariable" | \
  grep -v "if.*<=.*0\|if.*<.*0\|positive\|Positive\|Min(0\|validate"

# Currency rounding exploitation (truncation vs. rounding)
grep -rn "setScale\b\|\.divide(\|BigDecimal.*ROUND\|RoundingMode\b" --include="*.java"

# Free item through negative quantity
grep -rn "quantity\b\|qty\b\|count\b" --include="*.java" | grep "setQuantity\|updateQty\|addToCart\|addItem" | grep -v "if.*<=.*0\|positive\|Min"

# Refund > original amount
grep -rn "refund\b\|reversal\b\|chargeback\b" --include="*.java" -B5 | grep -v "if.*amount.*>\|validate\|originalAmount"
```

### 3.3 — Limit / Rate / Quota Bypass

```bash
# Rate limiting that can be bypassed
grep -rn "rateLimit\|rateLimiter\|RateLimiter\|@RateLimit\b" --include="*.java" -B10 | \
  grep -B10 "X-Forwarded-For\|getRemoteAddr\|getHeader.*IP\|clientIp\b" -i
# If IP-based rate limiting reads X-Forwarded-For without validation → bypass via spoofed header

# Coupon / promo code reuse
grep -rn "coupon\b\|promoCode\b\|voucherCode\b\|discountCode\b" --include="*.java" -A10 | \
  grep -A10 "redeem\|apply\|use\b\|claim\b" | \
  grep -v "isUsed\|wasUsed\|usedAt\|redeemed\|once\|unique\|idempotent"

# OTP / magic link reuse
grep -rn "otp\b\|oneTimePassword\|magicLink\|verificationToken\b" --include="*.java" -A10 | \
  grep -A10 "findByToken\|verif\|confirm\b" | \
  grep -v "delete\|expire\|invalidate\|markUsed\|setUsed"
```

---

## Phase 4: Data Integrity Issues

### 4.1 — Mass Assignment

```bash
# @ModelAttribute or @RequestBody binding directly to JPA entity (not DTO)
grep -rn "@Entity\b" --include="*.java" -l | xargs grep -l "@RequestBody\|@ModelAttribute" 2>/dev/null

# Sensitive fields that could be mass-assigned
grep -rn "@Entity\b" --include="*.java" -A50 | grep "role\b\|isAdmin\b\|is_admin\b\|verified\b\|balance\b\|credits\b\|accountType\b" | grep -v "//\|Column.*insertable.*false\|@JsonIgnore\|@JsonProperty.*access"
```

### 4.2 — Insecure Direct Reference in Business Operations

```bash
# Price/amount looked up by user-supplied ID and not verified
grep -rn "getPrice\b\|getAmount\b\|findPrice\b" --include="*.java" -B5 | grep -B5 "@PathVariable\|@RequestParam\|@RequestBody"
# Check: is the price verified server-side or does client send the price?

# Discount applied server-side but discount percentage comes from client
grep -rn "discount\b\|discountPercent\b\|discountAmount\b" --include="*.java" | grep "getParameter\|@RequestParam\|@RequestBody"
```

---

## Phase 5: Severity Assessment

| Issue | Severity |
|-------|---------|
| Race condition on payment/balance with no isolation | CRITICAL |
| Negative quantity/amount bypass | HIGH |
| State machine transition not enforced | HIGH |
| OTP/token can be reused | HIGH |
| Rate limit bypassable via X-Forwarded-For | MEDIUM |
| Coupon code reuse | MEDIUM |
| Integer overflow on financial amount | HIGH |
| Floating point equality on money | MEDIUM |
| Mass assignment of role/admin flag | HIGH |
| Optimistic lock without retry (data loss) | MEDIUM |
| `double`/`float` for currency | MEDIUM |
| Missing transaction on multi-step operation | HIGH |

---

## Finding Format

Follow the canonical format from `copilot-instructions.md`. Example:

```
### [HIGH] Race Condition — Balance Not Atomically Updated (Double-Spend)

**ID:** BIZ-001
**File:** `src/main/java/com/example/PaymentService.java:55`
**CWE:** CWE-362 | **OWASP:** A04:2021-Insecure Design
**CVSS (estimated):** 8.1 (AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N)
**Confidence:** High
**Skill:** `sast-business-logic`

**Taint Path:**
`POST /api/withdraw {"accountId":X,"amount":Y}` → `PaymentService.withdraw(accountId, amount) (PaymentService.java:50)` → `accountRepository.findById(accountId) (PaymentService.java:52)` [check] → `accountRepository.save(account) (PaymentService.java:57)` [update] — non-atomic TOCTOU window

**Vulnerable Code:**
```java
@Transactional  // READ_COMMITTED (default) — does not prevent concurrent reads
public void withdraw(Long accountId, BigDecimal amount) {
    Account account = accountRepository.findById(accountId).orElseThrow();
    if (account.getBalance().compareTo(amount) < 0) {
        throw new InsufficientFundsException();
    }
    // Another thread can pass the check and enter here concurrently
    account.setBalance(account.getBalance().subtract(amount));
    accountRepository.save(account);
}
```

**Why Exploitable:**
`@Transactional` with `READ_COMMITTED` (the default) does not prevent two concurrent transactions from both reading the same balance, both passing the check, and both committing a deduction. An attacker sends identical withdrawal requests in rapid succession, causing a double-spend without sufficient funds.

**Proof-of-Concept:**
```bash
# Send two concurrent withdrawal requests exceeding balance
curl -X POST /api/withdraw -d '{"accountId":1,"amount":500}' &
curl -X POST /api/withdraw -d '{"accountId":1,"amount":500}' &
# Both may succeed when balance is only 600
```

**Remediation:**
```java
// Option 1: Pessimistic locking in repository
@Lock(LockModeType.PESSIMISTIC_WRITE)
Optional<Account> findById(Long id);

// Option 2: Atomic DB update (preferred)
@Query("UPDATE Account a SET a.balance = a.balance - :amount WHERE a.id = :id AND a.balance >= :amount")
int decrementBalance(@Param("id") Long id, @Param("amount") BigDecimal amount);
// Returns 0 if insufficient funds
```

**References:** https://cwe.mitre.org/data/definitions/362.html, OWASP A04:2021
```

JSONL line (append to `.github/sast-findings.jsonl`):
```json
{"id":"BIZ-001","skill":"sast-business-logic","cwe":"CWE-362","owasp":"A04:2021-Insecure Design","severity":"High","confidence":"High","file":"src/main/java/com/example/PaymentService.java","line":55,"method":"withdraw","class":"com.example.PaymentService","evidence":"Account account = accountRepository.findById(accountId).orElseThrow();\nif (account.getBalance().compareTo(amount) < 0) { throw ...; }\naccount.setBalance(account.getBalance().subtract(amount));\naccountRepository.save(account);","sink":"accountRepository.save()","source":"POST /api/withdraw amount parameter","taint_path":[],"sanitizer_present":false,"sanitizer_detail":"","remediation":"Use PESSIMISTIC_WRITE lock on findById or atomic UPDATE query with balance >= amount predicate","references":["https://cwe.mitre.org/data/definitions/362.html"],"false_positive_indicators":[],"duplicate_of":null}
```
