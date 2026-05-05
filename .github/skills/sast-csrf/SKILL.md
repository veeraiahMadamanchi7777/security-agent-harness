# SKILL: sast-csrf — Cross-Site Request Forgery Detection

## Purpose

Identify CSRF vulnerabilities where state-changing operations lack token-based protection, allowing an attacker to trick an authenticated user's browser into making unauthorized requests on their behalf.

---

## Phase 1: CSRF Protection Configuration Audit

### 1.1 — Spring Security CSRF Configuration

```bash
# Spring Security CSRF disabled — blanket disable is always a finding
grep -rn "csrf()\.disable\|csrf\.disable\|\.csrf(c -> c\.disable())\|\.csrf().disable()" \
  --include="*.java"

# Partial CSRF disable (custom paths excluded)
grep -rn "ignoringAntMatchers\|ignoringRequestMatchers\|CsrfConfigurer" \
  --include="*.java" -A5

# CSRF token repository configuration
grep -rn "CookieCsrfTokenRepository\|HttpSessionCsrfTokenRepository\|csrfTokenRepository" \
  --include="*.java"

# Check if @EnableWebSecurity exists at all (if not, no Spring Security CSRF)
grep -rn "@EnableWebSecurity\|SecurityFilterChain" --include="*.java" -l
```

### 1.2 — CSRF Token Handling

```bash
# Custom CSRF filter implementations
grep -rn "CsrfFilter\|OncePerRequestFilter" --include="*.java" -A20 | grep -A20 "csrf\|token\|xsrf" -i

# CSRF token in response headers (custom implementation)
grep -rn "X-CSRF-TOKEN\|X-XSRF-TOKEN\|XSRF-TOKEN\|csrf-token" --include="*.java" -i

# SameSite cookie attribute (partial CSRF protection)
grep -rn "SameSite\|sameSite\|setSameSite" --include="*.java" --include="*.properties" --include="*.yml"
```

### 1.3 — Global CSRF Status Determination

Determine the app's CSRF posture:
1. If `.csrf().disable()` found AND no custom CSRF filter → **CSRF completely disabled**
2. If Spring Security present but no `csrf()` config → **CSRF enabled by default (Spring Security 5+)**
3. If `CookieCsrfTokenRepository` configured → **CSRF enabled via cookie**
4. If stateless JWT app (`SessionCreationPolicy.STATELESS`) → **CSRF not applicable** (no session = no CSRF vector for browser-based attacks)

```bash
# Check session policy — STATELESS means CSRF less relevant
grep -rn "SessionCreationPolicy\.STATELESS\|STATELESS\b" --include="*.java"
```

---

## Phase 2: State-Changing Endpoint Discovery

### 2.1 — Mutation Endpoints

Find all endpoints that perform state-changing operations:

```bash
# POST endpoints (primary CSRF targets)
grep -rn "@PostMapping\|@RequestMapping.*POST" --include="*.java" -B2 -A10 | \
  grep -A10 "save\|create\|delete\|update\|modify\|change\|reset\|transfer\|payment\|withdraw"

# PUT/PATCH/DELETE endpoints
grep -rn "@PutMapping\|@DeleteMapping\|@PatchMapping" --include="*.java"

# GET endpoints that mutate state — critical finding
grep -rn "@GetMapping\|@RequestMapping.*GET" --include="*.java" -A10 | \
  grep -A10 "save(\|delete(\|update(\|create(\|remove(\|reset("
```

### 2.2 — High-Value State-Changing Operations

These operations are the highest-priority CSRF targets:

```bash
# Password change
grep -rn "changePassword\|updatePassword\|resetPassword\|setPassword" --include="*.java" -B5 | \
  grep -B5 "@PostMapping\|@PutMapping\|@PatchMapping"

# Email/account change
grep -rn "changeEmail\|updateEmail\|updateAccount\|updateProfile" --include="*.java" -B5 | \
  grep -B5 "@PostMapping\|@PutMapping"

# Fund transfer / payment
grep -rn "transfer\|payment\|withdraw\|deposit\|purchase\|order" --include="*.java" -B5 -i | \
  grep -B5 "@PostMapping\|@PutMapping"

# Admin operations
grep -rn "@PostMapping.*admin\|@DeleteMapping.*admin\|@PutMapping.*admin" --include="*.java" -i

# User management
grep -rn "deleteUser\|createUser\|updateRole\|grantRole\|revokeRole" --include="*.java" -B5 | \
  grep -B5 "@PostMapping\|@DeleteMapping\|@PutMapping"
```

---

## Phase 3: CSRF Exemption Validity Check

Not all endpoints require CSRF protection. Verify before flagging:

### 3.1 — REST API Exemptions (Often NOT CSRF-vulnerable)

CSRF is only relevant for browser-based attacks using session cookies. APIs protected by:
- Bearer tokens in `Authorization` header (not cookies) → **Not CSRF-vulnerable** (browsers can't add custom headers cross-origin)
- JWT in `Authorization` header → **Not CSRF-vulnerable**
- API key in custom header → **Not CSRF-vulnerable**

```bash
# Check if endpoints use Bearer/JWT authentication (not session)
grep -rn "Authorization.*Bearer\|BearerTokenExtractor\|JwtAuthenticationFilter\|parseClaimsJws" \
  --include="*.java" -l

# Check auth header extraction (indicates API key/JWT, not session)
grep -rn "getHeader.*Authorization\|getHeader.*X-API-Key\|getHeader.*X-Auth" --include="*.java"
```

If the app uses `SessionCreationPolicy.STATELESS` AND no session cookies, CSRF is not applicable. Reduce all findings to Informational.

### 3.2 — CORS Restriction (Partial Mitigation)

Strict CORS can limit CSRF if only same-origin requests are allowed:

```bash
grep -rn "@CrossOrigin\|addCorsMappings\|allowedOrigins\|CorsConfiguration" --include="*.java" -A5
# If allowedOrigins=* with allowCredentials=true → CORS is misconfigured AND CSRF is dangerous
grep -rn "allowCredentials.*true\|setAllowCredentials(true)" --include="*.java" -B3 | \
  grep -B3 "allowedOrigins.*\*\|setAllowedOrigins.*\*"
```

---

## Phase 4: Severity Assessment

| Finding | Severity |
|---------|---------|
| `csrf().disable()` + session auth + financial/sensitive operations | CRITICAL |
| `csrf().disable()` + session auth + account changes | HIGH |
| `csrf().disable()` + session auth + low-impact state changes | MEDIUM |
| State-changing GET endpoint (even with CSRF enabled) | HIGH |
| `allowedOrigins=*` + `allowCredentials=true` | HIGH |
| CSRF token in URL parameter (not header/body) | MEDIUM |
| Missing `SameSite` cookie attribute | LOW |
| Stateless API with session CSRF disabled | Informational |

---

## Finding Format Example

```
### [HIGH] CSRF — Blanket csrf().disable() with Session Authentication

**File:** `src/main/java/com/example/SecurityConfig.java:34`
**CWE:** CWE-352
**CVSS:** 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)

**Vulnerable Code:**
```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .csrf().disable()  // ← CSRF protection removed for all endpoints
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/api/**").authenticated()
        )
        .sessionManagement(sess -> sess
            .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED));  // ← sessions are used
    return http.build();
}
```

**Attack Scenario:**
If a user visits a malicious page while authenticated, the page can submit a form or make a request to `/api/users/profile` (password change) and the user's session cookie will be automatically included.

**Remediation:**
Remove `.csrf().disable()`. For REST APIs that need to support CSRF tokens:
```java
http.csrf(csrf -> csrf
    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
    .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
);
```
Or if using stateless JWT: set `SessionCreationPolicy.STATELESS` instead of disabling CSRF.

**References:** CWE-352, OWASP A01:2021
```

---

## Self-Contained Check

This skill runs independently. If `.github/sast-context.json` exists, use `file_classifications.csrf_candidates` as the file list (security config files + mutation endpoint files). Otherwise scan all Java files.
