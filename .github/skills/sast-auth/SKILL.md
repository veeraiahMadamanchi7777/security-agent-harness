# SKILL: sast-auth — Authentication & Authorization Bypass Detection

## References

Load [`references/java-auth.md`](references/java-auth.md) at the start of this skill for Spring Security URL pattern ordering, JWT algorithm confusion attacks, common JWT validation mistakes, session fixation, password hashing benchmarks, method security enablement, CSRF conditions, and CORS misconfiguration table.

## Purpose

Identify authentication bypass, session management flaws, JWT vulnerabilities, privilege escalation, and authorization control gaps in Java applications.

---

## Phase 1: Authentication Configuration Review

### 1.1 — Spring Security Configuration Audit

```bash
# Find all SecurityFilterChain / WebSecurityConfigurerAdapter definitions
grep -rn "SecurityFilterChain\|WebSecurityConfigurerAdapter\|HttpSecurity" --include="*.java" -l

# permitAll() — every occurrence is a potential unauthenticated endpoint
grep -rn "\.permitAll()" --include="*.java" -B5 | grep -B5 "antMatchers\|requestMatchers\|mvcMatchers"

# Disabled CSRF — blanket disable is a finding
grep -rn "csrf()\.disable\|csrf\.disable\|\.csrf(c -> c\.disable())" --include="*.java"

# anyRequest().permitAll() — everything unauthenticated
grep -rn "anyRequest()\.permitAll\b" --include="*.java"

# No final catch-all rule (missing default-deny)
grep -rn "authorizeRequests\|authorizeHttpRequests" --include="*.java" -A30 | grep -v "anyRequest"
# If no anyRequest() at the end, there may be unprotected routes

# Session fixation disabled
grep -rn "sessionFixation()\.none\b\|sessionFixation.*none" --include="*.java"

# Concurrent session control
grep -rn "maximumSessions\|sessionRegistry\|ConcurrentSessionFilter" --include="*.java"
```

### 1.2 — JWT Implementation Audit

```bash
# JWT libraries in use
grep -rn "io\.jsonwebtoken\|com\.auth0\.jwt\|nimbus.*jose\|jjwt\|JWT\.decode\|JWT\.require\|JWT\.create" --include="*.java" -l

# Weak or empty JWT secret
grep -rn "secret\s*=\s*\"\|jwtSecret\s*=\s*\"\|JWT_SECRET\s*=" --include="*.java" --include="*.properties" --include="*.yml" | grep -i "secret\|key"

# Algorithm confusion — alg:none or alg override
grep -rn "\.setAllowedAlgorithms\|Algorithm\.none\|NONE\b.*algorithm\|verifyWith\|signWith" --include="*.java" | grep -v "//\|test\|Test"

# JWT signature not verified — decode without verify
grep -rn "JWT\.decode\b" --include="*.java" | grep -v "verify\|require"
grep -rn "parseClaimsJwt\b" --include="*.java"  # unsigned JWT — no signature check

# JWT expiry not checked
grep -rn "parseClaimsJws\|parseSignedClaims\|getClaims\b" --include="*.java" -A5 | grep -v "getExpiration\|isExpired\|expiry\|exp\b"

# Symmetric secret used in RS256 context
grep -rn "Algorithm\.HMAC\|HS256\|HS384\|HS512" --include="*.java"
# If RS256 is expected but HS256 is used, that's an alg confusion vector
```

### 1.3 — Session Management Audit

```bash
# Session ID in URL (session hijacking via Referer)
grep -rn "encodeURL\|encodeRedirectURL\|jsessionid\|JSESSIONID" --include="*.java" --include="*.xml"

# Insecure cookie flags
grep -rn "setSecure(false)\|setHttpOnly(false)\|setSecure( false\|setHttpOnly( false" --include="*.java"
grep -rn "Cookie\b" --include="*.java" -A5 | grep -A5 "setSecure\|setHttpOnly\|setSameSite"

# Session not invalidated on logout
grep -rn "logout\|signOut\|logOut" --include="*.java" -A10 | grep -v "invalidate\|clearAuthentication\|SecurityContextHolder\.clearContext\|clearContext"

# Session not regenerated after authentication (session fixation)
grep -rn "login\|authenticate\|onAuthenticationSuccess" --include="*.java" -A10 | grep -v "changeSessionId\|invalidate\|migrate\|sessionFixation"

# Long session timeout
grep -rn "session-timeout\|setMaxInactiveInterval\|server.servlet.session.timeout" --include="*.java" --include="*.xml" --include="*.properties" --include="*.yml"
```

---

## Phase 2: Authorization Bypass Patterns

### 2.1 — Missing Method-Level Security

```bash
# Methods that should be protected but aren't
grep -rn "public.*void\|public.*ResponseEntity\|public.*String\|public.*List\|public.*Map\b" \
  --include="*.java" | grep -v "@PreAuthorize\|@PostAuthorize\|@Secured\|@RolesAllowed\|//\|test"

# @EnableMethodSecurity / @EnableGlobalMethodSecurity present?
grep -rn "EnableMethodSecurity\|EnableGlobalMethodSecurity\|securedEnabled\s*=\s*true\|prePostEnabled\s*=\s*true" --include="*.java"
# If absent, @PreAuthorize/@Secured are silently ignored!

# Spring Security method security on non-Spring beans (ignored)
grep -rn "@PreAuthorize" --include="*.java" -B5 | grep -B5 "static\|private\b"
# @PreAuthorize on private/static methods is never enforced by Spring proxy
```

### 2.2 — URL Pattern Bypass Tricks

```bash
# antMatchers vs. requestMatchers ordering issue
grep -rn "antMatchers\|requestMatchers" --include="*.java" -A2 | head -60
# Check: more specific patterns must come BEFORE less specific ones
# More specific (role) must precede less specific (authenticated) which precedes permitAll

# Path traversal bypassing security filter
# Security on /admin/** but not /admin/../admin/ — check filter path normalization
grep -rn "getServletPath\|getRequestURI\|normalize\|canonicalize\|cleanPath" --include="*.java"

# Double encoding bypass — if filter decodes once but matcher doesn't
grep -rn "URLDecoder\.decode\|decodeURIComponent\|UriUtils\.decode" --include="*.java"
```

### 2.3 — HTTP Method Bypass

```bash
# Endpoint handles GET and POST but security only protects POST
grep -rn "@RequestMapping\b" --include="*.java" | grep -v "method\s*=\s*"
# @RequestMapping without method= accepts ALL HTTP methods

# CSRF check bypassed via GET that mutates state
grep -rn "@GetMapping\|@RequestMapping.*GET" --include="*.java" -A20 | grep -A20 "save\|delete\|update\|create\|modify\|remove"
```

### 2.4 — Privilege Escalation Patterns

```bash
# Role check using string comparison — typos bypass
grep -rn "getRole()\s*==\s*\"\|getRole()\.equals(\|getRoles()\.contains(" --include="*.java"

# Admin check via boolean flag that can be mass-assigned
grep -rn "isAdmin\b\|is_admin\b\|setAdmin\|setIsAdmin" --include="*.java" | grep -v "//\|test"

# Principal retrieved from user-supplied data (not security context)
grep -rn "getParameter.*user\|getParameter.*id\|getParameter.*role" --include="*.java" -B2 -A2 | grep -B2 "admin\|isAdmin\|role\|permission"

# Hardcoded bypass — backdoor admin access
grep -rn '"admin"\s*==\s*\|"admin"\.equals\|admin.*backdoor\|if.*admin.*debug' --include="*.java" -i
```

---

## Phase 3: Password & Credential Handling

```bash
# Weak hashing
grep -rn "MessageDigest.*MD5\|MessageDigest.*SHA1\b\|MessageDigest.*SHA-1\b" --include="*.java"

# Plaintext password comparison
grep -rn "\.equals(password)\|password\.equals(\|\.equals(pwd)\|pwd\.equals(" --include="*.java" | grep -v "//\|test\|Test\|encode\|hash\|bcrypt"

# BCrypt / Argon2 / PBKDF2 present?
grep -rn "BCryptPasswordEncoder\|Argon2PasswordEncoder\|Pbkdf2PasswordEncoder\|PasswordEncoder\b" --include="*.java" -l

# Password in logs
grep -rn "log.*password\|logger.*password\|print.*password\|System\.out.*password" --include="*.java" -i

# Password reset without rate limiting
grep -rn "resetPassword\|forgotPassword\|sendResetEmail" --include="*.java" -B5 | grep -B5 "RateLimiter\|rateLimiter\|@RateLimit"
```

---

## Phase 4: Severity Assessment

| Finding | Severity |
|---------|---------|
| `anyRequest().permitAll()` | CRITICAL |
| `csrf().disable()` with state-changing endpoints | HIGH |
| JWT `alg:none` accepted | CRITICAL |
| JWT signature not verified | CRITICAL |
| JWT secret is weak/hardcoded | HIGH |
| `@EnableMethodSecurity` absent (silent ignore) | HIGH |
| Session not invalidated on logout | HIGH |
| MD5/SHA1 for password hashing | HIGH |
| Missing ownership check (IDOR) | HIGH |
| Plaintext password comparison | CRITICAL |
| Role check via mutable flag (mass assignment) | HIGH |
| Session fixation | MEDIUM |
| Missing `Secure`/`HttpOnly` on session cookie | MEDIUM |
| Session ID in URL | MEDIUM |

---

## Finding Format

Follow the canonical format from `copilot-instructions.md`. Example:

```
### [CRITICAL] Auth Bypass — JWT Signature Not Verified (alg:none)

**ID:** AUTH-001
**File:** `src/main/java/com/example/JwtFilter.java:58`
**CWE:** CWE-345 | **OWASP:** A02:2021-Cryptographic Failures
**CVSS (estimated):** 9.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
**Confidence:** High
**Skill:** `sast-auth`

**Taint Path:**
`Authorization: Bearer <token>` → `JwtFilter.doFilterInternal() (JwtFilter.java:52)` → `Jwts.parser().parseClaimsJwt(token) (JwtFilter.java:58)` — signature never verified

**Vulnerable Code:**
```java
// Line 55-62 — parseClaimsJwt parses UNSIGNED JWTs; does NOT verify signature
Claims claims = Jwts.parser()
    .parseClaimsJwt(token)  // ← should be parseClaimsJws() with secret key
    .getBody();
String username = claims.getSubject();
// User is now authenticated with the username in the token, no signature verified
```

**Why Exploitable:**
`parseClaimsJwt` accepts unsigned (alg:none) JWTs without verifying any signature. An attacker crafts a token with arbitrary `sub` and `role` claims, signs with no key, and is authenticated as any user including admins.

**Proof-of-Concept:**
```python
import base64
header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b'=')
payload = base64.urlsafe_b64encode(b'{"sub":"admin","role":"ADMIN"}').rstrip(b'=')
token = header.decode() + '.' + payload.decode() + '.'
# Send: Authorization: Bearer <token>
```

**Remediation:**
```java
Claims claims = Jwts.parserBuilder()
    .setSigningKey(Keys.hmacShaKeyFor(secret.getBytes()))
    .build()
    .parseClaimsJws(token)  // parses SIGNED JWT, throws if invalid
    .getBody();
```

**References:** https://cwe.mitre.org/data/definitions/345.html, CVE-2015-9235, OWASP A02:2021
```

JSONL line (append to `.github/sast-findings.jsonl`):
```json
{"id":"AUTH-001","skill":"sast-auth","cwe":"CWE-345","owasp":"A02:2021-Cryptographic Failures","severity":"Critical","confidence":"High","file":"src/main/java/com/example/JwtFilter.java","line":58,"method":"doFilterInternal","class":"com.example.JwtFilter","evidence":"Claims claims = Jwts.parser()\n    .parseClaimsJwt(token)\n    .getBody();","sink":"Jwts.parser().parseClaimsJwt()","source":"Authorization header token","taint_path":[],"sanitizer_present":false,"sanitizer_detail":"","remediation":"Replace parseClaimsJwt with Jwts.parserBuilder().setSigningKey(...).build().parseClaimsJws(token)","references":["https://cwe.mitre.org/data/definitions/345.html","CVE-2015-9235"],"false_positive_indicators":[],"duplicate_of":null}
```
