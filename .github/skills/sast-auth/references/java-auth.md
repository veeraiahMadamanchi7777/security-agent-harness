# Java Authentication & Authorization Reference

## Spring Security URL Pattern Ordering Rules

Rules are evaluated **first-match**. More specific patterns must come first.

```java
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/admin/**").hasRole("ADMIN")    // specific first
    .requestMatchers("/api/**").authenticated()         // less specific next
    .requestMatchers("/public/**").permitAll()          // open paths
    .anyRequest().authenticated()                       // default-deny catch-all — REQUIRED
);
```

Missing `.anyRequest().authenticated()` means unmatched paths are **unauthenticated**.

## JWT Algorithm Confusion Attacks

| Attack | Description |
|--------|------------|
| `alg:none` | Remove signature, claim any identity |
| RS256 → HS256 | Use RS256 public key as HS256 secret to forge tokens |
| Key confusion | Present public key as HMAC secret |

### Vulnerable JJWT Code
```java
// VULNERABLE: parseClaimsJwt parses unsigned/unsecured JWTs
Jwts.parser().parseClaimsJwt(token)

// VULNERABLE: setSigningKey with weak secret
Jwts.parser().setSigningKey("password").parseClaimsJws(token)

// SAFE: parserBuilder with strong key material
Jwts.parserBuilder()
    .setSigningKey(Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret)))
    .build()
    .parseClaimsJws(token)
    .getBody()
```

## Common JWT Validation Mistakes

| Mistake | Impact |
|---------|--------|
| Not checking `exp` claim | Expired tokens accepted forever |
| Not checking `iss` (issuer) claim | Tokens from other systems accepted |
| Not checking `aud` (audience) claim | Tokens for other services accepted |
| Using `==` instead of `equals()` for claim comparison | String interning bypasses |
| Catching `JwtException` broadly and returning null user | Auth treated as anonymous |

## Session Fixation Attack

```
1. Attacker visits /login → gets JSESSIONID=attacker_known_id
2. Attacker tricks victim into using same session: link with ;jsessionid=attacker_known_id
3. Victim logs in → if session ID not rotated, attacker's known ID is now authenticated
```

**Fix:** `sessionFixation().migrateSession()` (default in Spring Security) or `.newSession()`

## Password Hashing Benchmark (2024)

| Algorithm | Recommended | Iterations/Cost |
|-----------|------------|-----------------|
| Argon2id | Yes (best) | memory=64MB, iterations=3, parallelism=4 |
| bcrypt | Yes | cost factor ≥ 12 |
| scrypt | Yes | N=2^17, r=8, p=1 |
| PBKDF2-HMAC-SHA512 | Acceptable | ≥ 600,000 |
| PBKDF2-HMAC-SHA256 | Acceptable | ≥ 600,000 |
| SHA-256 (even salted) | No | Breakable with GPU |
| MD5 | No | Trivially breakable |
| bcrypt cost < 10 | Not recommended | Too fast |

## Spring Security Method Security

`@PreAuthorize`, `@PostAuthorize`, `@Secured` are **silently ignored** unless enabled:

```java
// Spring Boot 3.x / Spring Security 6.x
@Configuration
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class MethodSecurityConfig {}

// Spring Boot 2.x / Spring Security 5.x
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class MethodSecurityConfig {}
```

Also: `@PreAuthorize` only works on **Spring-managed beans** accessed through the proxy. Direct `new` instantiation bypasses the proxy.

## CSRF Protection Notes

| Endpoint Type | CSRF Needed |
|--------------|-------------|
| Cookie-based session | Yes |
| Stateless JWT in Authorization header | No |
| JWT in cookie | Yes |
| API consumed by mobile (no browser) | No (but SameSite Strict on cookies instead) |

Disabling CSRF for a REST API is acceptable if **all** of these are true:
1. Authentication is via `Authorization: Bearer` header only
2. No cookies are used for auth
3. `Access-Control-Allow-Credentials: false` in CORS

## CORS Misconfiguration

| Config | Risk |
|--------|------|
| `allowedOrigins("*")` with `allowCredentials(true)` | Config error — rejected by browsers |
| `allowedOrigins("https://trusted.com")` + `allowCredentials(true)` | Safe if trust is correct |
| `allowedOrigins("*")` without credentials | Open CORS — data accessible from any origin (check if sensitive) |
| Reflecting Origin header without validation | Full CORS bypass — treat as CRITICAL |

```java
// VULNERABLE: reflects Origin back without check
configuration.setAllowedOriginPatterns(List.of("*"));
configuration.setAllowCredentials(true);
// ^ browsers will send cookies to any origin that POSTs to this endpoint
```
