# Java CSRF Reference — Spring Security Configuration & Bypass Conditions

## Spring Security CSRF Configuration States

| Config | Risk | Notes |
|--------|------|-------|
| `.csrf().disable()` (Spring Security 5) | HIGH | Disables globally for all endpoints |
| `.csrf(AbstractHttpConfigurer::disable)` (Spring Security 6) | HIGH | Same as above, new API |
| No CSRF config at all | HIGH | Default is enabled, but verify |
| `csrf().ignoringRequestMatchers("/api/**")` | MEDIUM | Selectively disabled for API paths |
| `CookieCsrfTokenRepository` configured | SAFE | Double-submit cookie pattern |
| `HttpSessionCsrfTokenRepository` configured | SAFE | Server-side token |
| `CsrfTokenRequestAttributeHandler` | SAFE | Spring Security 6 best practice |

## CSRF Token Handling in Spring

```java
// Spring Security 5 — session-based CSRF token
http.csrf(csrf -> csrf
    .csrfTokenRepository(HttpSessionCsrfTokenRepository())
);
// Client reads _csrf attribute from model; sends as X-CSRF-TOKEN header or _csrf parameter

// Spring Security 6 — cookie-based (SPA-friendly)
http.csrf(csrf -> csrf
    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
    .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
);
// Client reads XSRF-TOKEN cookie; sends as X-XSRF-TOKEN header

// Thymeleaf auto-injection (only works with session token)
// <form method="post" th:action="@{/submit}">
//   <!-- Thymeleaf injects <input type="hidden" name="_csrf" value="..."> automatically -->
// </form>
```

## When CSRF Protection Is Not Required

CSRF is only a browser threat — non-browser clients (mobile apps, curl) are not vulnerable.

| Condition | CSRF Needed | Why |
|-----------|------------|-----|
| Cookie session authentication | YES | Browser auto-sends cookies |
| JWT in `Authorization: Bearer` header | NO | Headers not auto-sent by browser |
| JWT stored in cookie | YES | Cookie is auto-sent |
| API key in `X-Api-Key` header | NO | Custom headers require CORS preflight |
| `SameSite=Strict` cookies | NO (reduces risk) | Browser won't send on cross-site requests |
| `SameSite=Lax` cookies | PARTIAL | GET safe; POST from links not safe |
| `SameSite=None` cookies | YES | Cross-site sends require CSRF token |

## SameSite Cookie Configuration in Spring

```java
// Spring Boot application.properties
server.servlet.session.cookie.same-site=strict
server.servlet.session.cookie.http-only=true
server.servlet.session.cookie.secure=true

// Or programmatically
@Bean
public TomcatContextCustomizer sameSiteCookiesConfig() {
    return context -> {
        Rfc6265CookieProcessor cookieProcessor = new Rfc6265CookieProcessor();
        cookieProcessor.setSameSiteCookies(SameSiteCookies.STRICT.getValue());
        context.setCookieProcessor(cookieProcessor);
    };
}
```

## State-Changing Endpoints to Audit

Flag all endpoints that perform mutations and accept session-cookie auth:

| HTTP Method | Endpoint Pattern | Risk if CSRF Missing |
|-------------|-----------------|---------------------|
| POST | `/api/users/**` | Account creation, profile change |
| PUT/PATCH | `/api/**` | Data modification |
| DELETE | `/api/**` | Resource deletion |
| POST | `/api/auth/password` | Password change |
| POST | `/api/admin/**` | Admin actions |
| POST | `/api/payments/**` | Financial transactions |
| POST | `/logout` | Anti-logout CSRF |

## Common Legitimate Exemptions

```java
// REST APIs using stateless JWT — safe to disable CSRF
http
    .csrf(AbstractHttpConfigurer::disable)
    .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
    .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
// ONLY exempt if auth is purely via Authorization header, never cookies

// Webhook receivers — safe to exempt specific paths
http.csrf(csrf -> csrf
    .ignoringRequestMatchers("/webhooks/**")  // GitHub, Stripe webhooks use their own signature
);
// Verify the webhook endpoint validates the provider's HMAC signature (e.g., X-Hub-Signature-256)
```

## Attack Scenario Templates

### Form-Based CSRF
```html
<!-- Attacker's page — auto-submitting form -->
<form id="csrf" method="POST" action="https://target.com/api/users/password">
  <input name="newPassword" value="hacked">
</form>
<script>document.getElementById("csrf").submit();</script>
```

### JSON CSRF (requires content-type bypass)
```html
<!-- Fetch with credentials — works if CORS allows credentials from attacker origin -->
<script>
fetch("https://target.com/api/profile", {
    method: "POST",
    credentials: "include",
    headers: {"Content-Type": "text/plain"},  // text/plain avoids preflight in some configs
    body: '{"email":"attacker@evil.com"}'
});
</script>
```

### Anti-CSRF Token Strength Check

Weak CSRF tokens are guessable:
- Tokens based on timestamp or sequential ID: LOW entropy
- Tokens based on `java.util.Random`: predictable
- Safe: `SecureRandom` with at least 128 bits → hex or base64 encoding

```java
// SAFE — generate CSRF token
byte[] tokenBytes = new byte[32];
new SecureRandom().nextBytes(tokenBytes);
String csrfToken = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
```
