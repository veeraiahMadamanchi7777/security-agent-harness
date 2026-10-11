---
name: sast-oauth
description: Review OAuth2 and OpenID Connect flows for redirect URI, state, PKCE, token validation, and account-linking flaws.
---

# SKILL: sast-oauth — OAuth and OIDC Flow Review

## Purpose

Find OAuth/OIDC implementation flaws that lead to account takeover, token leakage, login CSRF, authorization code interception, or confused-deputy bugs.

Load [`references/java-oauth.md`](references/java-oauth.md).

---

## Phase 1 — Identify OAuth/OIDC Surface

```bash
# Client registrations and provider config
rg -n "ClientRegistration|OAuth2AuthorizedClient|authorizationUri|tokenUri|issuer-uri|jwk-set-uri|spring.security.oauth2" \
   --glob "*.java" --glob "*.yml" --glob "*.properties"

# Authorization request construction
rg -n "state|nonce|code_verifier|code_challenge|PKCE|redirectUri|redirect_uri|response_type|scope" \
   --glob "*.java" --glob "*.yml"

# Callback and code exchange handling
rg -n "authorizationCode|getCode|getState|getNonce|OAuth2LoginAuthenticationFilter|OAuth2AuthorizationCodeGrantFilter\|successHandler\|failureHandler" \
   --glob "*.java"

# JWT and OIDC token validation
rg -n "JwtDecoder|NimbusJwtDecoder|JwtParser|parseClaimsJws|parseClaimsJwt|JWTClaimsSet|verifyWith\|withIssuer\|withAudience\|withSubject\|acceptLeeway" \
   --glob "*.java"

# Account linking and identity assertions
rg -n "findByEmail\|linkAccount\|getEmail\|getAttribute.*email\|getPrincipal\|getName\|getSubject\|merge.*account\|provision" \
   --glob "*.java"

# Token storage
rg -n "HttpSession.*token\|cookie.*token\|localStorage\|sessionStorage\|OAuth2AuthorizedClientRepository\|InMemoryOAuth2AuthorizedClientService" \
   --glob "*.java"
```

---

## Phase 2 — Authorization Request Flaws

### 2a. Missing or non-random `state` (Login CSRF)

**Vulnerable pattern:**
```java
// state omitted from authorization request builder
OAuth2AuthorizationRequest request = OAuth2AuthorizationRequest
    .authorizationCode()
    .clientId(clientId)
    .authorizationUri(authUri)
    .redirectUri(callbackUri)
    .scopes(scopes)
    // no .state() — CSRF possible
    .build();
```

**Safe pattern:** Let Spring Security generate state automatically via `DefaultOAuth2AuthorizationRequestResolver` and verify it in the callback handler. Never omit or hardcode state.

**JSONL finding:**
```json
{"id":"OAUTH-001","skill":"sast-oauth","cwe":"CWE-352","owasp":"A01:2021-Broken Access Control","severity":"High","confidence":"High","file":"src/main/java/com/example/oauth/CustomAuthRequestBuilder.java","line":28,"method":"buildRequest","class":"com.example.oauth.CustomAuthRequestBuilder","evidence":"    .build(); // state not set","sink":"OAuth2AuthorizationRequest.build()","source":"custom authorization request builder","taint_path":[],"sanitizer_present":false,"sanitizer_detail":"","remediation":"Remove custom request builder and use DefaultOAuth2AuthorizationRequestResolver which generates a cryptographically random state and verifies it automatically.","references":["CWE-352","https://www.rfc-editor.org/rfc/rfc6749#section-10.12"],"false_positive_indicators":["Check if a custom state generator is wired elsewhere in the filter chain"],"status":"candidate"}
```

### 2b. Redirect URI derived from user-controlled input

**Vulnerable pattern:**
```java
@GetMapping("/oauth/login")
public RedirectView startLogin(@RequestParam String returnUrl) {
    String callback = baseUrl + "/oauth/callback?next=" + returnUrl;
    // callback URI contains attacker-controlled returnUrl
    return new RedirectView(buildAuthUri(clientId, callback));
}
```

**Safe pattern:** Store the post-login destination in the session keyed to the state parameter. Never embed it in the redirect URI — the authorization server may not validate the suffix.

**JSONL finding:**
```json
{"id":"OAUTH-002","skill":"sast-oauth","cwe":"CWE-601","owasp":"A01:2021-Broken Access Control","severity":"High","confidence":"High","file":"src/main/java/com/example/oauth/LoginController.java","line":22,"method":"startLogin","class":"com.example.oauth.LoginController","evidence":"    String callback = baseUrl + \"/oauth/callback?next=\" + returnUrl;","sink":"buildAuthUri(clientId, callback)","source":"@RequestParam String returnUrl","taint_path":[],"sanitizer_present":false,"sanitizer_detail":"","remediation":"Store destination in session: session.setAttribute(\"post_login_redirect\", returnUrl); validate it against an allowlist of internal paths before redirect.","references":["CWE-601","https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control"],"false_positive_indicators":["Verify whether the authorization server enforces exact redirect URI matching"],"status":"candidate"}
```

### 2c. Missing PKCE for public clients

**Vulnerable pattern:**
```java
ClientRegistration reg = ClientRegistration.withRegistrationId("myapp")
    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
    .clientId("public-client-id")
    .clientSecret("")   // public client — no secret
    // no .additionalAuthorizationRequestParameters(Map.of("code_challenge_method","S256"))
    .build();
```

Authorization codes can be intercepted via referrer headers, browser history, or open redirects without PKCE.

**Safe pattern:** Enable PKCE via `DefaultOAuth2AuthorizationRequestResolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce())`.

---

## Phase 3 — Callback and Token Validation Flaws

### 3a. ID token accepted without signature verification

**Vulnerable pattern — JJWT:**
```java
// parseClaimsJwt accepts unsigned (alg:none) tokens
Claims claims = Jwts.parser()
    .setSigningKey(key)
    .parseClaimsJwt(idToken);   // ← should be parseClaimsJws
```

`parseClaimsJwt` does **not** verify a signature. An attacker can craft `{"alg":"none"}` tokens that pass this call. Always use `parseClaimsJws`.

**JSONL finding:**
```json
{"id":"OAUTH-003","skill":"sast-oauth","cwe":"CWE-347","owasp":"A02:2021-Cryptographic Failures","severity":"Critical","confidence":"High","file":"src/main/java/com/example/auth/TokenValidator.java","line":44,"method":"validateIdToken","class":"com.example.auth.TokenValidator","evidence":"    Claims claims = Jwts.parser().setSigningKey(key).parseClaimsJwt(idToken);","sink":"Jwts.parser().parseClaimsJwt()","source":"HTTP parameter idToken","taint_path":[],"sanitizer_present":false,"sanitizer_detail":"","remediation":"Replace parseClaimsJwt with parseClaimsJws. For RS256/ES256 public-key validation use NimbusJwtDecoder.withJwkSetUri(jwksUri).build() and call decoder.decode(idToken).","references":["CWE-347","https://nvd.nist.gov/vuln/detail/CVE-2022-21449"],"false_positive_indicators":["Confirm whether another layer (API gateway) has already verified the signature"],"status":"candidate"}
```

### 3b. Missing issuer, audience, or expiration validation

**Vulnerable pattern — Nimbus:**
```java
JWTClaimsSet claims = SignedJWT.parse(idToken).getJWTClaimsSet();
String sub = claims.getSubject();   // no issuer/audience/expiry check
```

**Safe pattern:**
```java
ConfigurableJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
    new JWTClaimsSet.Builder().issuer(expectedIssuer).audience(clientId).build(),
    Set.of("sub", "iat", "exp", "iss", "aud")));
JWTClaimsSet claims = processor.process(idToken, null);
```

### 3c. Account linking via unverified `email`

**Vulnerable pattern:**
```java
String email = (String) oidcUser.getAttribute("email");
User user = userRepository.findByEmail(email);
if (user == null) user = createUser(email);
// provider controls the email claim — no email_verified check
```

An attacker who registers `victim@example.com` at an identity provider that does not enforce domain verification can link to the victim's account.

**Safe pattern:** Check `email_verified` claim before linking. Prefer `sub` (subject) as the stable identifier — bind `(issuer, sub)` rather than email.

**JSONL finding:**
```json
{"id":"OAUTH-004","skill":"sast-oauth","cwe":"CWE-287","owasp":"A07:2021-Identification and Authentication Failures","severity":"High","confidence":"Medium","file":"src/main/java/com/example/auth/OidcUserService.java","line":61,"method":"loadUser","class":"com.example.auth.OidcUserService","evidence":"        User user = userRepository.findByEmail(email);","sink":"userRepository.findByEmail()","source":"oidcUser.getAttribute(\"email\")","taint_path":[{"step":"email extracted from OIDC claims without email_verified check","file":"src/main/java/com/example/auth/OidcUserService.java","line":58}],"sanitizer_present":false,"sanitizer_detail":"","remediation":"Check Boolean emailVerified = oidcUser.getEmailVerified(); assert Boolean.TRUE.equals(emailVerified) before linking. Prefer binding on (iss, sub) pair stored at first login.","references":["CWE-287","https://portswigger.net/web-security/oauth/openid"],"false_positive_indicators":["Verify that the identity provider guarantees email uniqueness and verification before issuing tokens"],"status":"candidate"}
```

### 3d. Accepting tokens from any issuer (`/token` bypass)

**Vulnerable pattern:**
```java
NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwksUri).build();
// no issuer validation — accepts tokens from any IdP pointing to same JWKS
Jwt jwt = decoder.decode(token);
```

**Safe pattern:**
```java
NimbusJwtDecoder decoder = NimbusJwtDecoder.withIssuerLocation(issuerUri).build();
// withIssuerLocation fetches OIDC discovery doc, sets the issuer validator automatically
```

---

## Phase 4 — Token Storage and Session Hygiene

### 4a. Access/refresh tokens stored in `HttpSession`

Short-lived access tokens in session are acceptable. Refresh tokens in session are risky when sessions can be replayed (missing `HttpOnly`, long timeout, no session rotation post-login). Check session fixation and whether sessions are invalidated on logout.

### 4b. Tokens logged or exposed in error responses

```bash
rg -n "log.*token\|logger.*access_token\|printStackTrace.*token\|getMessage.*token\|getBody.*token" --glob "*.java"
```

Tokens in logs are a long-lived secret exposure vector.

---

## False Positive Suppression

- Spring Security's built-in `OAuth2LoginAuthenticationFilter` handles state generation and verification automatically — only flag if it is **replaced or bypassed**.
- `NimbusJwtDecoder.withIssuerLocation()` or `withJwkSetUri()` combined with `JwtValidators.createDefaultWithIssuer()` satisfies issuer + expiry validation.
- `parseClaimsJws` (not `parseClaimsJwt`) is the safe JJWT method — confirm which is used before reporting.
- Custom `OAuth2UserService` implementations that call `delegate.loadUser(request)` first then augment are safe if the delegate is the standard Spring implementation.

---

## Severity Guide

| Flaw | Severity |
|---|---|
| `alg:none` / unsigned token accepted | Critical |
| Missing state (login CSRF → account takeover) | High |
| Redirect URI from user input | High |
| Account linking via unverified email | High |
| Missing issuer/audience/expiry validation | High |
| No PKCE on public client | Medium |
| Tokens logged at INFO/DEBUG | Medium |
| Missing PKCE on confidential client | Low |
| Refresh token in non-HttpOnly cookie | Medium |
