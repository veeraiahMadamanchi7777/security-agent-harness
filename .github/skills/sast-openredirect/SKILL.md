# SKILL: sast-openredirect — Open Redirect Detection

## References

Load [`references/java-openredirect.md`](references/java-openredirect.md) at the start of this skill for redirect sink table, high-risk parameter names, bypass techniques, safe validation patterns, OAuth redirect_uri validation, and false positives.

## Purpose

Identify endpoints that redirect users to attacker-controlled URLs, enabling phishing attacks, OAuth token theft, and credential harvesting by exploiting user trust in the legitimate domain.

---

## Phase 1: Sink Discovery

### 1.1 — HTTP Redirect Sinks

```bash
# HttpServletResponse.sendRedirect() — most common
grep -rn "\.sendRedirect(" --include="*.java"

# Spring RedirectView
grep -rn "new RedirectView(\|RedirectView\b" --include="*.java" | grep -v "//\|test"

# Spring "redirect:" return string
grep -rn '"redirect:' --include="*.java"

# ResponseEntity with Location header
grep -rn "HttpHeaders\b\|ResponseEntity\b" --include="*.java" -A5 | \
  grep -A5 "setLocation\|Location.*URI\|LOCATION"

# Spring ResponseEntity redirect builder
grep -rn "ResponseEntity\.status(HttpStatus\.FOUND)\|ResponseEntity\.status(302)\|\.location(" \
  --include="*.java"

# UriComponentsBuilder redirect
grep -rn "UriComponentsBuilder\b" --include="*.java" -A5 | grep -A5 "redirect\|location\|Location"

# Jakarta/Javax HttpServletResponse
grep -rn "response\.setHeader.*Location\|response\.addHeader.*Location" --include="*.java"

# Spring WebFlux redirect
grep -rn "ServerResponse\.temporaryRedirect\|ServerResponse\.permanentRedirect\|\.seeOther(" \
  --include="*.java"
```

### 1.2 — Return URL / Redirect URL Parameter Patterns

```bash
# Common redirect parameter names in controllers
grep -rn "@RequestParam.*redirect\|@RequestParam.*returnUrl\|@RequestParam.*returnTo\|@RequestParam.*next\|@RequestParam.*url\b\|@RequestParam.*target\b\|@RequestParam.*continue\b" \
  --include="*.java" -i

grep -rn "@PathVariable.*redirect\|@PathVariable.*url\b\|@PathVariable.*target\b" \
  --include="*.java" -i

# Raw servlet parameter for redirect
grep -rn "getParameter.*redirect\|getParameter.*return\|getParameter.*url\b\|getParameter.*next\b" \
  --include="*.java" -i
```

### 1.3 — OAuth / SSO Redirect URIs

```bash
# OAuth redirect_uri parameter — attacker-supplied
grep -rn "redirect_uri\|redirectUri\|callbackUrl\|callback_url" \
  --include="*.java" --include="*.properties" --include="*.yml"

# Spring Security OAuth2 redirect handling
grep -rn "OAuth2LoginAuthenticationFilter\|AbstractAuthorizationCodeTokenResponseClient\|RedirectServerAuthenticationSuccessHandler" \
  --include="*.java"
```

---

## Phase 2: Taint Analysis

### 2.1 — Confirm User Control of Redirect Target

```bash
# Direct: sendRedirect with request parameter
grep -rn "sendRedirect\|RedirectView\|redirect:" --include="*.java" -B10 | \
  grep -B10 "getParameter\|@RequestParam\|@PathVariable\|getHeader\|getQueryString"

# Indirect: redirect URL stored in variable from request
grep -rn "redirectUrl\|returnUrl\|targetUrl\|nextUrl" --include="*.java" | \
  grep "getParameter\|@RequestParam\|@PathVariable"
```

### 2.2 — Bypass-Prone Validation Check

Look for validation that appears to protect but can be bypassed:

```bash
# startsWith("/") check — bypassed by //evil.com
grep -rn "startsWith(\"/\")" --include="*.java" -B3 -A3 | \
  grep -B3 "redirect\|sendRedirect\|ReturnUrl\|returnTo" -i

# !contains("://") check — bypassed by //evil.com
grep -rn "contains.*://\|contains.*http" --include="*.java" -B5 | \
  grep -B5 "redirect\|returnUrl" -i

# URL regex validation (often incomplete)
grep -rn "matches\b\|Pattern\.compile" --include="*.java" -B5 | \
  grep -B5 "redirect\|return\b.*url\|target\b" -i
```

---

## Phase 3: Sanitizer Detection

### Effective Sanitizers (credit these, reduce to Low/Medium)

```bash
# Allowlist check against fixed set of permitted URLs
grep -rn "ALLOWED_REDIRECT\|allowedUrls\|whitelistUrl\|permittedDomains\|PERMITTED_HOSTS" \
  --include="*.java"

# Same-host check using URI parsing
grep -rn "URI\.create\|new URI(\|UriComponentsBuilder" --include="*.java" -A5 | \
  grep -A5 "getHost\|getAuthority\|getScheme"

# Spring Security's DefaultRedirectStrategy or HttpStatusReturningLogoutSuccessHandler
grep -rn "DefaultRedirectStrategy\|SimpleUrlAuthenticationSuccessHandler\|HttpStatusReturningLogoutSuccessHandler" \
  --include="*.java"
```

### Ineffective Validation (do NOT credit as sanitizer)

```bash
# startsWith("/") without also checking startsWith("//")
# → protocol-relative URL: //evil.com

# !url.contains("://") check
# → bypassed by //evil.com (no scheme, but still absolute)

# URLEncoder.encode(url) before redirect
# → encoding does not prevent redirect, just encodes the attacker's URL

# url.replaceAll("[^a-zA-Z0-9/]", "")
# → may destroy valid URLs; still redirectable to path-only

# Checking only the scheme (startsWith("https://"))
# → attacker can register https://evil.com
```

---

## Phase 4: Severity Assessment

| Pattern | Severity |
|---------|---------|
| sendRedirect(userInput) with no validation | HIGH |
| "redirect:" + userInput return string | HIGH |
| Partial validation bypassable with // | HIGH |
| OAuth redirect_uri not validated against allowlist | CRITICAL |
| Same-host check with URI parsing (strong but not perfect) | LOW |
| Allowlist validation present | Informational |
| Redirect to relative path only (no scheme/host) | LOW |

---

## Finding Format

Follow the canonical format from `copilot-instructions.md`. Example:

```
### [HIGH] Open Redirect — User-Controlled Redirect After Login

**ID:** REDIRECT-001
**File:** `src/main/java/com/example/AuthController.java:78`
**CWE:** CWE-601 | **OWASP:** A01:2021-Broken Access Control
**CVSS (estimated):** 7.4 (AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N)
**Confidence:** High
**Skill:** `sast-openredirect`

**Taint Path:**
`POST /login?returnTo=X` → `AuthController.login(@RequestParam returnTo) (AuthController.java:75)` → `response.sendRedirect(returnTo) (AuthController.java:78)` — no host or path validation

**Vulnerable Code:**
```java
@PostMapping("/login")
public void login(@RequestParam String username, @RequestParam String password,
                  @RequestParam String returnTo, HttpServletResponse response) throws IOException {
    authService.authenticate(username, password);
    response.sendRedirect(returnTo);  // ← attacker-controlled returnTo
}
```

**Why Exploitable:**
`returnTo` is taken directly from the query string and passed to `sendRedirect` without any host or scheme validation. After successful authentication the browser follows the redirect, sending the user (and any post-auth tokens in the URL) to the attacker's domain. Protocol-relative URLs (`//evil.com`) bypass simple `startsWith("/")` checks.

**Proof-of-Concept:**
```http
GET https://example.com/login?returnTo=https://evil.com/steal-tokens
# Protocol-relative bypass when only "/" check is present:
GET https://example.com/login?returnTo=//evil.com/steal-tokens
```

**Remediation:**
```java
private String validateReturnUrl(String url) {
    if (url == null || !url.startsWith("/") || url.startsWith("//")) {
        return "/dashboard";  // default safe redirect
    }
    return url;
}
// Call: response.sendRedirect(validateReturnUrl(returnTo));
```

**References:** https://cwe.mitre.org/data/definitions/601.html, OWASP A01:2021
```

JSONL line (append to `.github/sast-findings.jsonl`):
```json
{"id":"REDIRECT-001","skill":"sast-openredirect","cwe":"CWE-601","owasp":"A01:2021-Broken Access Control","severity":"High","confidence":"High","file":"src/main/java/com/example/AuthController.java","line":78,"method":"login","class":"com.example.AuthController","evidence":"response.sendRedirect(returnTo);","sink":"HttpServletResponse.sendRedirect()","source":"@RequestParam String returnTo","taint_path":[],"sanitizer_present":false,"sanitizer_detail":"","remediation":"Validate returnTo: reject if not starting with '/' or if starting with '//'","references":["https://cwe.mitre.org/data/definitions/601.html"],"false_positive_indicators":[],"duplicate_of":null}
```

---

## Self-Contained Check

This skill runs independently. If `.github/sast-context.json` exists, use `file_classifications.openredirect_candidates` as the file list. Otherwise scan all Java files in `src/main/java/`.
