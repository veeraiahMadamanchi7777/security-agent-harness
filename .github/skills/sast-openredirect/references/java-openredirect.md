# Java Open Redirect Reference — Sinks, Bypass Patterns & Safe Validation

## Redirect Sinks

| API | Risk | Notes |
|-----|------|-------|
| `HttpServletResponse.sendRedirect(url)` | HIGH | Direct redirect to user-controlled URL |
| Spring MVC `return "redirect:" + url` | HIGH | View name interpolation |
| `RedirectView(url)` | HIGH | Spring redirect view |
| `new ModelAndView("redirect:" + url)` | HIGH | ModelAndView redirect |
| `ResponseEntity.status(302).location(URI.create(url)).build()` | HIGH | Manual Location header |
| `response.setHeader("Location", url)` with 3xx status | HIGH | Raw header injection |
| `UriComponentsBuilder.fromUriString(url)` → `buildAndExpand().toUri()` | MEDIUM | Used as redirect target |

## High-Risk URL Parameter Names

These query/form parameters are commonly used as redirect targets:

```
returnUrl, return_url, returnTo, return_to
next, redirect, redirectTo, redirect_to
redirect_uri, redirectUri, callback
continue, forward, url, goto, dest, destination
target, redir, link, from, origin
```

## Bypass Techniques (Evaluate When Assessing Validation)

| Bypass | Example | Defeats |
|--------|---------|---------|
| Protocol-relative URL | `//evil.com/path` | Checks for `http://` prefix |
| Scheme-less absolute | `evil.com/path` | Checks only for `/` prefix |
| Whitespace prefix | ` https://evil.com` | Trimming not applied |
| Newline injection | `%0d%0aLocation: evil.com` | Response splitting (old servers) |
| Subpath match confusion | `https://trusted.com.evil.com/` | `startsWith("https://trusted.com")` |
| Path traversal in URL | `https://trusted.com/../../../evil.com` | Path-only check |
| Unicode lookalike | `https://trüsted.com` | ASCII comparison |
| Open redirect chain | `https://trusted.com/redirect?url=https://evil.com` | Same-host check passes trusted.com |
| JavaScript scheme | `javascript:alert(1)` | Old `sendRedirect` implementations |
| IPv6 | `http://[::1]/admin` | IP range check on string |
| Data URI | `data:text/html,<script>...</script>` | Scheme check not exhaustive |

## Safe Validation Patterns

```java
// Pattern 1 — Allowlist of known safe paths (simplest and most secure)
private static final Set<String> ALLOWED_PATHS = Set.of(
    "/dashboard", "/home", "/profile", "/orders"
);

public String safeRedirect(String returnTo) {
    if (returnTo != null && ALLOWED_PATHS.contains(returnTo)) {
        return returnTo;
    }
    return "/dashboard";  // default
}

// Pattern 2 — Relative path only (no scheme, no host)
public String safeRedirect(String returnTo) {
    if (returnTo == null
            || returnTo.startsWith("//")   // protocol-relative
            || returnTo.contains("://")    // has scheme
            || !returnTo.startsWith("/")) { // not a path
        return "/dashboard";
    }
    return returnTo;
}

// Pattern 3 — Same-host check using URI parsing
public URI safeRedirect(String returnTo, HttpServletRequest request) throws URISyntaxException {
    URI uri = new URI(returnTo);
    if (uri.isAbsolute()) {  // has scheme
        String requestHost = new URI(request.getRequestURL().toString()).getHost();
        if (!uri.getHost().equals(requestHost)) {
            throw new SecurityException("Redirect to external host not allowed");
        }
    }
    return uri;
}
// NOTE: Pattern 2 is safer — URI parsing has edge cases (e.g., //host in path)
```

## Ineffective Defenses (Still Bypassable)

| Defense | Why Insufficient |
|---------|-----------------|
| `url.contains("://")` check | `//evil.com` has no scheme — bypasses |
| `url.startsWith("/")` only | `//evil.com` starts with `/` — bypasses |
| `URLEncoder.encode(url)` before redirect | Encoding doesn't prevent redirect, just encodes the target |
| `url.replaceAll("[<>]", "")` | Doesn't remove `://` or `//` |
| `url.startsWith("https://trusted.com")` | `https://trusted.com.evil.com` bypasses |
| Blocklist of `javascript:` | New schemes may not be blocked (`vbscript:`, `data:`) |

## OAuth `redirect_uri` Validation

OAuth redirect URIs must be validated against a strict allowlist registered at the authorization server, not just a prefix check:

```java
// DANGEROUS — prefix check bypassable
if (!redirectUri.startsWith("https://example.com")) {
    throw new InvalidRedirectUriException();
}
// Bypass: https://example.com.evil.com/callback

// SAFE — exact match or registered URI set
Set<String> REGISTERED_URIS = Set.of(
    "https://example.com/callback",
    "https://app.example.com/oauth/callback"
);
if (!REGISTERED_URIS.contains(redirectUri)) {
    throw new InvalidRedirectUriException();
}
```

## False Positives

| Pattern | Reason to Exclude |
|---------|------------------|
| Redirect to hardcoded string constant | No user input |
| `redirect:` to `@Value("${app.redirect}")` | Static config |
| Redirect only to other endpoints in same app (mapped by controller method) | Internal |
| URL validated against ALLOWED_PATHS Set before use | Allowlist defense effective |
