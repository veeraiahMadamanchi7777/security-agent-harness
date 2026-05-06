---
name: sast-cors
description: Review Java CORS configuration for credential leakage, origin reflection, and cross-origin authorization bypass.
---

# SKILL: sast-cors — CORS Misconfiguration Review

## Purpose

Find CORS policies that allow untrusted web origins to read authenticated or sensitive API responses.

Load [`references/java-cors.md`](references/java-cors.md).

## Method

1. Identify CORS configuration in Spring MVC, Spring Security, filters, gateways, and custom response headers.
2. Determine whether browser credentials are used: cookies, HTTP auth, client certificates, or bearer tokens stored by browser-accessible clients.
3. Check whether `Access-Control-Allow-Origin` is wildcard, reflected, regex-matched too broadly, or paired with credentials.
4. Trace sensitive endpoints exposed under the CORS policy.

## Searches

```bash
rg -n "@CrossOrigin|CorsConfiguration|CorsRegistry|allowedOrigins|allowedOriginPatterns|Access-Control-Allow-Origin|allowCredentials|CorsFilter|cors\\(" --glob "*.java" --glob "*.yml" --glob "*.properties"
```

## True Positive Signals

- `allowCredentials(true)` with wildcard, broad pattern, or reflected origins.
- Custom filter echoes the `Origin` header without strict allowlist.
- Sensitive endpoints allow cross-origin reads from untrusted origins.
- CORS is used as an authorization control instead of server-side auth.

## Output

Include vulnerable policy, affected origins, credential mode, sensitive endpoints, exploit scenario, and strict allowlist remediation.
