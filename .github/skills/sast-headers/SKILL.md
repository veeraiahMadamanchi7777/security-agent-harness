---
name: sast-headers
description: Review Java security header configuration for clickjacking, MIME sniffing, transport security, referrer leakage, and browser isolation gaps.
---

# SKILL: sast-headers — Browser Security Headers Review

## Purpose

Find missing or weakened browser security headers when they meaningfully affect exploitability. This is usually hardening unless tied to a concrete attack path.

Load [`references/java-headers.md`](references/java-headers.md).

## Method

1. Identify Spring Security header config, servlet filters, gateways, and reverse proxy assumptions.
2. Review frame protection, content sniffing, HSTS, referrer policy, content security policy, permissions policy, and cache headers for sensitive pages.
3. Tie missing headers to XSS, clickjacking, token leakage, mixed content, or data exposure where possible.

## Searches

```bash
rg -n "headers\\(|frameOptions|contentSecurityPolicy|httpStrictTransportSecurity|xssProtection|X-Frame-Options|Content-Security-Policy|Strict-Transport-Security|X-Content-Type-Options|Referrer-Policy|Permissions-Policy" --glob "*.java" --glob "*.yml" --glob "*.properties"
```

## True Positive Signals

- Sensitive state-changing UI can be framed and clicked by another site.
- Content type sniffing can make uploaded files execute as script.
- HSTS missing or disabled on HTTPS-only production app.
- Referrer leaks sensitive tokens or IDs to third parties.
- CSP absent where existing XSS risk is otherwise hard to eliminate.

## Output

Include affected surface, missing header, exploit class enabled, and exact header/config remediation. Keep pure hardening as Low or Informational.
