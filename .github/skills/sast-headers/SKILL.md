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
# Browser security headers
rg -n "headers\\(|frameOptions|contentSecurityPolicy|httpStrictTransportSecurity|xssProtection|X-Frame-Options|Content-Security-Policy|Strict-Transport-Security|X-Content-Type-Options|Referrer-Policy|Permissions-Policy" \
   --glob "*.java" --glob "*.yml" --glob "*.properties"

# Spring Boot Actuator exposure
rg -n "management\.endpoints\|management\.endpoint\|exposure\.include\|web\.exposure\|actuator\|EndpointWebExtension\|@Endpoint\|@WebEndpoint\|@ReadOperation\|@WriteOperation" \
   --glob "*.java" --glob "*.yml" --glob "*.properties"
```

## True Positive Signals

- Sensitive state-changing UI can be framed and clicked by another site.
- Content type sniffing can make uploaded files execute as script.
- HSTS missing or disabled on HTTPS-only production app.
- Referrer leaks sensitive tokens or IDs to third parties.
- CSP absent where existing XSS risk is otherwise hard to eliminate.
- **Actuator wildcard exposure:** `management.endpoints.web.exposure.include=*` exposes `/actuator/env` (environment variables including secrets), `/actuator/heapdump` (heap dump with in-memory credentials), `/actuator/loggers` (runtime log-level changes enabling debug credential leakage), and `/actuator/shutdown` (remote JVM kill).
- **Actuator without authentication:** Actuator endpoints reachable without Spring Security authentication guard or separate management port restriction.

## Actuator Exposure Patterns

### Critical: heap dump and env endpoint exposed

```yaml
# application.yml — dangerous
management:
  endpoints:
    web:
      exposure:
        include: "*"   # exposes /actuator/heapdump, /actuator/env, /actuator/shutdown
```

`/actuator/heapdump` returns a full JVM heap dump — an attacker can extract in-memory passwords, JWT signing keys, database credentials, and session tokens from it.

**Safe configuration:**
```yaml
management:
  endpoints:
    web:
      exposure:
        include: health,info    # allowlist only what is needed
  endpoint:
    health:
      show-details: when_authorized
```

**JSONL finding:**
```json
{"id":"HEADERS-010","skill":"sast-headers","cwe":"CWE-200","owasp":"A05:2021-Security Misconfiguration","severity":"Critical","confidence":"High","file":"src/main/resources/application.yml","line":8,"method":"","class":"","evidence":"        include: \"*\"","sink":"management.endpoints.web.exposure.include","source":"application.yml wildcard actuator exposure","taint_path":[],"sanitizer_present":false,"sanitizer_detail":"","remediation":"Replace include: \"*\" with an explicit allowlist of safe endpoints (e.g., health,info). Protect remaining endpoints with Spring Security: require ACTUATOR_ADMIN role on /actuator/** path. Alternatively bind management server to a separate non-public port using management.server.port.","references":["CWE-200","https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html#actuator.endpoints.security"],"false_positive_indicators":["Confirm whether /actuator is protected by Spring Security role check or is bound to an internal-only management.server.port"],"status":"candidate"}
```

### High: Actuator not protected by Spring Security

```bash
# Detect actuator route without corresponding security config
rg -n "requestMatchers.*actuator\|antMatchers.*actuator\|management\.server\.port" --glob "*.java" --glob "*.yml"
```

If `management.server.port` is not set to a separate internal port, and no `requestMatchers("/actuator/**").hasRole(...)` rule exists in the Spring Security config, actuator endpoints are accessible to any authenticated (or unauthenticated) user.

## Output

Include affected surface, missing header or misconfigured actuator endpoint, exploit class enabled, and exact header/config remediation. Keep pure hardening as Low or Informational.
