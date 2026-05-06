---
name: sast-cache
description: Review Java applications for web cache poisoning, sensitive response caching, tenant cache key confusion, and CDN/proxy trust flaws.
---

# SKILL: sast-cache — Cache Poisoning and Sensitive Caching Review

## Purpose

Find flaws where shared caches store attacker-influenced or sensitive responses under keys that are too broad or trust unvalidated request headers.

Load [`references/java-cache.md`](references/java-cache.md).

## Method

1. Identify HTTP cache headers, CDN/proxy assumptions, Spring cache usage, Redis/cache templates, and custom cache keys.
2. Review whether sensitive responses are marked private/no-store.
3. Review cache keys for tenant, user, role, locale, authorization, and request variation.
4. Check whether untrusted headers influence response generation but are missing from `Vary` or cache keys.

## Searches

```bash
rg -n "Cache-Control|Pragma|Expires|Vary|@Cacheable|CacheManager|RedisTemplate|Caffeine|EhCache|X-Forwarded|Forwarded|Host|X-Original-URL|X-Rewrite-URL" --glob "*.java" --glob "*.yml" --glob "*.properties"
```

## True Positive Signals

- Authenticated sensitive responses are cacheable by shared caches.
- Cache key omits user, tenant, role, or authorization context.
- Response varies by `Host`, forwarded headers, language, or custom headers without safe cache variation.
- Password reset, token, or PII pages lack `no-store`.
- CDN/proxy trust uses untrusted request headers for absolute links or redirects.

## Output

Include cache layer, key or header flaw, affected response, attacker poisoning/read scenario, and remediation.
