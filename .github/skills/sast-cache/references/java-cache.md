# Java Cache Reference

## Risky Patterns

- `@Cacheable` on methods returning user-specific data without user/tenant key.
- `Cache-Control: public` on authenticated responses.
- Missing `Vary: Origin` for origin-dependent responses.
- Password reset or token pages without `Cache-Control: no-store`.
- Absolute URL generation from untrusted `Host` or forwarded headers.

## Safer Controls

- Include tenant/user/security context in cache keys.
- Mark sensitive responses `Cache-Control: no-store`.
- Normalize and trust proxy headers only from known proxies.
- Avoid reflecting untrusted headers into cacheable responses.
