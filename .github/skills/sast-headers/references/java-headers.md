# Java Security Headers Reference

## Common Headers

- `Content-Security-Policy`.
- `X-Frame-Options` or CSP `frame-ancestors`.
- `X-Content-Type-Options: nosniff`.
- `Strict-Transport-Security`.
- `Referrer-Policy`.
- `Permissions-Policy`.
- `Cache-Control: no-store` for sensitive pages.

## Review Notes

Spring Security enables some headers by default. Confirm whether custom config disables them.

Report missing headers as confirmed vulnerabilities only when tied to a realistic exploit path. Otherwise report as hardening.
