# Java Logging Reference

## Sensitive Data

- Passwords and password hashes.
- JWTs, bearer tokens, API keys, OAuth codes, refresh tokens.
- Session IDs and cookies.
- Reset or verification links.
- Private keys and secrets.
- Full PII where policy forbids logging.

## Risky Patterns

- `e.printStackTrace()`.
- Returning exception messages directly.
- Logging request headers wholesale.
- Logging request or response bodies on auth/payment/profile endpoints.
- User-controlled log fields containing CR/LF.

## Safer Controls

- Structured logging with redaction.
- Token fingerprinting instead of full token values.
- Generic client errors with server-side correlation IDs.
- Audit events for privilege and account lifecycle changes.
