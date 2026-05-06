# Java CORS Reference

## Risky Patterns

- `allowedOrigins("*")` with credentials.
- `allowedOriginPatterns("*")` with credentials.
- `response.setHeader("Access-Control-Allow-Origin", request.getHeader("Origin"))`.
- Regex or suffix checks such as `endsWith("example.com")` that allow `evil-example.com`.
- CORS enabled globally for admin APIs.

## Safer Patterns

- Exact scheme/host/port allowlist.
- No credentials for public cross-origin resources.
- Server-side authorization independent of CORS.
- Narrow methods and headers.
- Environment-specific origins.
