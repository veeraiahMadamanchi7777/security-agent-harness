# Java WebSocket Reference

## High-Risk Areas

- `setAllowedOrigins("*")`.
- Missing `HandshakeInterceptor` auth.
- `@MessageMapping` methods without principal or authorization checks.
- Broad topics such as `/topic/**` carrying tenant data.
- Direct use of `SimpMessagingTemplate.convertAndSend` to user-controlled destinations.

## Safer Controls

- Strict allowed origins.
- Authenticated principal at handshake.
- Message-level authorization.
- Tenant/user scoping for subscriptions.
- Payload validation.
- Rate limiting and message size limits.
