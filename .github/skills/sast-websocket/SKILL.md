---
name: sast-websocket
description: Review Java WebSocket and STOMP endpoints for authentication, origin checks, message-level authorization, and subscription leaks.
---

# SKILL: sast-websocket — WebSocket Security Review

## Purpose

Find WebSocket and STOMP flaws where handshake authentication, origin checks, or message-level authorization are weaker than HTTP endpoints.

Load [`references/java-websocket.md`](references/java-websocket.md).

## Method

1. Identify WebSocket handlers, STOMP controllers, broker configuration, handshake interceptors, and subscription paths.
2. Review authentication at handshake and message time.
3. Verify origin checks are strict for browser clients.
4. Verify message destinations and subscriptions enforce user/tenant/room authorization.
5. Trace message payloads into sinks and state transitions.

## Searches

```bash
rg -n "@EnableWebSocket|WebSocketHandler|TextWebSocketHandler|@ServerEndpoint|@MessageMapping|@SubscribeMapping|SimpMessagingTemplate|StompEndpointRegistry|setAllowedOrigins|HandshakeInterceptor|ChannelInterceptor" --glob "*.java"
```

## True Positive Signals

- WebSocket accepts cross-site browser connections without strict origin checks.
- Handshake authenticates, but messages or subscriptions do not enforce per-object authorization.
- User can subscribe to another tenant/user destination.
- Message payload mutates state without CSRF-equivalent or authorization controls.
- STOMP destination patterns expose sensitive broadcasts.

## Output

Include endpoint, handshake auth, origin policy, message destination, missing authorization, and exploit sequence.
