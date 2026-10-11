---
name: sast-grpc
description: Review gRPC service definitions and Java stubs for authentication bypass, insecure reflection API exposure, missing input validation on Protobuf messages, and streaming input abuse.
---

# SKILL: sast-grpc — gRPC and Protobuf Security Review

## Purpose

Find security flaws in gRPC service implementations: unauthenticated service exposure, server reflection API abuse, missing input validation on Protobuf fields, insecure channel configuration, and streaming attack surfaces.

Load [`references/java-grpc.md`](references/java-grpc.md) if present.

---

## Phase 1 — Identify gRPC Surface

```bash
# Service implementations and stubs
rg -n "extends.*Grpc\.|ImplBase|StreamObserver|ServerInterceptor|ClientInterceptor|ManagedChannel|ServerBuilder|NettyServerBuilder|InProcessServerBuilder" \
   --glob "*.java"

# Protobuf message types and field access
rg -n "\.getDefaultInstance\|\.newBuilder\|\.parseFrom\|\.mergeFrom\|\.toByteArray\|\.writeTo\|com\.google\.protobuf" \
   --glob "*.java"

# Authentication and metadata interceptors
rg -n "Metadata\|ServerCall\|Contexts\|Context\.key\|AuthServerInterceptor\|JwtServerInterceptor\|BearerToken\|io\.grpc\.auth" \
   --glob "*.java"

# gRPC reflection (dangerous in production)
rg -n "ProtoReflectionService\|reflection\.v1\|ServerReflection\|addService.*reflection\|ProtoServerReflectionService" \
   --glob "*.java" --glob "*.yml" --glob "*.properties"

# Channel credentials and TLS
rg -n "usePlaintext\|forAddress\|ManagedChannelBuilder\|InsecureChannelCredentials\|TlsChannelCredentials\|negotiationType.*PLAINTEXT" \
   --glob "*.java"

# Service config and port binding
rg -n "grpc\.port\|grpc\.server\|grpc\.security\|spring\.grpc\|net\.devh\.boot\.grpc" \
   --glob "*.yml" --glob "*.properties"
```

---

## Phase 2 — Authentication and Authorization Gaps

### 2a. No authentication interceptor on service methods

**Vulnerable pattern:**
```java
@GrpcService
public class UserServiceImpl extends UserServiceGrpc.UserServiceImplBase {
    @Override
    public void getUser(GetUserRequest req, StreamObserver<UserResponse> resp) {
        // No auth check — any unauthenticated caller can invoke this
        User user = userRepository.findById(req.getUserId());
        resp.onNext(UserResponse.newBuilder().setUser(user).build());
        resp.onCompleted();
    }
}
```

Check whether a `ServerInterceptor` enforcing authentication is registered for every service, or whether individual methods check the gRPC `Context` for a verified identity.

**Safe pattern:**
```java
// Register interceptor globally or per-service
server = ServerBuilder.forPort(port)
    .addService(ServerInterceptors.intercept(new UserServiceImpl(), new AuthInterceptor()))
    .build();

// In AuthInterceptor: extract and verify JWT from Metadata, attach to Context
// In service: Context.current().call(() -> { ... }) or check a Context.Key
```

**JSONL finding:**
```json
{"id":"GRPC-001","skill":"sast-grpc","cwe":"CWE-306","owasp":"A07:2021-Identification and Authentication Failures","severity":"Critical","confidence":"Medium","file":"src/main/java/com/example/grpc/UserServiceImpl.java","line":12,"method":"getUser","class":"com.example.grpc.UserServiceImpl","evidence":"    public void getUser(GetUserRequest req, StreamObserver<UserResponse> resp) {","sink":"UserServiceGrpc.UserServiceImplBase.getUser()","source":"gRPC client call (unauthenticated)","taint_path":[],"sanitizer_present":false,"sanitizer_detail":"","remediation":"Register a ServerInterceptor that verifies a bearer token or mTLS client certificate before service dispatch. Attach verified identity to gRPC Context and check it in each handler.","references":["CWE-306","https://grpc.io/docs/guides/auth/"],"false_positive_indicators":["Confirm whether a global interceptor is registered via ServerBuilder or Spring @GrpcGlobalServerInterceptor"],"status":"candidate"}
```

### 2b. gRPC Server Reflection enabled in production

Server Reflection (`ProtoReflectionService`) exposes all service definitions, method names, and Protobuf schemas to any caller — equivalent to an open introspection API. In development this is useful; in production it enables:
- Service enumeration without source code
- Attack surface discovery (method names, field types)
- Replay attack construction from schema alone

**Vulnerable pattern:**
```java
Server server = ServerBuilder.forPort(9090)
    .addService(new OrderServiceImpl())
    .addService(ProtoReflectionService.newInstance())  // ← dangerous in production
    .build();
```

**JSONL finding:**
```json
{"id":"GRPC-002","skill":"sast-grpc","cwe":"CWE-200","owasp":"A05:2021-Security Misconfiguration","severity":"Medium","confidence":"High","file":"src/main/java/com/example/grpc/GrpcServerConfig.java","line":34,"method":"grpcServer","class":"com.example.grpc.GrpcServerConfig","evidence":"    .addService(ProtoReflectionService.newInstance())","sink":"ServerBuilder.addService(ProtoReflectionService)","source":"gRPC server configuration","taint_path":[],"sanitizer_present":false,"sanitizer_detail":"","remediation":"Gate reflection behind a build profile: add ProtoReflectionService only when spring.profiles.active contains 'dev' or 'local'. Never enable in production or staging.","references":["CWE-200","https://github.com/grpc/grpc/blob/master/doc/server-reflection.md"],"false_positive_indicators":["Verify grpc.reflection.enabled property and active Spring profile"],"status":"candidate"}
```

---

## Phase 3 — Protobuf Input Validation

### 3a. Missing validation on Protobuf numeric fields

Protobuf numeric fields default to `0` when absent — not `null`. Code that treats `0` as "not set" is exploitable with a missing-field request.

**Vulnerable pattern:**
```java
public void transfer(TransferRequest req, StreamObserver<TransferResponse> resp) {
    // req.getAmount() returns 0 if not set — never negative, but zero is accepted
    accountService.transfer(req.getFromAccount(), req.getToAccount(), req.getAmount());
}
```

**Safe pattern:** Validate all required fields explicitly; proto3 has no `required` keyword.
```java
if (req.getAmount() <= 0) {
    resp.onError(Status.INVALID_ARGUMENT.withDescription("amount must be positive").asException());
    return;
}
if (req.getFromAccount().isBlank() || req.getToAccount().isBlank()) {
    resp.onError(Status.INVALID_ARGUMENT.withDescription("account IDs required").asException());
    return;
}
```

### 3b. `parseFrom` on untrusted bytes without size limit

Protobuf `parseFrom(byte[])` will allocate objects proportional to the message size. Without a size limit, a caller can trigger excessive memory allocation.

**Vulnerable pattern:**
```java
public void processEvent(RawEventRequest req, StreamObserver<Empty> resp) {
    MyEvent event = MyEvent.parseFrom(req.getPayload().toByteArray()); // unbounded
}
```

**Safe pattern:**
```java
CodedInputStream cis = CodedInputStream.newInstance(req.getPayload().toByteArray());
cis.setSizeLimit(1024 * 1024); // 1 MB max
MyEvent event = MyEvent.parseFrom(cis);
```

---

## Phase 4 — Channel Security and Transport

### 4a. Plaintext gRPC channel (no TLS)

**Vulnerable pattern:**
```java
ManagedChannel channel = ManagedChannelBuilder
    .forAddress("internal-service", 9090)
    .usePlaintext()  // ← sends credentials and data unencrypted
    .build();
```

For internal service-to-service communication behind a service mesh (Istio/Linkerd with mTLS), `usePlaintext()` may be acceptable. Flag where no mTLS is documented.

### 4b. Client streaming without per-message authorization

In streaming RPCs, authentication is checked once at stream open. If the service processes messages from a long-lived stream without re-validating the message content's ownership, an authenticated attacker can stream requests targeting other users' resources.

```bash
rg -n "requestObserver\|onNext\|StreamObserver" --glob "*.java" -A 5 | \
  grep -v "authorization\|userId\|ownerId\|tenantId"
```

---

## False Positive Suppression

- `usePlaintext()` inside unit/integration tests (`@SpringBootTest`, `InProcessServerBuilder`) is safe — flag only production config classes.
- `ProtoReflectionService` is safe if the server is bound to `localhost` only (not `0.0.0.0`) or protected behind an authenticated API gateway.
- Input validation in a shared interceptor counts as sanitized — verify the interceptor is actually registered for the service.
- Spring Boot gRPC starters (net.devh) auto-configure security when `grpc.server.security.*` properties are set — check `application.yml` before reporting.

---

## Severity Guide

| Flaw | Severity |
|---|---|
| No authentication on externally exposed service | Critical |
| Reflection API enabled in production (0.0.0.0) | Medium |
| Plaintext channel carrying credentials (no service mesh) | High |
| Missing validation on financial/state-change fields | High |
| Unbounded `parseFrom` (DoS via memory) | Medium |
| Reflection enabled, localhost-only | Low |
| Client streaming without per-message ownership check | Medium |
