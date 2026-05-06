---
name: sast-secrets
description: Detect hardcoded credentials, tokens, private keys, secret material, and sensitive configuration leaks.
---

# SKILL: sast-secrets — Hardcoded Credentials & Secret Detection

## References

Load [`references/java-secrets.md`](references/java-secrets.md) at the start of this skill for credential patterns by provider, entropy-based detection guidance, safe placeholder patterns, severity table, and rotation checklist.

## Purpose

Identify hardcoded API keys, passwords, tokens, cryptographic keys, and connection strings embedded in source code, configuration files, and tests. Distinguish true positives from intentional test/placeholder values.

---

## Phase 1: Sink Discovery

### 1.1 — High-Signal Credential Patterns

```bash
# Private key PEM blocks
grep -rn "BEGIN RSA PRIVATE KEY\|BEGIN PRIVATE KEY\|BEGIN EC PRIVATE KEY\|BEGIN OPENSSH PRIVATE KEY\|BEGIN PGP PRIVATE KEY" \
  --include="*.java" --include="*.properties" --include="*.yml" --include="*.yaml" --include="*.xml" --include="*.json" --include="*.env" --include="*.pem" --include="*.key"

# AWS credentials
grep -rn "AKIA[A-Z0-9]\{16\}\|ASIA[A-Z0-9]\{16\}\|aws_access_key_id\s*=\|AWS_SECRET_ACCESS_KEY\s*=" \
  --include="*.java" --include="*.properties" --include="*.yml" --include="*.yaml" --include="*.xml" --include="*.env" -i

# GitHub tokens
grep -rn "ghp_[a-zA-Z0-9]\{36\}\|ghs_[a-zA-Z0-9]\{36\}\|github_token\s*=\|GITHUB_TOKEN\s*=" \
  --include="*.java" --include="*.properties" --include="*.yml" --include="*.yaml" -i

# Slack tokens
grep -rn "xox[baprs]-[A-Za-z0-9\-]\{10,}\|slack.*token\s*=" \
  --include="*.java" --include="*.properties" --include="*.yml" -i

# Google / GCP service account keys (JSON structure)
grep -rn '"type"\s*:\s*"service_account"\|"private_key_id"\s*:' \
  --include="*.json" --include="*.java" --include="*.properties"

# Stripe API keys
grep -rn "sk_live_[a-zA-Z0-9]\{24,}\|rk_live_[a-zA-Z0-9]\{24,}" \
  --include="*.java" --include="*.properties" --include="*.yml" --include="*.yaml"

# Twilio
grep -rn "AC[a-f0-9]\{32\}\|SK[a-f0-9]\{32\}" --include="*.java" --include="*.properties" --include="*.yml"

# SendGrid
grep -rn "SG\.[a-zA-Z0-9\._\-]\{22,}" --include="*.java" --include="*.properties" --include="*.yml"

# Generic high-entropy strings in credential context
grep -rn "password\s*=\s*\"[^\"]\{8,}\"\|secret\s*=\s*\"[^\"]\{8,}\"\|apikey\s*=\s*\"[^\"]\{8,}\"\|api_key\s*=\s*\"[^\"]\{8,}\"" \
  --include="*.java" --include="*.properties" -i | grep -v "CHANGEME\|changeme\|your_secret\|TODO\|FIXME\|example\|placeholder\|test\|demo\|\*\*\*\|xxxx\|1234\|password"
```

### 1.2 — Database Connection Strings

```bash
# JDBC URLs with embedded credentials
grep -rn "jdbc:.*//.*:.*@\|jdbc:.*password=" \
  --include="*.java" --include="*.properties" --include="*.yml" --include="*.xml"

# Datasource password in application properties
grep -rn "spring\.datasource\.password\s*=\|datasource\.password\s*=" \
  --include="*.properties" --include="*.yml" --include="*.yaml" | grep -v "^\s*#\|password\s*=\s*$\|\${.*}\|env\b"

# Hibernate dialect / connection in Java code
grep -rn "hibernate\.connection\.password\|c3p0.*password\|hikari.*password" --include="*.java" --include="*.properties" -i
```

### 1.3 — Application-Level Secrets

```bash
# JWT signing secrets
grep -rn "jwtSecret\|jwt\.secret\|jwt-secret\|JWT_SECRET\|signingKey\|signing\.key" \
  --include="*.java" --include="*.properties" --include="*.yml" --include="*.yaml" | grep -v "\${\|env\b\|<" | grep "=\s*\""

# Encryption keys
grep -rn "encryptionKey\|encryption\.key\|aesKey\|aes\.key\|secretKey\s*=\s*\"\|SECRET_KEY\s*=" \
  --include="*.java" --include="*.properties" --include="*.yml" -i | grep -v "\${\|env\b\|KeySpec\|KeyGenerator\|KeyFactory"

# OAuth client secrets
grep -rn "client\.secret\|clientSecret\s*=\s*\"\|oauth.*secret\s*=\s*\"\|OAUTH_CLIENT_SECRET" \
  --include="*.java" --include="*.properties" --include="*.yml" -i | grep -v "\${"

# SMTP credentials
grep -rn "mail\.password\s*=\|smtp\.password\s*=\|MAIL_PASSWORD\s*=" \
  --include="*.properties" --include="*.yml" --include="*.yaml" | grep -v "\${" | grep "=\s*[^\s]"

# S3 / storage secrets
grep -rn "s3\.secret\|s3SecretKey\|storageSecret\|bucketSecret\|S3_SECRET\|MINIO_SECRET" \
  --include="*.java" --include="*.properties" --include="*.yml" -i | grep -v "\${"
```

### 1.4 — Secrets in Test Code (Lower Priority but Still Report)

```bash
# Test files often contain real-looking secrets
grep -rn "password\|secret\|apiKey\|token\b" \
  --include="*Test.java" --include="*Tests.java" --include="*IT.java" --include="*Spec.java" | \
  grep '=\s*"[^"]\{8,}"' | grep -v "CHANGEME\|dummy\|fake\|test\|mock\|example\|placeholder"

# application-test.properties
grep -rn "password\|secret\|apiKey" \
  --include="application-test.properties" --include="application-test.yml" | \
  grep -v "\${\|env\b\|dummy\|test\|changeme"
```

---

## Phase 2: False Positive Filtering

### 2.1 — Clearly Fake / Placeholder Values (Skip)

The following patterns are **not findings**:
- Values containing: `CHANGEME`, `REPLACE_ME`, `TODO`, `FIXME`, `your_secret_here`, `<YOUR_API_KEY>`, `placeholder`, `example`, `xxx`, `***`, `12345678`
- Values that are only 3–5 characters (too short to be real secrets)
- Values that are clearly property references: `${jwt.secret}`, `${env.SECRET}`, `#{...}`, `@Value("${...}")`
- Values in comments: lines starting with `//` or `#`
- JUnit `@Test` annotations on the same line
- Obvious test database passwords like `password`, `root`, `postgres`, `sa` in test context

### 2.2 — External Reference Patterns (Safe)

```bash
# Spring @Value injection — secret comes from environment/config at runtime
grep -rn '@Value("\${' --include="*.java"

# Environment variable references
grep -rn "System\.getenv\b\|System\.getProperty\b" --include="*.java" | grep -v "//\|test"

# Spring Cloud Config / AWS Secrets Manager / Vault
grep -rn "spring\.config\.import.*vault\|spring\.config\.import.*secrets\|@EnableVault\|SecretManagerTemplate\|AwsSecretsManagerPropertySource" \
  --include="*.java" --include="*.properties" --include="*.yml"
```

If secrets are fetched at runtime via these mechanisms → safe. But verify there's no fallback default:
```bash
grep -rn '@Value("\${.*:.*")' --include="*.java" | grep "secret\|password\|key\b\|token\b" -i
# @Value("${jwt.secret:HARDCODED_DEFAULT}") — the default IS a hardcoded secret if it's real
```

---

## Phase 3: Entropy Analysis (High-Entropy String Detection)

For strings that pass syntactic checks, assess entropy:

High entropy strings in credential-named variables are likely real secrets even without known-format patterns:
- Length > 20 characters
- Mix of upper/lower/digit/special
- No dictionary words
- Not a UUID (which is usually non-sensitive)
- Variable name contains: `secret`, `key`, `token`, `password`, `credential`, `auth`

```bash
# Find potential high-entropy secrets (manual review needed)
grep -rn 'secret\s*=\s*"[A-Za-z0-9+/=_\-]\{20,}"\|key\s*=\s*"[A-Za-z0-9+/=_\-]\{20,}"' \
  --include="*.java" --include="*.properties" --include="*.yml" -i | \
  grep -v "\${.*}\|CHANGEME\|example\|test\|test\|demo\|placeholder"
```

---

## Phase 4: Git History (Surface Area Extension)

Note for the reviewer: if the secret was already removed from the current codebase but may exist in git history:
```bash
git log --all --full-history --diff-filter=D --name-only --pretty=format: | xargs git show 2>/dev/null | grep -i "password\|secret\|apikey\|token\b" | head -30
```
This is a manual check — note the need to rotate even if removed from current code.

---

## Phase 5: Severity Assessment

| Finding | Severity |
|---------|---------|
| Live production secret (cloud key, OAuth client secret) | CRITICAL |
| JWT signing secret hardcoded | CRITICAL |
| Database password hardcoded in prod config | CRITICAL |
| Private key (RSA/EC) committed | CRITICAL |
| Test-only real credential (rotated before prod) | HIGH |
| Default fallback secret in `@Value` annotation | HIGH |
| Weak/known secrets (123456, password) | MEDIUM |
| Secret in git history (already removed) | HIGH (requires rotation) |
| Secret in test/mock context, clearly fake | INFO |

---

## Finding Format

Follow the canonical format from `copilot-instructions.md`. Example:

```
### [CRITICAL] Hardcoded Secret — JWT Signing Key in Source Code

**ID:** SECRETS-001
**File:** `src/main/java/com/example/JwtConfig.java:15`
**CWE:** CWE-798 | **OWASP:** A02:2021-Cryptographic Failures
**CVSS (estimated):** 9.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
**Confidence:** High
**Skill:** `sast-secrets`

**Taint Path:**
`static final String JWT_SECRET = "s3cr3t!..." (JwtConfig.java:15)` → used by `JwtService.generateToken() (JwtService.java:34)` to sign all issued tokens

**Vulnerable Code:**
```java
// Line 13-17
@Configuration
public class JwtConfig {
    private static final String JWT_SECRET = "s3cr3t!JWT@K3y#2024Pr0duct10n";
    // This secret is committed to version control
}
```

**Why Exploitable:**
Any person with repository read access (current or historical) can use this key to sign arbitrary JWT tokens claiming any user identity or role, bypassing all authentication and authorization controls.

**Proof-of-Concept:**
```python
import jwt
token = jwt.encode({"sub":"admin","role":"ADMIN"}, "s3cr3t!JWT@K3y#2024Pr0duct10n", algorithm="HS256")
# Use token in Authorization: Bearer <token>
```

**Remediation:**
1. Rotate immediately — treat the key as compromised
2. Load from environment: `@Value("${JWT_SECRET}") private String jwtSecret;`
3. Set via CI/CD secrets or secrets manager (AWS Secrets Manager, HashiCorp Vault)
4. Minimum key size: 256-bit random — `openssl rand -hex 32`
5. If present in git history: rotate first, then scrub with `git filter-repo`

**References:** https://cwe.mitre.org/data/definitions/798.html, OWASP A02:2021
```

JSONL line (append to `.github/sast-findings.jsonl`):
```json
{"id":"SECRETS-001","skill":"sast-secrets","cwe":"CWE-798","owasp":"A02:2021-Cryptographic Failures","severity":"Critical","confidence":"High","file":"src/main/java/com/example/JwtConfig.java","line":15,"method":"","class":"com.example.JwtConfig","evidence":"private static final String JWT_SECRET = \"s3cr3t!JWT@K3y#2024Pr0duct10n\";","sink":"JWT signing key","source":"Hardcoded string literal in source code","taint_path":[],"sanitizer_present":false,"sanitizer_detail":"","remediation":"Remove hardcoded value; load from @Value(\"${JWT_SECRET}\") backed by CI/CD secrets or secrets manager","references":["https://cwe.mitre.org/data/definitions/798.html"],"false_positive_indicators":[],"duplicate_of":null}
```
