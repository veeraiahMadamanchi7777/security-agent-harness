# Java Hardcoded Secrets Reference — Patterns, Entropy & Remediation

## High-Signal Credential Patterns

### Cryptographic Key Material

| Pattern | Regex / String | Risk |
|---------|---------------|------|
| RSA private key | `-----BEGIN RSA PRIVATE KEY-----` | CRITICAL |
| EC private key | `-----BEGIN EC PRIVATE KEY-----` | CRITICAL |
| PKCS8 private key | `-----BEGIN PRIVATE KEY-----` | CRITICAL |
| PGP private key | `-----BEGIN PGP PRIVATE KEY BLOCK-----` | CRITICAL |
| Certificate + key bundle | `-----BEGIN CERTIFICATE-----` with adjacent key | HIGH |

### Cloud Provider Credentials

| Provider | Pattern | Example |
|----------|---------|---------|
| AWS Access Key | `AKIA[0-9A-Z]{16}` | `AKIAIOSFODNN7EXAMPLE` |
| AWS Secret Key | 40-char alphanumeric in variable named `secret` | — |
| GCP Service Account JSON | `"type": "service_account"` in JSON | — |
| GCP API Key | `AIza[0-9A-Za-z-_]{35}` | — |
| Azure Storage Key | 88-char base64 ending `==` in storage context | — |

### Source Control & CI/CD

| Service | Pattern |
|---------|---------|
| GitHub token | `ghp_[a-zA-Z0-9]{36}` (PAT), `ghs_` (app), `github_pat_` (fine-grained) |
| GitLab PAT | `glpat-[a-zA-Z0-9-]{20}` |
| CircleCI token | `[0-9a-f]{40}` in CircleCI context |
| Travis CI | `travis` + 22-char base64 |

### Payment & Communication APIs

| Service | Pattern | Risk |
|---------|---------|------|
| Stripe secret | `sk_live_[a-zA-Z0-9]{24,}` | CRITICAL |
| Stripe publishable | `pk_live_[a-zA-Z0-9]{24,}` | LOW (public key) |
| Twilio | `SK[a-zA-Z0-9]{32}` | HIGH |
| SendGrid | `SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}` | HIGH |
| Slack token | `xox[baprs]-[a-zA-Z0-9-]+` | HIGH |
| Slack webhook | `https://hooks.slack.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+` | HIGH |
| Mailgun | `key-[a-z0-9]{32}` | HIGH |

### Application-Level Secrets

| Type | Variable Name Patterns | Risk |
|------|----------------------|------|
| JWT signing key | `jwt.secret`, `JWT_SECRET`, `jwtKey`, `signingKey` | CRITICAL |
| OAuth client secret | `client_secret`, `oauth.secret`, `clientSecret` | CRITICAL |
| Encryption key | `encryptionKey`, `aes.key`, `secretKey` | CRITICAL |
| Database password | `db.password`, `datasource.password`, `DB_PASS` | HIGH |
| SMTP password | `mail.password`, `smtp.password` | MEDIUM |
| API key (generic) | `api.key`, `apiKey`, `API_KEY` | HIGH |
| Session secret | `session.secret`, `SESSION_SECRET` | CRITICAL |

## Entropy-Based Detection

High-entropy strings in credential-named variables should be flagged even without a known prefix:

```
# Entropy calculation: Shannon entropy > 4.5 bits/character for 20+ char strings
# Tools: trufflehog, gitleaks, detect-secrets --list-all-plugins

# Common false-positive: encoded URLs, UUIDs (low entropy per char)
# Genuine secrets: random hex, random base64 (high entropy)

# Red flag: any of these variable names containing a 20+ char non-dictionary value:
secret, password, passwd, pwd, token, key, secret_key, private_key,
api_key, auth_token, access_token, credential, credentials
```

## Safe Patterns (Do NOT Report)

| Pattern | Reason |
|---------|--------|
| `password = "CHANGEME"` | Placeholder — not a real credential |
| `secret = "test"` | Test value — too short |
| `apiKey = "your-api-key-here"` | Template placeholder |
| `token = "{{TOKEN}}"` | Template variable |
| `@Value("${jwt.secret}")` | External reference — credential is external |
| `System.getenv("DB_PASSWORD")` | Runtime environment variable |
| `secretsManager.getSecret("mySecret")` | Secrets manager lookup |
| Value in `src/test/` with clearly mock context | Test-only scope |
| Value shorter than 8 characters | Too short to be a real production secret |

## Git History Check

Secrets removed from current HEAD may still exist in git history:

```bash
# Search all commits for patterns
git log --all --oneline | head -20
git log -p --all -- "*.properties" | grep -i "password\|secret\|token"

# Recommended tools
trufflehog git file://. --since-commit HEAD~100
gitleaks detect --source . --log-opts="--all"
```

## Severity Assignment

| Condition | Severity |
|-----------|---------|
| Private key (RSA/EC) committed | CRITICAL |
| Cloud provider credentials (AWS AKIA, GCP key) | CRITICAL |
| JWT signing key in source | CRITICAL |
| OAuth client secret | CRITICAL |
| Production database password | CRITICAL |
| API key for external service (payment, communication) | HIGH |
| SMTP / mail credentials | MEDIUM |
| Development/staging credentials clearly labeled | LOW |
| Test/mock value in test directory | INFO |

## Remediation Patterns

```java
// BEFORE (dangerous)
private static final String JWT_SECRET = "h4rdcod3dS3cr3t";

// AFTER (safe — Spring Boot)
@Value("${JWT_SECRET}")
private String jwtSecret;

// AFTER (safe — AWS Secrets Manager)
@Bean
public String jwtSecret(SecretsManagerClient client) {
    GetSecretValueResponse resp = client.getSecretValue(
        GetSecretValueRequest.builder().secretId("prod/app/jwt-secret").build());
    return resp.secretString();
}

// Key generation (for rotation)
// openssl rand -hex 32  → 256-bit random hex key
// new SecureRandom().ints(64, 0, 16).mapToObj(Integer::toHexString).collect(joining())
```

## Rotation Checklist

When a secret is confirmed hardcoded:
1. Rotate immediately — treat as compromised
2. Audit access logs for use of the compromised secret
3. Remove from current code + commit
4. Use `git filter-repo --path-glob '*.properties' --invert-paths` or `BFG Repo Cleaner` to scrub history
5. Notify security team if repo is/was public
