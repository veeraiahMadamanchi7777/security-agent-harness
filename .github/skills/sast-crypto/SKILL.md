# SKILL: sast-crypto — Weak Cryptography Detection

## Purpose

Identify weak or broken cryptographic algorithms, insecure key management, poor random number generation, and homemade crypto implementations in Java applications.

---

## Phase 1: Sink Discovery

### 1.1 — Weak Symmetric Encryption

```bash
# DES / 3DES (56-bit / 112-bit effective key — broken)
grep -rn '"DES"\|"DESede"\|"DES/\|"DESede/' --include="*.java"
grep -rn "Cipher\.getInstance.*DES\b\|Cipher\.getInstance.*3DES\|Cipher\.getInstance.*DESEDE" --include="*.java" -i

# RC2, RC4, Blowfish (deprecated/weak)
grep -rn '"RC2"\|"RC4"\|"ARCFOUR"\|"Blowfish"\b' --include="*.java"
grep -rn "Cipher\.getInstance.*RC4\|Cipher\.getInstance.*RC2\|Cipher\.getInstance.*Blowfish" --include="*.java" -i

# AES in ECB mode (leaks block patterns)
grep -rn '"AES"\b\|"AES/ECB' --include="*.java"
# AES without mode = ECB by default in Java

# AES-CBC without HMAC (padding oracle risk)
grep -rn '"AES/CBC\b' --include="*.java" | grep -v "GCM\|CCM\|AEAD"

# Short key sizes
grep -rn "KeyGenerator\.getInstance\|KeyPairGenerator\.getInstance" --include="*.java" -A3 | grep "init(1[0-9][0-9][^0-9]\|init([0-9][0-9][^0-9]"
# Flag any key init with < 128 bits (AES), < 2048 bits (RSA), < 256 bits (EC)
```

### 1.2 — Weak Hashing

```bash
# MD5 — broken for security purposes
grep -rn "MessageDigest\.getInstance.*MD5\|\"MD5\"\|DigestUtils\.md5\|md5Hex\b" --include="*.java" -i

# SHA-1 — deprecated for collision resistance
grep -rn 'MessageDigest\.getInstance.*"SHA-1"\|MessageDigest\.getInstance.*"SHA1"\|DigestUtils\.sha1\|"SHA-1"\b' --include="*.java" -i

# CRC32 used as hash/MAC (not cryptographic at all)
grep -rn "CRC32\b\|Adler32\b" --include="*.java" | grep -v "checksum\|zip\|gzip\|//\|test" -i

# PBKDF2 with too few iterations
grep -rn "PBKDF2\|PBEKeySpec\b" --include="*.java" -A5 | grep -A5 "iterationCount\|iterations\b" | grep "[0-9]\{1,4\}[^0-9]"
# Minimum safe iterations: 600,000 (OWASP 2023), flag anything under 100,000

# BCrypt with cost factor < 10
grep -rn "BCryptPasswordEncoder\|bcrypt\b" --include="*.java" | grep -v "//\|test"
grep -rn "BCryptPasswordEncoder(" --include="*.java" -A2 | grep "([0-9])\|([0-9], "
# Default is 10 — if explicit and < 10, flag
```

### 1.3 — Asymmetric Cryptography Issues

```bash
# RSA key size < 2048 bits
grep -rn "KeyPairGenerator\b" --include="*.java" -A5 | grep "initialize\|init\b" | grep "[0-9]\{1,3\}[^0-9]"
# Flag: 512, 1024, 1024-bit RSA

# RSA without OAEP padding (PKCS1v1.5 vulnerable to Bleichenbacher)
grep -rn '"RSA"\b\|"RSA/ECB/PKCS1Padding"\|"RSA/None/PKCS1Padding"' --include="*.java"

# EC with weak curve
grep -rn "secp192r1\|prime192v1\|sect163\|brainpoolP160" --include="*.java" -i

# DSA (deprecated in favor of ECDSA)
grep -rn '"DSA"\b\|KeyPairGenerator.*DSA' --include="*.java"
```

### 1.4 — Weak Random Number Generation

```bash
# java.util.Random — not cryptographically secure
grep -rn "new Random()\|new Random(\|Math\.random()\|Random\b.*new Random" --include="*.java" | grep -v "//\|test\|Test\|mock\|Mock"

# Random seeded with predictable value
grep -rn "new Random(\|setSeed(" --include="*.java" | grep "System\.currentTimeMillis\|nanoTime\|new Date()\|time\b"

# ThreadLocalRandom — also not secure
grep -rn "ThreadLocalRandom\.current()" --include="*.java" | grep "nextBytes\|nextInt.*token\|nextLong.*token\|session.*id" -i

# SecureRandom with weak algorithm (SHA1PRNG)
grep -rn 'SecureRandom\.getInstance.*"SHA1PRNG"' --include="*.java"

# SecureRandom seeded manually (can reduce entropy)
grep -rn "SecureRandom\b" --include="*.java" -A3 | grep "setSeed\b"
```

### 1.5 — Key Management Failures

```bash
# Hardcoded encryption keys
grep -rn "secretKey\s*=\s*\"\|encryptKey\s*=\s*\"\|aesKey\s*=\s*\"\|privateKey\s*=\s*\"\|ENCRYPTION_KEY\s*=" --include="*.java" --include="*.properties" --include="*.yml" -i

# Key derived from password without salt (ECB/low-entropy)
grep -rn "PBEKeySpec\b\|SecretKeyFactory\|PBKDF2WithHmacSHA" --include="*.java" -A10 | grep -v "salt\|getSalt\|SecureRandom"

# IV (Initialization Vector) hardcoded or zero
grep -rn "IvParameterSpec\b" --include="*.java" -B3 | grep "new byte\|{0,\|0x00\|\"\\\\0\|STATIC_IV\|IV ="

# IV reuse (same IV for multiple encryptions with same key — CBC specific)
grep -rn "IvParameterSpec\b" --include="*.java" -B10 | grep -B10 "static\b\|final\b\|STATIC\b"
```

### 1.6 — TLS / SSL Configuration

```bash
# SSLv3 / TLSv1.0 / TLSv1.1 enabled (deprecated protocols)
grep -rn "SSLv3\|TLSv1\b\|TLSv1\.0\|TLSv1\.1\|\"TLS1\"\|\"SSL\"" --include="*.java" --include="*.properties" --include="*.yml"

# All-trusting TrustManager (disables certificate verification)
grep -rn "X509TrustManager\b\|TrustManager\b" --include="*.java" -A10 | grep "checkClientTrusted\|checkServerTrusted\|getAcceptedIssuers" | grep "return null\|return new\|{}"

# Hostname verification disabled
grep -rn "HostnameVerifier\b\|ALLOW_ALL_HOSTNAME_VERIFIER\|NoopHostnameVerifier\|setHostnameVerifier.*return true" --include="*.java"
grep -rn "HttpsURLConnection\.setDefaultHostnameVerifier\|setHostnameVerifier" --include="*.java" -A3 | grep "true\|ALLOW\|Noop"

# SSLContext.getInstance("SSL") instead of TLS
grep -rn 'SSLContext\.getInstance.*"SSL"\b\|SSLContext\.getInstance.*"TLS"\b' --include="*.java"
```

### 1.7 — Homemade Crypto / XOR

```bash
# XOR-based "encryption" (trivially breakable)
grep -rn "XOR\b\|'\^'\|byte.*\^.*byte\|xorEncrypt\|xorDecrypt" --include="*.java" -i | grep -v "//\|test\|checksum\|CRC"

# Base64 used as "encryption"
grep -rn "Base64.*encod\|encodeToString\|base64.*encrypt" --include="*.java" -i | grep "encrypt\|secret\|password\|token" -i

# ROT13 / Caesar cipher
grep -rn "rot13\|caesar\|charAtOffset\|char.*+.*13" --include="*.java" -i
```

---

## Phase 2: Severity Assessment

| Issue | Severity |
|-------|---------|
| MD5/SHA1 for password hashing | CRITICAL |
| DES / RC4 for sensitive data encryption | HIGH |
| AES/ECB for sensitive data | HIGH |
| RSA PKCS1v1.5 padding (Bleichenbacher) | HIGH |
| `java.util.Random` for tokens/session IDs | HIGH |
| `Random` seeded with time | HIGH |
| All-trusting TrustManager (cert bypass) | CRITICAL |
| Hostname verification disabled | HIGH |
| Hardcoded encryption key | CRITICAL |
| Static/hardcoded IV | HIGH |
| TLS 1.0/1.1 still enabled | MEDIUM |
| BCrypt cost < 10 | MEDIUM |
| PBKDF2 < 100,000 iterations | MEDIUM |
| RSA < 2048 bits | HIGH |
| XOR/Base64 called "encryption" | HIGH |
| SHA1PRNG SecureRandom | MEDIUM |

---

## Finding Format

Follow the canonical format from `copilot-instructions.md`. Example:

```
### [CRITICAL] Weak Crypto — MD5 Used for Password Hashing

**ID:** CRYPTO-001
**File:** `src/main/java/com/example/UserService.java:78`
**CWE:** CWE-916 | **OWASP:** A02:2021-Cryptographic Failures
**CVSS (estimated):** 9.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
**Confidence:** High
**Skill:** `sast-crypto`

**Taint Path:**
`rawPassword` (caller-supplied) → `UserService.setPassword(rawPassword) (UserService.java:76)` → `MessageDigest.getInstance("MD5").digest(rawPassword.getBytes()) (UserService.java:78)` → stored as `passwordHash`

**Vulnerable Code:**
```java
// Line 76-80
public void setPassword(User user, String rawPassword) {
    MessageDigest md = MessageDigest.getInstance("MD5");
    byte[] hash = md.digest(rawPassword.getBytes());
    user.setPasswordHash(Base64.getEncoder().encodeToString(hash));
}
```

**Why Exploitable:**
MD5 is computationally trivial to reverse via precomputed rainbow tables. No salt means identical passwords produce identical hashes. Tools like hashcat crack MD5 at billions of hashes per second. Any database breach immediately exposes all user passwords.

**Proof-of-Concept:**
No HTTP request needed; password cracking after DB dump:
```
hashcat -a 0 -m 0 hashes.txt rockyou.txt
# MD5("password") = 5f4dcc3b5aa765d61d8327deb882cf99 — cracks in <1s
```

**Remediation:**
```java
@Autowired
private BCryptPasswordEncoder passwordEncoder;

public void setPassword(User user, String rawPassword) {
    user.setPasswordHash(passwordEncoder.encode(rawPassword));
}
```
Configure `BCryptPasswordEncoder` with strength ≥ 12 for new deployments.

**References:** https://cwe.mitre.org/data/definitions/916.html, OWASP A02:2021
```

JSONL line (append to `.github/sast-findings.jsonl`):
```json
{"id":"CRYPTO-001","skill":"sast-crypto","cwe":"CWE-916","owasp":"A02:2021-Cryptographic Failures","severity":"Critical","confidence":"High","file":"src/main/java/com/example/UserService.java","line":78,"method":"setPassword","class":"com.example.UserService","evidence":"MessageDigest md = MessageDigest.getInstance(\"MD5\");\nbyte[] hash = md.digest(rawPassword.getBytes());","sink":"MessageDigest.getInstance(\"MD5\")","source":"rawPassword parameter","taint_path":[],"sanitizer_present":false,"sanitizer_detail":"","remediation":"Replace with BCryptPasswordEncoder.encode(rawPassword) with strength >= 12","references":["https://cwe.mitre.org/data/definitions/916.html"],"false_positive_indicators":[],"duplicate_of":null}
```
