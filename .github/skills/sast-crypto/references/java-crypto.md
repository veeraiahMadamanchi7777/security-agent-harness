# Java Weak Cryptography Reference — Algorithms, APIs & Safe Replacements

## Symmetric Encryption — Weak Algorithms

| Algorithm | Risk | Why Weak | Safe Replacement |
|-----------|------|----------|-----------------|
| DES | CRITICAL | 56-bit key — brute-forceable in hours | AES-256-GCM |
| 3DES / DESede | HIGH | 112-bit effective — Sweet32 birthday attack | AES-256-GCM |
| RC2 | CRITICAL | 40-128 bit key, broken | AES-256-GCM |
| RC4 | CRITICAL | Statistical biases, BEAST/NOMORE | AES-256-GCM |
| Blowfish | MEDIUM | 64-bit block — Sweet32 birthday attack | AES-256-GCM |
| AES/ECB | HIGH | Deterministic — patterns visible in ciphertext | AES/GCM/NoPadding |
| AES/CBC without HMAC | HIGH | Padding oracle attacks (POODLE, BEAST) | AES/GCM/NoPadding |
| AES/CBC with IV=0 | CRITICAL | First block predictable | AES/GCM with random IV |
| AES key < 128 bits | MEDIUM | Reduced security margin | AES-256 |

```java
// DANGEROUS — ECB mode
Cipher.getInstance("AES")              // defaults to AES/ECB/PKCS5Padding
Cipher.getInstance("AES/ECB/PKCS5Padding")

// DANGEROUS — DES
Cipher.getInstance("DES/CBC/PKCS5Padding")

// SAFE
Cipher.getInstance("AES/GCM/NoPadding")
// Always generate fresh IV: new byte[12]; secureRandom.nextBytes(iv)
// Prepend IV to ciphertext for decryption; never reuse IV with same key
```

## Hashing — Weak Algorithms

| Algorithm | Risk | Use Case Impact |
|-----------|------|----------------|
| MD5 | CRITICAL (passwords), HIGH (integrity) | Collision-prone; rainbow table crackable in seconds |
| SHA-1 | HIGH | Collision demonstrated (SHAttered 2017); deprecated by NIST |
| SHA-256 unsalted (passwords) | HIGH | Fast — GPU cracks billions/second |
| PBKDF2 < 100,000 iterations | MEDIUM | Below NIST SP 800-132 minimum |
| bcrypt cost < 10 | MEDIUM | Too fast on modern hardware |

```java
// DANGEROUS
MessageDigest.getInstance("MD5")
MessageDigest.getInstance("SHA-1")
MessageDigest.getInstance("SHA1")

// SAFE for passwords
// BCrypt (Spring Security)
new BCryptPasswordEncoder(12).encode(rawPassword)
// Argon2
Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8().encode(rawPassword)
// PBKDF2 (raw)
new PBKDF2WithHmacSHA512().generate(password, salt, 600_000, 256)

// SAFE for data integrity (non-password)
MessageDigest.getInstance("SHA-256")   // acceptable for checksums, not passwords
MessageDigest.getInstance("SHA-512")
```

## Asymmetric — Key Size & Padding

| Config | Risk | Notes |
|--------|------|-------|
| RSA < 2048 bits | HIGH | Factorable — NIST requires ≥ 2048 |
| RSA 1024 bits | CRITICAL | Factorable by nation-state actors |
| RSA PKCS1v1.5 padding | HIGH | Bleichenbacher oracle attack |
| EC curve `secp112r1` / `sect113r1` | HIGH | < 128-bit security |
| EC curve `secp160r1` | MEDIUM | < 160-bit — too small |
| DSA < 2048 bits | HIGH | Same key-size rules as RSA |

```java
// DANGEROUS
KeyPairGenerator.getInstance("RSA").initialize(1024)
Cipher.getInstance("RSA/ECB/PKCS1Padding")

// SAFE
KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
kpg.initialize(4096);  // 2048 minimum; 4096 for long-lived keys
Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")

// SAFE (Elliptic Curve)
KeyPairGenerator.getInstance("EC").initialize(new ECGenParameterSpec("secp256r1"))
```

## Insecure Randomness

| API | Risk | Notes |
|-----|------|-------|
| `java.util.Random` | CRITICAL | Predictable — linear congruential generator |
| `Math.random()` | CRITICAL | Wraps `java.util.Random` |
| `new Random(seed)` | CRITICAL | Fixed seed — fully deterministic |
| `ThreadLocalRandom` | HIGH | Designed for performance, not security |
| `SecureRandom` with `SHA1PRNG` | MEDIUM | Platform-dependent; prefer default |

```java
// DANGEROUS
new Random().nextInt()
Math.random()

// SAFE
SecureRandom sr = new SecureRandom();
byte[] token = new byte[32];
sr.nextBytes(token);
```

## Key Management Issues

| Pattern | Risk | Notes |
|---------|------|-------|
| Hardcoded key `byte[] key = "hardcoded".getBytes()` | CRITICAL | Key in source/binary |
| Zero IV `new byte[16]` passed to GCM | CRITICAL | IV must be unique per encryption |
| Reused IV with same key (counter starting at 0) | CRITICAL | GCM security collapses |
| Key derived from password with MD5 | HIGH | Weak KDF |
| Key stored in `application.properties` | HIGH | Committed to version control |

## TLS/SSL Misconfigurations

| Config | Risk | Notes |
|--------|------|-------|
| `SSLContext.getInstance("SSL")` | CRITICAL | Enables SSLv3 — POODLE |
| `SSLContext.getInstance("TLSv1")` | HIGH | TLS 1.0 deprecated, BEAST |
| `SSLContext.getInstance("TLSv1.1")` | HIGH | Deprecated; POODLE variant |
| `TrustAllX509TrustManager` | CRITICAL | Disables certificate validation entirely |
| `setHostnameVerifier((h,s) -> true)` | CRITICAL | Disables hostname verification |
| `HttpsURLConnection.setDefaultHostnameVerifier(...)` with always-true | CRITICAL | Global bypass |

```java
// DANGEROUS — disables all TLS verification
TrustManager[] trustAllCerts = new TrustManager[]{
    new X509TrustManager() {
        public void checkClientTrusted(X509Certificate[] c, String a) {}
        public void checkServerTrusted(X509Certificate[] c, String a) {}
        public X509Certificate[] getAcceptedIssuers() { return null; }
    }
};

// SAFE — use TLSv1.2 or TLSv1.3 minimum
SSLContext ctx = SSLContext.getInstance("TLSv1.3");
ctx.init(null, null, null);  // use default trust store

// SAFE — configure RestTemplate with TLS 1.2+
SSLContext sslContext = SSLContextBuilder.create()
    .setProtocol("TLSv1.3")
    .build();
```

## Safe Algorithm Reference (Quick Table)

| Use Case | Recommended | Minimum Acceptable |
|----------|------------|-------------------|
| Symmetric encryption | AES-256-GCM | AES-128-GCM |
| Password hashing | Argon2id, bcrypt (cost≥12) | PBKDF2-SHA512 (600k iters) |
| Data integrity / HMAC | HMAC-SHA-256 | HMAC-SHA-256 |
| Digital signature | RSA-4096-OAEP or ECDSA P-256 | RSA-2048-OAEP |
| Key exchange | ECDH P-256 or X25519 | DH 2048-bit |
| Random tokens | `SecureRandom` 256 bits | `SecureRandom` 128 bits |
| TLS | TLS 1.3 | TLS 1.2 |
