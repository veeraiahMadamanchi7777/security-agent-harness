# Java Sanitizer Patterns

Shared reference used by ALL Phase 2 skills. When any of these patterns appear between a taint source and a sink, set `sanitizer_present=true` and downgrade confidence.

**Important**: Finding a sanitizer does NOT suppress a finding. It reduces confidence and must be documented in `sanitizer_detail`. Some sanitizers are insufficient for their context.

---

## SQL-Specific Safe Patterns

### Parameterized Queries — These ARE safe (do not flag as SQLi)
- `PreparedStatement` with `?` placeholders: `conn.prepareStatement("SELECT ... WHERE id=?")` then `ps.setLong(1, id)`
- Spring Data `@Query` with `:param` named parameters or `?1` positional parameters
- MyBatis `#{}` notation (NOT `${}` — see unsafe section)
- JPA `CriteriaBuilder` API (type-safe query construction)
- jOOQ typed DSL
- QueryDSL typed predicates
- JPQL named parameters: `createQuery("FROM User WHERE id = :id").setParameter("id", id)`
- Spring Data method names (e.g., `findByUsername(String name)`) — no raw SQL

### Parameterized — BUT still scan
- `conn.prepareStatement(sql)` where `sql` is a variable (not a literal) — scan to see if `sql` contains concatenation
- `@Query(nativeQuery=true, value="...")` — safe only if no `+` concatenation in the value

### SQL UNSAFE — Do NOT credit as sanitizer
- `String.replace("'", "''")` — trivially bypassed with Unicode or encoding tricks
- `StringEscapeUtils.escapeSql()` — deprecated since Commons Lang 3, not reliable
- Manual regex filtering on SQL input
- `addBatch(String sql)` with concatenated string — still injectable

---

## Command Injection Safe Patterns

### Safe Forms
- `ProcessBuilder(List<String> args)` where no list element contains user input with shell metacharacters AND the first element is NOT `sh`/`bash`/`cmd`
- `Runtime.exec(String[] cmdArray)` array form — safer but NOT safe if any element is user-controlled and a shell interpreter is in position 0

### UNSAFE — Do NOT credit as sanitizer
- Even array form is unsafe if: `{"/bin/sh", "-c", userInput}` — shell is invoked, full injection possible
- Allowlist check on a URL or filename does NOT protect against shell metacharacters in a different parameter

---

## Path Traversal Safe Patterns

These ARE effective sanitizers for path traversal:
- `Paths.get(baseDir).resolve(userInput).normalize().startsWith(Paths.get(baseDir))` — canonical path containment check
- `new File(baseDir, userInput).getCanonicalPath().startsWith(canonicalBase)` — canonical path check
- `FilenameUtils.getName(userInput)` (Apache Commons IO) — strips all path components, returns filename only
- Allowlist of permitted filenames (exact match only)

### Partially Safe (reduce to Medium, not eliminate)
- `userInput.contains("..")` check — can be bypassed with URL encoding (`%2e%2e`) or null bytes on some systems
- `!userInput.startsWith("/")` check — relative path only, but `../` traversal still possible

---

## XML / XXE Safe Patterns

Full protection (confidence → Low / suppress if all three features set):
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setExpandEntityReferences(false);
```

For SAXParserFactory:
```java
SAXParserFactory spf = SAXParserFactory.newInstance();
spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

For XMLInputFactory (StAX):
```java
XMLInputFactory xif = XMLInputFactory.newFactory();
xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
```

### Partially Safe
- Setting only ONE of the above features — reduce to Medium (other attack vectors remain)
- `FEATURE_SECURE_PROCESSING` only — reduces but does not eliminate XXE risk

---

## Deserialization Safe Patterns

### Effective Mitigations
- `ObjectInputStream` with `ObjectInputFilter` (Java 9+) that allowlists permitted classes
- `ValidatingObjectInputStream` from Apache Commons IO with explicit `accept()` allowlist
- Not using Java native serialization — using JSON/XML/Protobuf instead (no `ObjectInputStream` = no gadget chain risk)
- Jackson with explicit `@JsonSubTypes` allowlist and `@JsonTypeInfo(use=Id.NAME)` — restricts polymorphic deserialization

### Ineffective / Partially Safe
- Jackson `FAIL_ON_UNKNOWN_PROPERTIES` — does NOT prevent type confusion attacks
- Jackson `enableDefaultTyping()` is UNSAFE (deprecated for this reason) — flag regardless
- Kryo without class registration — unsafe by default
- XStream without security framework configured — unsafe by default

---

## Redirect Safe Patterns

### Effective Sanitizers for Open Redirect
- Explicit allowlist check: `if (!ALLOWED_REDIRECT_URLS.contains(redirectUrl)) throw new IllegalArgumentException()`
- Same-host check: `URI.create(redirectUrl).getHost().equals(request.getServerName())`
- Relative path enforcement: `if (redirectUrl.startsWith("/") && !redirectUrl.startsWith("//"))` — partially safe

### Bypass Patterns (do NOT credit as sanitizer if these checks are used)
- `redirectUrl.startsWith("/")` without also checking `!redirectUrl.startsWith("//")` — `//evil.com` bypasses
- `!redirectUrl.contains("://")` — bypassed by `//evil.com` (protocol-relative)
- `redirectUrl.matches("[a-zA-Z0-9/]+")` without anchoring — may be bypassable

---

## CSRF Safe Patterns

### Effective (full CSRF protection)
- Spring Security CSRF filter active (default when `@EnableWebSecurity` is used and `.csrf()` is NOT `.disable()`'d)
- `CsrfTokenRepository` configured and in use
- `SameSite=Strict` or `SameSite=Lax` on session cookies
- Custom request header (e.g., `X-Requested-With`) checked server-side — effective because cross-origin requests cannot set custom headers

### Not Sufficient
- `.csrf().disable()` explicitly disables protection — flag
- Checking `Origin` header only — can be spoofed in some contexts
- CAPTCHA — prevents automated attacks but not same-origin exploitation

---

## Encoding / Output Sanitizers (XSS-adjacent)

| Library | Method | Context |
|---|---|---|
| OWASP Java Encoder | `Encode.forHtml(input)` | HTML body |
| OWASP Java Encoder | `Encode.forHtmlAttribute(input)` | HTML attribute |
| OWASP Java Encoder | `Encode.forJavaScript(input)` | JavaScript context |
| OWASP Java Encoder | `Encode.forUrl(input)` | URL parameter |
| Apache Commons Text | `StringEscapeUtils.escapeHtml4(input)` | HTML |
| Spring | `HtmlUtils.htmlEscape(input)` | HTML |
| Spring | `UriUtils.encode(input, charset)` | URL |

These do not affect SQL/RCE/XXE — they are output-side sanitizers relevant for template injection and open redirect.

---

## Input Validation (Partial Sanitizers)

These REDUCE attack surface but do NOT eliminate injection vulnerabilities:

| Pattern | Effect |
|---|---|
| `@Valid` / `@Validated` + JSR-303 annotations | Validates format (length, regex, @NotNull) — does NOT prevent SQLi if validated value is concatenated |
| `@Min(1) @Max(100)` on a numeric param | Constrains range — prevents some business logic attacks, reduces but doesn't eliminate numeric injection |
| `@Pattern(regexp="[a-zA-Z]+")` | Constrains characters — effective if regex is strict and anchored |
| `@Email` | Validates email format — not a security sanitizer |
| Length check `input.length() > 100` | Limits attack payload length — may prevent some exploits but not all |

**Rule**: `@Valid` alone reduces confidence by one level (e.g., High → Medium). It does NOT eliminate the finding.

---

## Cryptography Safe Patterns

### Safe Algorithms and Configurations
| Use case | Safe | Unsafe |
|---|---|---|
| Symmetric encryption | AES/GCM/NoPadding (128+ bit key) | DES, 3DES, RC4, AES/ECB |
| Asymmetric encryption | RSA/OAEP (2048+ bit) | RSA/PKCS1 (RSA/ECB/PKCS1Padding) |
| Password hashing | BCrypt, SCrypt, Argon2 | MD5, SHA-1, SHA-256 (unsalted) |
| Hashing (non-password) | SHA-256, SHA-3 | MD5, SHA-1 (for integrity/security) |
| Random numbers (security) | `SecureRandom` | `Random`, `Math.random()` |
| Key derivation | PBKDF2 ≥10,000 iterations | PBKDF2 <1,000 iterations |
| Message authentication | HMAC-SHA256 | CRC32, Adler-32 |

### Safe Usage Rules
- IV/nonce must be randomly generated for each encryption operation (never reuse with same key)
- Salt must be unique per password for password hashing
- Keys must be ≥128 bits for AES, ≥2048 bits for RSA
- `GCM` authentication tag must be verified before using decrypted data

---

## Sanitizer Confidence Degradation Rules

Apply these rules cumulatively:

| Sanitizer Found | Confidence Change | Reasoning |
|---|---|---|
| Parameterized SQL query | Eliminate finding | No injection possible |
| OWASP Java Encoder (correct context) | Eliminate finding | Encoding prevents injection |
| `ObjectInputFilter` allowlist | Eliminate finding | Gadget chains blocked |
| DTD disabled in XML parser | Eliminate XXE finding | External entities blocked |
| `@Valid` + strict `@Pattern` | High → Medium | Format validated but logic may still be injectable |
| `@Valid` with `@NotNull`/length only | High → Medium | Non-functional security validation |
| Input from admin-only endpoint | Any → Low | Requires admin compromise first |
| Input from internal service (not HTTP) | Any → Medium | Internal services may be compromised |
| User is authenticated | Severity -1 level | Auth reduces unauth → auth severity |
| Null check only | No change | Not a sanitizer |
| Logging of input | No change | Not a sanitizer |
| CAPTCHA | No change for code-level vulns | Doesn't affect server-side injection |
