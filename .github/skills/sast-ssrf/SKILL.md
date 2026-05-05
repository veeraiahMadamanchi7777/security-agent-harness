# SKILL: sast-ssrf — Server-Side Request Forgery Detection

## Purpose

Identify code paths where attacker-supplied URLs, hostnames, or IP addresses cause the server to make outbound HTTP/TCP requests, potentially reaching internal services, cloud metadata APIs, or localhost-bound services.

---

## Phase 1: Sink Discovery

### 1.1 — HTTP Client Libraries

```bash
# Spring RestTemplate
grep -rn "RestTemplate\b" --include="*.java" -l
grep -rn "restTemplate\.getForObject\|restTemplate\.getForEntity\|restTemplate\.postForObject\|restTemplate\.exchange\|restTemplate\.execute" --include="*.java"

# Spring WebClient (reactive)
grep -rn "WebClient\b\|webClient\b" --include="*.java" -l
grep -rn "WebClient\.create\|\.uri(\|\.get()\|\.post()\|\.put()\|\.delete()" --include="*.java"

# Apache HttpClient / CloseableHttpClient
grep -rn "CloseableHttpClient\|HttpClientBuilder\|HttpGet\b\|HttpPost\b\|HttpPut\b\|HttpDelete\b" --include="*.java"
grep -rn "HttpClient\.execute\|httpClient\.execute\|CloseableHttpResponse" --include="*.java"

# OkHttp
grep -rn "OkHttpClient\b\|okhttp3\b" --include="*.java" -l
grep -rn "Request\.Builder\|\.url(\|\.build()\|client\.newCall" --include="*.java"

# Java standard library
grep -rn "new URL(\|URL\.openConnection\|HttpURLConnection\b\|openStream()\b" --include="*.java"
grep -rn "URI\.create(\|new URI(" --include="*.java"

# Feign / OpenFeign
grep -rn "@FeignClient\|FeignClient\b" --include="*.java" -A5

# Retrofit
grep -rn "Retrofit\.Builder\|retrofit2\b" --include="*.java" -l
```

### 1.2 — DNS / Socket Lookups

```bash
# Direct socket connection to user-controlled host/port
grep -rn "new Socket(\|ServerSocket\b\|InetAddress\|InetSocketAddress" --include="*.java" -B5 | grep -B5 "getParameter\|@RequestParam\|@PathVariable\|@RequestBody"

# DNS resolution with user input
grep -rn "InetAddress\.getByName(\|InetAddress\.getAllByName(" --include="*.java"

# SMTP / LDAP / JDBC with dynamic host
grep -rn "new Properties()\|smtp\b.*host\|ldap://\|jdbc://" --include="*.java" | grep -v "//\|application\.\|\.properties"
```

### 1.3 — Cloud / Metadata API Risk

```bash
# AWS SDK — any call where endpoint is user-controlled
grep -rn "endpointOverride\|withEndpointConfiguration\|AwsClientBuilder.*endpoint" --include="*.java"

# File:// scheme — SSRF to local filesystem
grep -rn '"file://"\|file://\|"classpath://"\|Protocol.*file' --include="*.java"

# JNDI-based SSRF
grep -rn "InitialContext\b\|ldap://\|rmi://\|iiop://\|dns://" --include="*.java"
```

---

## Phase 2: Taint Analysis

For each HTTP client call, trace the URL/hostname back to its source:

```bash
# URL/host constructed from request parameter
grep -rn "\.getForObject(\|\.exchange(\|WebClient.*uri(\|new URL(" --include="*.java" -B15 | grep -B15 "getParameter\|@RequestParam\|@PathVariable\|@RequestBody\|request\."

# URL concatenated from user input
grep -rn '"http://"\s*+\|"https://"\s*+' --include="*.java" -B5 | grep -B5 "getParameter\|param\|request"

# Dynamic base URL
grep -rn "baseUrl\s*=\s*\|endpoint\s*=\s*\|targetUrl\s*=\s*" --include="*.java" | grep "getParameter\|param\b\|getHeader\|@RequestParam"
```

**Key questions:**
1. Is the full URL attacker-controlled (worst case)?
2. Is only the path attacker-controlled but host is fixed (lower risk, still a finding)?
3. Is only a query parameter appended to a fixed URL (URL injection, MEDIUM)?
4. Is the scheme attacker-controlled (`file://`, `dict://`, `gopher://`)?

---

## Phase 3: Scheme & Redirect Bypass Patterns

### 3.1 — Redirect Following

```bash
# Check if HTTP client follows redirects (default: yes for most clients)
grep -rn "setFollowRedirects\|followRedirects\|RedirectStrategy\|setRedirectsEnabled\|disableRedirectHandling" --include="*.java"
# If not disabled: attacker can redirect from allowed host to internal host
```

### 3.2 — DNS Rebinding Risk

If the application validates a hostname via DNS before making the request, and the DNS record TTL is 0, an attacker can rebind the hostname to `127.0.0.1` between validation and connection. This is a timing attack — note it as an SSRF amplifier.

### 3.3 — URL Parsing Confusion

```bash
# Use of different URL parsers (java.net.URL vs. URI vs. Apache URIBuilder)
grep -rn "new URL(\|URI\.create(\|URIBuilder\b\|new URIBuilder(" --include="*.java"
# URL(String) on attacker-controlled input — check if scheme is validated
```

Common bypasses:
- `http://allowed.com@attacker.com/` — host is `attacker.com`
- `http://attacker.com#allowed.com` — fragment trick (browser only, but some parsers split wrong)
- `http://127.0.0.1` vs. `http://localhost` — IP vs. name allowlist bypass
- `http://0x7f000001` (hex IP) — bypass IP allowlists
- `http://[::1]` (IPv6 localhost)

---

## Phase 4: Defense Detection

Look for defenses — if present, reduce severity:

```bash
# Allowlist-based URL validation
grep -rn "allowedHosts\|allowedDomains\|allowedUrls\|whitelist.*url\|urlWhitelist\|safeUrls" --include="*.java" -i

# Blocklist-based (weaker, bypassable — still note)
grep -rn "127\.0\.0\.1\|localhost\|169\.254\|10\.\|192\.168\|172\.16" --include="*.java" | grep -v "//\|test\|Test\|application\."

# IP address parsing before request
grep -rn "InetAddress\.getByName\|isLoopbackAddress\|isSiteLocalAddress\|isLinkLocalAddress\|isAnyLocalAddress" --include="*.java"
```

**Allowlist check:**
```java
// Proper: exact domain matching
URI uri = URI.create(userInput);
if (!ALLOWED_HOSTS.contains(uri.getHost())) throw new SecurityException();
```

---

## Phase 5: Severity Assessment

| Condition | Severity |
|-----------|---------|
| Full URL user-controlled, no validation | CRITICAL |
| Full URL user-controlled, blocklist only | HIGH (blocklist bypasses exist) |
| Hostname user-controlled, path fixed | HIGH |
| Path appended to fixed host, URL-encoded slash bypass possible | MEDIUM |
| Scheme controllable (`file://`, `gopher://`) | CRITICAL |
| Redirect following to internal via open redirect | HIGH |
| Cloud metadata reachable (no IMDSv2) | CRITICAL |
| Internal endpoint discoverable via timing | MEDIUM |

---

## Cloud Metadata SSRF Targets

If SSRF is confirmed, the most impactful target is the cloud metadata API:

| Cloud | Metadata URL |
|-------|-------------|
| AWS | `http://169.254.169.254/latest/meta-data/` |
| AWS IMDSv2 | Same URL but requires `PUT` with token first |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` |
| Azure | `http://169.254.169.254/metadata/instance` |
| DigitalOcean | `http://169.254.169.254/metadata/v1/` |

AWS credentials at: `http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}`

---

## Finding Format

Follow the canonical format from `copilot-instructions.md`. Example:

```
### [CRITICAL] SSRF — Webhook URL Fully Attacker-Controlled

**ID:** SSRF-001
**File:** `src/main/java/com/example/WebhookService.java:29`
**CWE:** CWE-918 | **OWASP:** A10:2021-Server-Side Request Forgery
**CVSS (estimated):** 9.1 (AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N)
**Confidence:** High
**Skill:** `sast-ssrf`

**Taint Path:**
`POST /api/webhooks {"url":"..."}` → `WebhookController.register(url) (WebhookController.java:18)` → `WebhookService.testWebhook(url) (WebhookService.java:27)` → `restTemplate.getForObject(url) (WebhookService.java:29)` — no URL validation

**Vulnerable Code:**
```java
public void testWebhook(String url) {
    // No URL validation performed
    restTemplate.getForObject(url, String.class);
}
```

**Why Exploitable:**
`url` is passed from the request body directly to `RestTemplate.getForObject` with no host, scheme, or IP range validation. An attacker supplies an internal URL (e.g., AWS IMDSv1) to read cloud credentials or probe internal services inaccessible from the public internet.

**Proof-of-Concept:**
```http
POST /api/webhooks HTTP/1.1
Authorization: Bearer <any_user_token>
Content-Type: application/json

{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-role"}
```
Returns AWS instance metadata with temporary IAM credentials.

**Remediation:**
Use an allowlist, not a blocklist (blocklists are bypassable via IPv6, hex IPs, DNS rebinding):
```java
URI uri = URI.create(url);
if (!ALLOWED_DOMAINS.stream().anyMatch(d -> uri.getHost().endsWith(d))) {
    throw new SecurityException("SSRF: host not in allowlist");
}
InetAddress addr = InetAddress.getByName(uri.getHost());
if (addr.isLoopbackAddress() || addr.isSiteLocalAddress() || addr.isLinkLocalAddress()) {
    throw new SecurityException("SSRF: private/loopback address");
}
restTemplate.getForObject(url, String.class);
```

**References:** https://cwe.mitre.org/data/definitions/918.html, OWASP A10:2021
```

JSONL line (append to `.github/sast-findings.jsonl`):
```json
{"id":"SSRF-001","skill":"sast-ssrf","cwe":"CWE-918","owasp":"A10:2021-Server-Side Request Forgery","severity":"Critical","confidence":"High","file":"src/main/java/com/example/WebhookService.java","line":29,"method":"testWebhook","class":"com.example.WebhookService","evidence":"restTemplate.getForObject(url, String.class);","sink":"RestTemplate.getForObject()","source":"POST body field \"url\"","taint_path":[{"step":"WebhookController.register passes url to service","file":"src/main/java/com/example/WebhookController.java","line":18}],"sanitizer_present":false,"sanitizer_detail":"","remediation":"Validate url against an allowlist of permitted hostnames before passing to RestTemplate","references":["https://cwe.mitre.org/data/definitions/918.html"],"false_positive_indicators":[],"duplicate_of":null}
```
