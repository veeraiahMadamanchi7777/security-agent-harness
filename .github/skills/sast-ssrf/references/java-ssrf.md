# Java SSRF Reference — HTTP Clients, Bypass Patterns & Cloud Targets

## HTTP Client Sinks

| API | Risk | Notes |
|-----|------|-------|
| `RestTemplate.getForObject(url, ...)` | CRITICAL | URL from user input |
| `RestTemplate.postForObject(url, ...)` | CRITICAL | URL from user input |
| `RestTemplate.exchange(url, ...)` | CRITICAL | URL from user input |
| `WebClient.create(url).get().retrieve()` | CRITICAL | Reactive HTTP client |
| `HttpURLConnection.openConnection()` | CRITICAL | `new URL(userInput).openConnection()` |
| `URL.openStream()` | CRITICAL | Fetches arbitrary URL |
| `HttpClient.send(HttpRequest.newBuilder(uri))` | CRITICAL | Java 11+ client |
| `OkHttpClient.newCall(new Request.Builder().url(url))` | CRITICAL | OkHttp |
| `Feign` client with dynamic URL | HIGH | `@RequestLine` with runtime URL |
| `Retrofit` with dynamic `@Url` parameter | HIGH | Dynamic URL injection |
| `CloseableHttpClient.execute(new HttpGet(url))` | CRITICAL | Apache HttpClient |
| `socket.connect(new InetSocketAddress(host, port))` | HIGH | TCP-level SSRF |
| `InetAddress.getByName(host)` | MEDIUM | DNS lookup — blind SSRF signal |
| `InitialContext.lookup(url)` | CRITICAL | JNDI — triggers Log4Shell |

## Safe Patterns (Not Findings)

| Pattern | Why Safe |
|---------|---------|
| URL built entirely from application constants | No user input in URL |
| Host extracted from validated JWT claim and matched to allowlist | Trust boundary correct |
| `allowedHosts.contains(uri.getHost())` before HTTP call | Allowlist enforced |
| URL parsed, host checked against `InetAddress` private-range check + allowlist | Defense-in-depth |

## Bypass Techniques (for Blocklist Evasion Assessment)

| Bypass | Example | Notes |
|--------|---------|-------|
| Protocol-relative | `//169.254.169.254/` | Some clients resolve without scheme |
| IPv6 localhost | `http://[::1]/` | Bypasses `127.0.0.1` string check |
| IPv6 mapped | `http://[::ffff:169.254.169.254]/` | Bypasses dotted-decimal check |
| Decimal IP | `http://2130706433/` | `127.0.0.1` as 32-bit integer |
| Hex IP | `http://0x7f000001/` | `127.0.0.1` in hex |
| Octal IP | `http://0177.0.0.01/` | Octal notation |
| DNS rebinding | Attacker DNS returns public IP for validation, then private IP for request | Splits validation from fetch |
| URL encoding | `http://169.254.169.%32%35%34/` | Percent-encoded octets |
| Open redirect chain | `http://trusted.com/redirect?url=http://169.254.169.254/` | If client follows redirects |
| `file://` scheme | `file:///etc/passwd` | Local file read via SSRF |
| `gopher://` scheme | `gopher://localhost:6379/_SET key val` | Redis, memcached command injection |
| `dict://` scheme | `dict://localhost:11211/` | Memcached |

## Cloud Metadata Endpoints

| Provider | URL | Sensitive Data |
|----------|-----|---------------|
| AWS IMDSv1 | `http://169.254.169.254/latest/meta-data/` | IAM credentials, AMI ID |
| AWS IAM creds | `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` | `AccessKeyId`, `SecretAccessKey`, `Token` |
| AWS IMDSv2 | Requires `PUT` with `X-aws-ec2-metadata-token-ttl-seconds` header | Harder to hit but not immune |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` | Requires `Metadata-Flavor: Google` header |
| Azure | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` | Requires `Metadata: true` header |
| DigitalOcean | `http://169.254.169.254/metadata/v1/` | SSH keys, user-data |
| Kubernetes API | `https://kubernetes.default.svc/api/v1/` | Pod service account token |
| Docker daemon | `http://localhost:2375/v1.40/containers/json` | Container metadata, commands |

## Effective Remediation Pattern

```java
// Step 1: Parse and validate scheme
URI uri = URI.create(userSuppliedUrl);
if (!Set.of("http", "https").contains(uri.getScheme())) {
    throw new SecurityException("Disallowed scheme: " + uri.getScheme());
}

// Step 2: Allowlist host
if (!ALLOWED_DOMAINS.stream().anyMatch(d -> uri.getHost().endsWith(d))) {
    throw new SecurityException("Host not in allowlist");
}

// Step 3: Resolve IP and check for private ranges (post-DNS)
InetAddress addr = InetAddress.getByName(uri.getHost());
if (addr.isLoopbackAddress() || addr.isSiteLocalAddress()
        || addr.isLinkLocalAddress() || addr.isAnyLocalAddress()) {
    throw new SecurityException("Private/loopback address disallowed");
}

// Step 4: Disable redirects in the HTTP client
// RestTemplate: configure SimpleClientHttpRequestFactory.setFollowRedirects(false)
// OkHttp: .followRedirects(false).followSslRedirects(false)
```

## False Positives

| Pattern | Reason to Exclude |
|---------|------------------|
| URL assembled entirely from `@Value` config properties | No user input reaches URL |
| URL comes from database field written only by admins | Trust boundary established by access control |
| Fixed base URL with only query params from user | Host is static; only path injection risk |
