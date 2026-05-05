# SKILL: sast-dependency — Vulnerable Dependency Detection

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

Emit findings using `.github/schemas/finding.schema.json`.

Recommended CWE values:

- `CWE-1104` for use of unmaintained third-party components
- `CWE-937` for known vulnerable component use
- vulnerability-specific CWE when a reachable exploit path is confirmed

Example sink names:

- `pom.xml dependency`
- `Gradle dependency`
- `ObjectMapper.activateDefaultTyping()`
- `Log4j JndiLookup`

---

## Self-Contained Check

This skill runs independently and does not require Phase 1 context. Phase 1 context improves reachability scoring for web-exposed vulnerable features.
