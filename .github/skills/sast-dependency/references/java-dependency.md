# Java Vulnerable Dependency Reference — CVE Families, Versions & Reachability

## Critical Vulnerability Families

### Log4j (Log4Shell)

| Artifact | Vulnerable Versions | CVE | Fix |
|----------|-------------------|-----|-----|
| `log4j-core` | 2.0-beta9 – 2.14.1 | CVE-2021-44228 (CVSS 10.0) | ≥ 2.15.0 |
| `log4j-core` | 2.15.0 | CVE-2021-45046 (CVSS 9.0) | ≥ 2.16.0 |
| `log4j-core` | < 2.17.1 | CVE-2021-45105 (DoS) | ≥ 2.17.1 |
| `log4j-core` | < 2.17.1 | CVE-2021-44832 (CVSS 6.6) | ≥ 2.17.1 |
| `log4j` (1.x) | All 1.x | CVE-2019-17571, multiple | Migrate to 2.x |

**Reachability:** Any call to `log.debug/info/warn/error(userControlledString)` where JNDI lookup pattern `${jndi:...}` reaches a logger. Also triggered by log4j 1.x `SocketServer` or `JMSAppender`.

### Spring Framework

| Artifact | Vulnerable Versions | CVE | Fix |
|----------|-------------------|-----|-----|
| `spring-webmvc` / `spring-webflux` | 5.3.0–5.3.17, 5.2.0–5.2.19 | CVE-2022-22965 Spring4Shell (CVSS 9.8) | ≥ 5.3.18 |
| `spring-core` | < 5.3.20, < 5.2.22 | CVE-2022-22950 DoS | ≥ 5.3.20 |
| `spring-security` | < 5.6.3, < 5.5.6 | CVE-2022-22978 (auth bypass) | ≥ 5.6.3 |
| `spring-security` | < 5.7.5, < 5.6.9 | CVE-2022-31692 (forward/include auth bypass) | ≥ 5.7.5 |

**Spring4Shell reachability:** Requires JDK 9+, Tomcat as servlet container, `spring-webmvc` on classpath, and `@RequestMapping` with `@ModelAttribute` or data binding.

### Apache Struts

| Artifact | Vulnerable Versions | CVE | Fix |
|----------|-------------------|-----|-----|
| `struts2-core` | 2.3.5–2.3.31, 2.5–2.5.10 | CVE-2017-5638 OGNL injection (CVSS 10.0) | ≥ 2.3.32 / 2.5.10.1 |
| `struts2-core` | 2.0.0–2.3.15 | CVE-2013-2251 | ≥ 2.3.15.1 |
| `struts2-core` | < 2.5.33 | CVE-2023-50164 (file upload path traversal) | ≥ 2.5.33 |

### Apache Shiro

| Artifact | Vulnerable Versions | CVE | Fix |
|----------|-------------------|-----|-----|
| `shiro-core` | < 1.7.0 | CVE-2020-17523 (auth bypass via semicolon) | ≥ 1.7.0 |
| `shiro-core` | < 1.6.0 | CVE-2020-11989 (auth bypass) | ≥ 1.6.0 |
| `shiro-core` | < 1.13.0 | CVE-2023-34478 (path traversal bypass) | ≥ 1.13.0 |

**Reachability:** Shiro auth bypass requires Spring MVC or similar framework where URL pattern matching differs from Shiro's pattern matching (e.g., `/admin/` vs `/admin`).

### XStream

| Artifact | Vulnerable Versions | CVE | Fix |
|----------|-------------------|-----|-----|
| `xstream` | < 1.4.18 | CVE-2021-39139 through CVE-2021-39154 (RCE) | ≥ 1.4.18 |
| `xstream` | < 1.4.20 | CVE-2022-40151, CVE-2022-41966 (DoS) | ≥ 1.4.20 |

**Reachability:** `new XStream().fromXML(userInput)` without security framework applied.

### Jackson Databind

| Artifact | Vulnerable Versions | CVE | Impact |
|----------|-------------------|-----|--------|
| `jackson-databind` | < 2.13.4.2 | CVE-2022-42003, CVE-2022-42004 (DoS) | ≥ 2.13.4.2 |
| `jackson-databind` | < 2.9.10.8 | Multiple RCE via polymorphic typing | ≥ 2.9.10.8 |

**Reachability:** RCE requires `enableDefaultTyping()` — check for this explicit call.

### Commons Collections

| Artifact | Vulnerable Versions | CVE | Fix |
|----------|-------------------|-----|-----|
| `commons-collections` | 3.0–3.2.1 | CVE-2015-6420, CVE-2015-7501 | ≥ 3.2.2 |
| `commons-collections4` | 4.0 | Same gadget chains | ≥ 4.1 |

**Reachability:** Only via Java deserialization (`ObjectInputStream`) or XStream/JBoss deserialization gadgets. Presence alone is not sufficient — confirm deserialization surface.

### SnakeYAML

| Artifact | Vulnerable Versions | CVE | Fix |
|----------|-------------------|-----|-----|
| `snakeyaml` | < 1.31 | CVE-2022-25857 (DoS) | ≥ 1.31 |
| `snakeyaml` | < 2.0 | CVE-2022-1471 (RCE via `Yaml.load()`) | ≥ 2.0 |

**Reachability:** RCE requires `new Yaml().load(userInput)` — not `loadAs()` with a safe type.

### Netty

| Artifact | Vulnerable Versions | CVE | Fix |
|----------|-------------------|-----|-----|
| `netty-codec-http` | < 4.1.77.Final | CVE-2022-24823 (temp file local info disclosure) | ≥ 4.1.77 |
| `netty-handler` | < 4.1.86.Final | CVE-2022-41915 (HTTP request smuggling) | ≥ 4.1.86 |

## Reachability Assessment Guide

| Finding Level | Criteria |
|--------------|---------|
| CRITICAL | Vulnerable version + vulnerable API called in application code + user input reaches call |
| HIGH | Vulnerable version + vulnerable API callable via endpoint (may need specific conditions) |
| MEDIUM | Vulnerable version present + feature used but taint path to user input unclear |
| LOW | Vulnerable version present + no evidence vulnerable feature is used |
| INFO | Transitive dependency only + no direct use in application code |

## Dependency Inventory Grep Patterns

```bash
# Maven — find groupId:artifactId:version
grep -n "log4j\|commons-collections\|xstream\|snakeyaml\|shiro\|struts" pom.xml

# Gradle
grep -n "log4j\|commons-collections\|xstream\|snakeyaml\|shiro\|struts" build.gradle build.gradle.kts

# Effective POM (resolves transitive deps)
mvn dependency:tree -Dincludes=org.apache.logging.log4j:*
mvn dependency:tree -Dincludes=commons-collections:*
```

## Version Extraction Pattern

```bash
# From Maven coordinates in pom.xml
grep -A2 "<artifactId>log4j-core</artifactId>" pom.xml | grep "<version>"

# From compiled JAR manifest (if source not available)
unzip -p app.jar META-INF/MANIFEST.MF | grep "Implementation-Version"
```
