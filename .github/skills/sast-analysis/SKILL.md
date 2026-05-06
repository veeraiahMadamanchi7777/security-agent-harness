---
name: sast-analysis
description: Map Java application architecture, entry points, trust boundaries, security controls, and data flows before vulnerability-specific review.
---

# SKILL: sast-analysis — Architecture Recon & Entry Point Mapping

## Purpose

Phase 1 of the security pipeline. Map the target Java application's attack surface before any vulnerability-specific analysis begins. Output a structured **Architecture Context Document** that Phase 2 skills consume to avoid redundant exploration and ensure complete coverage.

---

## Execution Steps

### Step 1 — Framework Detection

Identify the application framework(s) in use:

```
grep -r "spring-boot-starter\|spring-webmvc\|javax.ws.rs\|jakarta.ws.rs\|com.sun.jersey\|io.quarkus\|micronaut\|play.mvc" \
  --include="*.xml" --include="*.gradle" --include="*.gradle.kts" -l
```

Also check imports in Java source:
```
grep -rn "org.springframework.web\|javax.servlet\|jakarta.servlet\|org.jboss.resteasy" \
  --include="*.java" -l | head -30
```

Record: Spring MVC / Spring Boot / Spring WebFlux / JAX-RS (Jersey/RESTEasy/CXF) / Servlet raw / Play / Quarkus / Micronaut / Other.

---

### Step 2 — Entry Point Discovery

#### HTTP Entry Points

**Spring MVC / Spring Boot:**
```
grep -rn "@RestController\|@Controller\|@RequestMapping\|@GetMapping\|@PostMapping\|@PutMapping\|@DeleteMapping\|@PatchMapping" \
  --include="*.java" | grep -v "//.*@"
```

**JAX-RS:**
```
grep -rn "@Path\|@GET\|@POST\|@PUT\|@DELETE\|@PATCH\|@HEAD\|@OPTIONS" \
  --include="*.java" | grep -v "//.*@"
```

**Raw Servlets:**
```
grep -rn "extends HttpServlet\|implements Servlet\|doGet\|doPost\|doPut\|doDelete\|service(" \
  --include="*.java"
```

**WebSockets:**
```
grep -rn "@ServerEndpoint\|@OnMessage\|WebSocketHandler\|TextWebSocketHandler\|BinaryWebSocketHandler" \
  --include="*.java"
```

**GraphQL:**
```
grep -rn "@QueryMapping\|@MutationMapping\|@SchemaMapping\|GraphQLResolver\|@GraphQLQuery\|@GraphQLMutation" \
  --include="*.java"
```

**gRPC:**
```
grep -rn "extends.*Grpc\|StreamObserver\|onNext\|onCompleted" --include="*.java"
```

**Messaging (async attack surface):**
```
grep -rn "@RabbitListener\|@KafkaListener\|@JmsListener\|@SqsListener\|@EventListener\|@Async" \
  --include="*.java"
```

**Scheduled jobs (time-triggered, sometimes with elevated privilege):**
```
grep -rn "@Scheduled\|@Cron\|QuartzJobBean\|Job implements" --include="*.java"
```

For each entry point, record: **class**, **method**, **HTTP method + path pattern**, **authentication requirement** (see Step 5).

---

### Step 3 — Data Flow Source Identification

Identify how attacker-controlled data enters the application:

```
grep -rn "@RequestParam\|@PathVariable\|@RequestBody\|@RequestHeader\|@CookieValue\|@MatrixVariable\|@ModelAttribute\|@RequestPart" \
  --include="*.java"
```

```
grep -rn "request\.getParameter\|request\.getHeader\|request\.getCookies\|request\.getInputStream\|request\.getReader\|request\.getQueryString" \
  --include="*.java"
```

```
grep -rn "\.readValue\|\.readTree\|\.parseObject\|JAXB\.unmarshal\|XmlMapper\|ObjectMapper" \
  --include="*.java"
```

Record these as **taint sources** — Phase 2 skills will taint-track from here.

---

### Step 4 — Trust Boundary Mapping

**Authentication configuration:**
```
grep -rn "WebSecurityConfigurerAdapter\|SecurityFilterChain\|HttpSecurity\|authorizeRequests\|authorizeHttpRequests\|antMatchers\|requestMatchers\|permitAll\|authenticated\|hasRole\|hasAuthority" \
  --include="*.java"
```

**Filter chain:**
```
grep -rn "implements Filter\|extends OncePerRequestFilter\|addFilterBefore\|addFilterAfter\|addFilterAt" \
  --include="*.java"
```

**CORS:**
```
grep -rn "@CrossOrigin\|CorsConfiguration\|addCorsMappings\|allowedOrigins\|allowCredentials" \
  --include="*.java"
```

**CSRF:**
```
grep -rn "csrf()\.disable\|CsrfConfigurer\|csrfTokenRepository\|CookieCsrfTokenRepository\|HttpSessionCsrfTokenRepository" \
  --include="*.java"
```

**Session:**
```
grep -rn "SessionCreationPolicy\|STATELESS\|NEVER\|IF_REQUIRED\|ALWAYS\|sessionFixation\|invalidateHttpSession\|maximumSessions" \
  --include="*.java"
```

---

### Step 5 — Endpoint Authentication Classification

For each entry point found in Step 2, determine its auth requirement:

- **Unauthenticated (public):** mapped by `permitAll()`, outside security filter chain, or in a public URL pattern
- **Authenticated (any user):** requires valid session/JWT but no role check
- **Role-restricted:** requires specific authority (`hasRole`, `hasAuthority`, `@PreAuthorize`)
- **Unknown/unclear:** no explicit security config found for this path

```
grep -rn "@PreAuthorize\|@PostAuthorize\|@Secured\|@RolesAllowed" --include="*.java"
```

Flag any endpoint that appears **unauthenticated** but handles sensitive data or mutating operations as HIGH PRIORITY for Phase 2 auth review.

---

### Step 6 — Database & External Integration Inventory

**Database access patterns:**
```
grep -rn "JdbcTemplate\|NamedParameterJdbcTemplate\|EntityManager\|@Repository\|JpaRepository\|CrudRepository\|MongoRepository\|RedisTemplate\|CassandraRepository" \
  --include="*.java" -l
```

**Native queries (highest SQLi risk):**
```
grep -rn "@Query.*nativeQuery\s*=\s*true\|createNativeQuery\|createQuery\|executeQuery\|Statement\b\|PreparedStatement\b" \
  --include="*.java"
```

**File system:**
```
grep -rn "new File\|Files\.\|FileInputStream\|FileOutputStream\|FileWriter\|FileReader\|Path\.of\|Paths\.get\|File\.createTemp" \
  --include="*.java"
```

**HTTP clients (SSRF surface):**
```
grep -rn "RestTemplate\|WebClient\|HttpClient\|OkHttpClient\|CloseableHttpClient\|URL\.openConnection\|HttpURLConnection\|Feign\|FeignClient" \
  --include="*.java" -l
```

**XML parsing:**
```
grep -rn "DocumentBuilderFactory\|SAXParserFactory\|XMLInputFactory\|XPathFactory\|JAXBContext\|Unmarshaller\|XmlMapper" \
  --include="*.java" -l
```

**Deserialization:**
```
grep -rn "ObjectInputStream\|readObject\|readUnshared\|XMLDecoder\|XStream\|Kryo\|Hessian\|JsonParser\|readValue.*Class" \
  --include="*.java" -l
```

---

### Step 7 — Dependency & Version Snapshot

```
# Maven
cat pom.xml | grep -E "<artifactId>|<version>" | paste - - | head -60

# Gradle
cat build.gradle | grep -E "implementation|compile|api|testImplementation" | head -60

# Gradle KTS
cat build.gradle.kts | grep -E "implementation|compile|api" | head -60
```

Flag known-vulnerable libraries (check against common CVE patterns):
- Spring Framework < 5.3.18 (CVE-2022-22965, Spring4Shell)
- Log4j 1.x or Log4j 2.x < 2.17.1 (Log4Shell)
- Jackson < 2.14 (polymorphic deserialization gadgets)
- Commons Collections 3.x, 4.0 (deserialization gadgets)
- Shiro < 1.7 (auth bypass)
- Struts 2.x < 2.5.33 (multiple RCE)
- XStream < 1.4.19 (CVE-2021-43859)

---

### Step 8 — Architecture Context Document (Output)

Produce a structured document in this exact format:

```markdown
## Architecture Context

### Framework
[e.g., Spring Boot 3.1, JAX-RS via Jersey 3.0]

### Entry Points
| ID | Class | Method | Path | HTTP Method | Auth |
|----|-------|--------|------|-------------|------|
| EP-001 | UserController | createUser | /api/users | POST | Authenticated |
| EP-002 | PublicController | healthCheck | /health | GET | Public |
...

### Taint Sources
- @RequestBody on EP-001, EP-003, EP-007
- request.getParameter() in LegacyServlet (line 42, 67, 89)
- @PathVariable on EP-002 through EP-015

### Trust Boundaries
- Security filter chain covers: /api/**
- Public paths: /health, /actuator/info, /public/**
- CSRF: [enabled/disabled - note config location]
- CORS: [origins allowed, credentials flag]
- Session policy: [STATELESS/ALWAYS/etc.]

### High-Risk Integrations
- Database: JPA + native queries in [files]
- HTTP clients: RestTemplate used in [files] — SSRF surface
- XML parsing: DocumentBuilderFactory in [files] — XXE surface
- Deserialization: ObjectInputStream in [files] — gadget chain risk

### Flagged Dependencies
- [library version] — [CVE if known]

### Priority Focus Areas for Phase 2
1. [EP-005]: Unauthenticated POST that calls JdbcTemplate — high SQLi/auth risk
2. [LegacyXmlService]: DocumentBuilderFactory, no explicit setFeature hardening
3. [UserImportController]: Accepts multipart/form-data + ObjectInputStream
```

---

## Fallback Behavior

If this skill is invoked without prior Phase 1 output available, Phase 2 skills should:
1. Run their own targeted grep patterns against the full source tree
2. Note in their output: "Phase 1 context not available — performed standalone analysis"
3. Still produce valid findings

---

## Self-Contained Check

This skill can run standalone. No dependencies on other skills.
