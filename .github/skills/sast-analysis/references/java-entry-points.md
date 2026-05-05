# Java Entry Point Reference — Spring, JAX-RS, Servlet

## Spring MVC / Spring Boot

### Controller Annotations
| Annotation | Meaning | Notes |
|-----------|---------|-------|
| `@RestController` | HTTP controller, all methods return JSON/body | Combines `@Controller` + `@ResponseBody` |
| `@Controller` | HTTP controller, methods return view names or `@ResponseBody` | Must check if methods use `@ResponseBody` |
| `@RequestMapping` | Maps any HTTP method to a path | Can be class-level (path prefix) or method-level |
| `@GetMapping` | GET only | Shorthand for `@RequestMapping(method=GET)` |
| `@PostMapping` | POST only | Most mutation surface |
| `@PutMapping` | PUT only | |
| `@DeleteMapping` | DELETE only | |
| `@PatchMapping` | PATCH only | Partial update |

### Request Data Annotations
| Annotation | Source | Taint Notes |
|-----------|--------|------------|
| `@RequestParam` | Query string / form field | Fully attacker-controlled |
| `@PathVariable` | URL path segment | Attacker-controlled; often used in ID lookups (IDOR) |
| `@RequestBody` | HTTP body (JSON/XML/form) | Fully attacker-controlled; deserialized by message converter |
| `@RequestHeader` | HTTP header | Attacker-controlled (some headers are hop-by-hop but app can't guarantee) |
| `@CookieValue` | Cookie value | Attacker-controlled if cookie isn't HttpOnly signed |
| `@ModelAttribute` | Form data bound to POJO | Mass assignment risk if POJO has sensitive fields |
| `@RequestPart` | Multipart file upload | Attacker controls filename, content type, content |
| `@MatrixVariable` | Semicolon-delimited path params | Less common; often not covered by security filters |

### Spring Security Integration Points
| Class/Method | What it controls |
|-------------|-----------------|
| `HttpSecurity.authorizeRequests()` / `authorizeHttpRequests()` | URL-level auth rules |
| `antMatchers()` / `requestMatchers()` | Path patterns for auth rules |
| `permitAll()` | Removes auth requirement for matched paths |
| `authenticated()` | Requires any authenticated user |
| `hasRole()` / `hasAuthority()` | Role-based restriction |
| `@PreAuthorize("hasRole('ADMIN')")` | Method-level security (SpEL) |
| `@PostAuthorize` | Method-level post-execution check |
| `@Secured` | Simple role list on method |
| `@RolesAllowed` | JSR-250 equivalent |
| `OncePerRequestFilter` | Custom filter — check what it gates |
| `UsernamePasswordAuthenticationFilter` | Login endpoint |
| `BasicAuthenticationFilter` | HTTP Basic processing |
| `JwtAuthenticationFilter` (custom) | JWT validation — check for alg:none, weak secret |

### Spring Actuator Endpoints (Common Exposures)
| Endpoint | Risk if exposed |
|---------|----------------|
| `/actuator/env` | Reveals environment variables, secrets |
| `/actuator/heapdump` | Memory dump — credential theft |
| `/actuator/mappings` | Full route listing — recon |
| `/actuator/beans` | Spring bean graph |
| `/actuator/loggers` | May allow changing log level |
| `/actuator/metrics` | Info leak |
| `/actuator/shutdown` | DoS (usually disabled by default) |
| `/actuator/httptrace` | Recent HTTP traffic |

---

## JAX-RS (Jersey, RESTEasy, CXF)

### Resource Annotations
| Annotation | Meaning |
|-----------|---------|
| `@Path("/users")` | Class-level or method-level path |
| `@GET`, `@POST`, `@PUT`, `@DELETE`, `@PATCH` | HTTP method binding |
| `@Produces` | Response Content-Type |
| `@Consumes` | Acceptable request Content-Type |

### Parameter Annotations
| Annotation | Source |
|-----------|--------|
| `@QueryParam` | Query string |
| `@PathParam` | URL path segment |
| `@FormParam` | Form POST body |
| `@HeaderParam` | HTTP header |
| `@CookieParam` | Cookie |
| `@BeanParam` | Aggregates params into POJO (mass assignment risk) |
| `@MatrixParam` | Semicolon path params |
| Entity body (unannotated method param) | Full request body deserialization |

### JAX-RS Filters and Interceptors
| Class/Interface | Role |
|----------------|------|
| `ContainerRequestFilter` | Pre-routing filter — auth checks often here |
| `ContainerResponseFilter` | Post-processing — security headers |
| `@PreMatching` | Applied before URI matching — can affect auth bypass |
| `DynamicFeature` | Conditional filter registration |

---

## Raw Servlet API

### Key Methods to Find
| Method | Meaning |
|--------|---------|
| `extends HttpServlet` | Direct HTTP handler |
| `doGet(HttpServletRequest, HttpServletResponse)` | GET handler |
| `doPost(...)` | POST handler |
| `doPut(...)` | PUT handler |
| `doDelete(...)` | DELETE handler |
| `service(...)` | Handles all methods — check dispatch logic |
| `getParameter(String)` | Query/form param — taint source |
| `getHeader(String)` | HTTP header — taint source |
| `getCookies()` | Cookies — taint source |
| `getInputStream()` / `getReader()` | Raw body — taint source |
| `getRequestURI()` / `getRequestURL()` | Full URL — used in path traversal |
| `getQueryString()` | Raw query string |

### Servlet Filters
| Pattern | Note |
|---------|------|
| `implements Filter` | `doFilter()` must call `chain.doFilter()` or block — check bypass conditions |
| `init-param` in `web.xml` | Filter configuration — often hard-coded credentials |
| `<url-pattern>` in `web.xml` | Scope of filter — gaps = attack surface |

---

## WebSocket Entry Points
| Annotation/Class | Framework | Note |
|-----------------|-----------|------|
| `@ServerEndpoint` | Java EE WebSocket | `@OnMessage` methods receive messages from client |
| `TextWebSocketHandler` | Spring WebSocket | `handleTextMessage()` |
| `BinaryWebSocketHandler` | Spring WebSocket | Binary data — potential deserialization entry |
| `@OnMessage` | Java EE | Direct message handler — treat as taint source |
| `@OnOpen` | Java EE | Connection established — auth must be done here |

---

## Messaging / Async Entry Points
| Annotation | Framework | Note |
|-----------|-----------|------|
| `@RabbitListener` | Spring AMQP | Message content from broker — treat as tainted |
| `@KafkaListener` | Spring Kafka | Kafka messages — treat as tainted |
| `@JmsListener` | Spring JMS | JMS messages — treat as tainted |
| `@SqsListener` | AWS SQS | SQS messages — treat as tainted |
| `@EventListener` | Spring Events | Internal — low risk unless external input drives event |
| `@Async` | Spring | Async method — check context propagation (auth principal) |
| `MessageListener.onMessage()` | Raw JMS | JMS entry point |

---

## Scheduled / Batch Entry Points
| Annotation/Class | Note |
|-----------------|------|
| `@Scheduled(cron=...)` | Recurring job — check if it processes external data |
| `@Scheduled(fixedRate=...)` | Polling job — what external system does it poll? |
| `QuartzJobBean` | Quartz — `executeInternal()` |
| `Job.execute()` | Quartz raw interface |
| `ItemReader` / `ItemProcessor` / `ItemWriter` | Spring Batch — check data sources |
| `CommandLineRunner` / `ApplicationRunner` | Runs on startup — privilege context is system, not user |

---

## Common False Positive Patterns

| Pattern | Why It's Usually a FP |
|---------|----------------------|
| `@GetMapping` on `/error` | Spring Boot error handler, not user-data endpoint |
| `@GetMapping` on `/actuator/health` | Health check, no sensitive data |
| `doGet()` inside `AbstractSecurityInterceptor` | Framework internal, not application code |
| `@EventListener(ApplicationReadyEvent.class)` | Init hook, no external input |
| `@Scheduled` reading from classpath resource | Static data, attacker can't control |
