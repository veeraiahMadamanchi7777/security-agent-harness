# Java Framework Detection Patterns

Used by `sast-analysis` Step 2 to identify which frameworks are present before mapping entry points.

## Detection Priority Order

1. **Build file** (`pom.xml` / `build.gradle`) — most reliable, check first
2. **Configuration files** (`application.properties`, `web.xml`, etc.)
3. **Annotation grep** — fastest, use to confirm or detect frameworks missed in build files

---

## Maven (pom.xml) Dependency Signals

Search for `<groupId>` + `<artifactId>` combinations:

| Framework | groupId | artifactId (prefix match) |
|---|---|---|
| Spring MVC | `org.springframework` | `spring-webmvc` |
| Spring Boot MVC | `org.springframework.boot` | `spring-boot-starter-web` |
| Spring WebFlux | `org.springframework.boot` | `spring-boot-starter-webflux` |
| Spring Security | `org.springframework.security` | `spring-security-web` |
| Spring Security Boot | `org.springframework.boot` | `spring-boot-starter-security` |
| JAX-RS / Jersey | `org.glassfish.jersey` | `jersey-server` |
| JAX-RS / RESTEasy | `org.jboss.resteasy` | `resteasy-core` |
| JAX-RS / Apache CXF | `org.apache.cxf` | `cxf-rt-frontend-jaxrs` |
| Quarkus | `io.quarkus` | `quarkus-resteasy` or `quarkus-rest` |
| Micronaut | `io.micronaut` | `micronaut-http` |
| Struts 2 | `org.apache.struts` | `struts2-core` |
| Struts 1 | `struts` | `struts` |
| MyBatis | `org.mybatis` | `mybatis` |
| MyBatis Spring Boot | `org.mybatis.spring.boot` | `mybatis-spring-boot-starter` |
| Hibernate | `org.hibernate` | `hibernate-core` |
| Spring Data JPA | `org.springframework.boot` | `spring-boot-starter-data-jpa` |
| Thymeleaf | `org.thymeleaf` | `thymeleaf` |
| FreeMarker | `org.freemarker` | `freemarker` |
| Velocity | `org.apache.velocity` | `velocity-engine-core` |
| Mustache | `com.github.spullara.mustache.java` | `compiler` |
| Kryo | `com.esotericsoftware` | `kryo` |
| XStream | `com.thoughtworks.xstream` | `xstream` |
| SnakeYAML | `org.yaml` | `snakeyaml` |
| Jackson | `com.fasterxml.jackson.core` | `jackson-databind` |
| JJWT | `io.jsonwebtoken` | `jjwt` |
| Nimbus JOSE+JWT | `com.nimbusds` | `nimbus-jose-jwt` |
| Apache Shiro | `org.apache.shiro` | `shiro-core` |
| Keycloak | `org.keycloak` | `keycloak-spring-boot-starter` |

## Gradle (build.gradle / build.gradle.kts) Dependency Signals

Same groupId:artifactId patterns. Look inside these configuration blocks:
- `implementation`, `api`, `compile` (deprecated), `runtimeOnly`, `compileOnly`

Pattern to grep: `"<groupId>:<artifactId>` or `group: '<groupId>', name: '<artifactId>'`

---

## Configuration File Signals

| File | What it signals |
|---|---|
| `web.xml` | Servlet-based app (Servlet API 3.x or earlier). Check `<filter>` declarations for security filters. |
| `application.properties` | Spring Boot present. Check for `spring.security.*`, `server.*`, `spring.datasource.*` |
| `application.yml` | Same as above in YAML format |
| `application.properties` with `quarkus.*` keys | Quarkus |
| `micronaut-cli.yml` | Micronaut |
| `struts-config.xml` | Struts 1 — also maps URLs to ActionForm classes |
| `struts.xml` | Struts 2 — also maps URLs to Action classes |
| `persistence.xml` | JPA present. Check for `<named-native-query>` (SQLi risk) |
| `mybatis-config.xml` | MyBatis standalone config |
| `shiro.ini` | Apache Shiro auth framework |
| `applicationContext.xml` | Spring XML config (older style) |

---

## Annotation Presence Signals (Fast Grep)

Use these to confirm framework detection or catch frameworks that aren't in build files (e.g., fat JARs):

| Grep pattern | Framework |
|---|---|
| `@SpringBootApplication` | Spring Boot |
| `@RestController` | Spring MVC |
| `@Controller` (without `@RestController`) | Spring MVC (view-based) |
| `@Path` + `@GET` in same file | JAX-RS |
| `@QuarkusTest` or `import io.quarkus` | Quarkus |
| `import io.micronaut.http` | Micronaut |
| `extends ActionSupport` | Struts 2 |
| `extends Action` + `import org.apache.struts` | Struts 1 |
| `extends HttpServlet` | Plain Servlet |
| `implements Filter` | Servlet Filter (may sanitize/authenticate) |
| `@EnableWebSecurity` | Spring Security present |
| `WebSecurityConfigurerAdapter` | Spring Security 5.x (deprecated) |
| `SecurityFilterChain` | Spring Security 5.7+ (modern config) |

---

## ORM / Database Access Signals

| Signal | Implication for SAST |
|---|---|
| `Connection.createStatement()` | Raw SQL — high SQLi risk, scan this file |
| `Connection.prepareStatement()` | Parameterized — scan to confirm `?` is used |
| `@Query(nativeQuery=true)` | Spring Data native SQL — scan for string concat |
| `@Select`, `@Insert` with `${}` | MyBatis — `${}` is unsafe, `#{}` is safe |
| `EntityManager.createNativeQuery()` | JPA native SQL — scan for dynamic construction |
| `session.createQuery()` (Hibernate) | HQL — scan for dynamic construction |
| `CriteriaBuilder` | Type-safe — low SQLi risk |
| `jOOQ`, `QueryDSL` | Type-safe — low SQLi risk |

---

## Security Framework Signals

| Signal | Implication |
|---|---|
| `@EnableWebSecurity` | Spring Security active — check for `.csrf().disable()`, `.authorizeRequests()` config |
| `.csrf().disable()` in `SecurityConfig` | CSRF protection removed — flag for `sast-csrf` |
| `.authorizeRequests().anyRequest().permitAll()` | All endpoints open — flag for `sast-auth` |
| `@PreAuthorize` / `@PostAuthorize` | Method-level security active — reduces IDOR/auth confidence |
| `ShiroFilterFactoryBean` | Apache Shiro — check filter chain config |
| `KeycloakSecurityContextClientRequestInterceptor` | Keycloak JWT validation |
| `@EnableGlobalMethodSecurity` | Method security annotations are enforced |
| `permitAll()` on specific paths | Those paths are unauthed — elevate severity for findings on those endpoints |

---

## GraphQL Entry Points

| Signal | Note |
|---|---|
| `@QueryMapping`, `@MutationMapping` | Spring GraphQL — arguments are user-controlled |
| `@GraphQLQuery` (graphql-java-kickstart) | Arguments are user-controlled |
| `graphql-spring-boot-starter` in build file | GraphQL endpoint present at `/graphql` |

## gRPC Entry Points

| Signal | Note |
|---|---|
| Classes extending `*Grpc.ImplBase` | gRPC service — request message fields are user-controlled |
| `protobuf-java` in build file | Protocol Buffers used — check generated stubs |
| Source may be internal service | Reduce source trust level vs. HTTP endpoints |
