# Java Mass Assignment Reference — Binding Sinks, Sensitive Fields & Defenses

## Binding Sinks

| API / Pattern | Risk | Notes |
|--------------|------|-------|
| `@RequestBody EntityClass entity` | HIGH | Binds full JSON payload to JPA entity |
| `@ModelAttribute EntityClass entity` | HIGH | Binds form fields to entity |
| `BeanUtils.copyProperties(source, target)` | HIGH | Copies all properties including sensitive |
| `BeanUtils.copyProperties(source, target, ignoreProperties)` | MEDIUM | Depends on ignore list completeness |
| `ObjectMapper.readValue(json, EntityClass.class)` | HIGH | Full JSON deserialization to entity |
| `ModelMapper.map(dto, Entity.class)` | HIGH | Unconfigured ModelMapper maps everything |
| `MapStruct` mapper without `@Mapping(target="field", ignore=true)` | MEDIUM | Auto-maps all matching fields |
| `EntityManager.merge(entity)` | HIGH | Persists all entity fields including managed by app |
| Spring Data `repository.save(entity)` | HIGH | If entity bound directly from request |

## High-Risk Sensitive Fields

Fields that should never be bound from user input:

| Field Name | Type | Risk |
|-----------|------|------|
| `id`, `userId`, `accountId` | Long/UUID | Horizontal privilege escalation |
| `role`, `roles` | String/Enum/Set | Vertical privilege escalation |
| `isAdmin`, `admin` | Boolean | Direct privilege escalation |
| `ownerId`, `createdBy` | Long/String | Ownership forgery |
| `tenantId`, `organizationId` | Long/UUID | Tenant isolation bypass |
| `price`, `amount`, `discount` | BigDecimal | Financial fraud |
| `balance`, `credit` | BigDecimal | Balance manipulation |
| `status`, `state` | Enum/String | Workflow bypass |
| `verified`, `emailVerified` | Boolean | Verification bypass |
| `createdAt`, `updatedAt` | Date/Timestamp | Audit trail manipulation |
| `password`, `passwordHash` | String | Credential replacement |
| `apiKey`, `secretToken` | String | Token forgery |
| `enabled`, `active`, `locked` | Boolean | Account state manipulation |

## Defense Patterns

### 1. DTO Pattern (Most Effective)

```java
// DANGEROUS — entity bound directly
@PutMapping("/users/{id}")
public User update(@PathVariable Long id, @RequestBody User user) {
    user.setId(id);
    return userRepository.save(user);  // role, isAdmin bindable
}

// SAFE — narrow DTO
public record UserUpdateDto(String username, String email) {}  // no role, no isAdmin

@PutMapping("/users/{id}")
public User update(@PathVariable Long id, @RequestBody UserUpdateDto dto) {
    User user = userRepository.findById(id).orElseThrow();
    user.setUsername(dto.username());
    user.setEmail(dto.email());
    // role and isAdmin never touched
    return userRepository.save(user);
}
```

### 2. Jackson Write Protection

```java
@Entity
public class User {
    @Id
    private Long id;

    @JsonIgnore
    private String role;           // never serialized in or out

    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    private Boolean isAdmin;       // can be read (returned in response) but not written (bound from request)

    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    private LocalDateTime createdAt;
}
```

### 3. Spring MVC `@InitBinder` Field Restriction

```java
@Controller
public class UserController {
    @InitBinder("user")
    protected void initBinder(WebDataBinder binder) {
        binder.setAllowedFields("username", "email", "firstName", "lastName");
        // All other fields (role, isAdmin, balance) are silently ignored
    }
}
```

### 4. ModelMapper with Type Map

```java
ModelMapper modelMapper = new ModelMapper();
TypeMap<UserUpdateDto, User> typeMap = modelMapper.createTypeMap(UserUpdateDto.class, User.class);
typeMap.addMappings(mapper -> {
    mapper.skip(User::setRole);
    mapper.skip(User::setAdmin);
    mapper.skip(User::setId);
});
```

### 5. BeanUtils with Ignore List

```java
// Include ALL sensitive fields in the ignore list
String[] ignoredFields = {"id", "role", "isAdmin", "ownerId", "tenantId",
                          "balance", "status", "verified", "createdAt"};
BeanUtils.copyProperties(source, target, ignoredFields);
```

## ModelMapper Misconfiguration Risks

```java
// DANGEROUS — default ModelMapper maps all matching field names
ModelMapper mapper = new ModelMapper();
mapper.map(request, existingEntity);  // maps role if request has "role" field

// DANGEROUS — strict strategy still maps by name if DTO and entity share field names
mapper.getConfiguration().setMatchingStrategy(MatchingStrategies.STRICT);
// STRICT affects name matching algorithm, not field allowlisting

// SAFE — use TypeMap with explicit skip or use DTOs with no sensitive fields
```

## Spring Data Projection — Safe Read Pattern

```java
// For reads: use projections to limit exposed data
public interface UserSummary {
    Long getId();
    String getUsername();
    String getEmail();
    // No getRole(), no getIsAdmin()
}

List<UserSummary> findByDepartment(String department);
```

## False Positives

| Pattern | Reason Not Vulnerable |
|---------|----------------------|
| `@JsonIgnore` on sensitive fields in entity | Jackson won't bind those fields from request |
| `@JsonProperty(access = READ_ONLY)` on privilege fields | Cannot be set via deserialization |
| `@InitBinder` with `setAllowedFields` | Spring MVC silently drops disallowed fields |
| DTO class without sensitive fields used in `@RequestBody` | Fields simply don't exist in binding target |
| Admin endpoint protected by `@PreAuthorize("hasRole('ADMIN')")` | Requires admin to exploit — lower risk |
