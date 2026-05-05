# SKILL: sast-massassignment — Mass Assignment Detection

## Purpose

Identify endpoints that bind attacker-controlled request bodies directly into domain entities or privileged DTO fields, allowing users to set fields such as roles, ownership, account status, prices, or approval flags.

---

## Phase 1: Binding Sink Discovery

### 1.1 — Request Body Binding

```bash
grep -rn "@RequestBody\|@ModelAttribute\|@RequestPart" --include="*.java" -B5 -A10
grep -rn "ObjectMapper.*readValue\|BeanUtils\.copyProperties\|PropertyUtils\.copyProperties\|ModelMapper\|DozerBeanMapper" --include="*.java"
```

### 1.2 — Entity Persistence After Binding

```bash
grep -rn "\.save(\|\.saveAndFlush(\|entityManager\.persist\|entityManager\.merge\|repository\.save" --include="*.java" -B10 -A5
```

### 1.3 — Sensitive Field Names

```bash
grep -rn "isAdmin\|admin\b\|role\|roles\|authority\|authorities\|ownerId\|userId\|tenantId\|accountId\|price\|amount\|balance\|status\|approved\|verified\|enabled\|locked" --include="*.java" -i
```

---

## Phase 2: Exploitability Analysis

Confirm all of the following before reporting:

1. The endpoint binds a request body or model attributes into an object.
2. The object is an entity or is copied into an entity without an allowlist.
3. Sensitive fields are present and can affect authorization, ownership, workflow, money, or account state.
4. The code persists or acts on those fields.
5. There is no explicit field allowlist, role check, or server-side override before persistence.

High-risk patterns:

```java
@PostMapping("/users")
public User create(@RequestBody User user) {
    return userRepository.save(user);
}
```

```java
BeanUtils.copyProperties(request, account);
accountRepository.save(account);
```

Lower-risk patterns:

- binding into a narrow DTO with only safe fields
- server overwrites sensitive fields after binding
- `@JsonIgnore`, `@JsonProperty(access = READ_ONLY)`, or validation prevents client writes

---

## Phase 3: Defense Detection

```bash
# Narrow DTOs and explicit mapping
grep -rn "Dto\b\|DTO\b\|Request\b\|Command\b" --include="*.java"
grep -rn "setRole\|setOwnerId\|setTenantId\|setStatus\|setPrice" --include="*.java" -B5 -A5

# Jackson write protection
grep -rn "@JsonIgnore\|JsonProperty.*READ_ONLY\|JsonView" --include="*.java"

# Spring binder restrictions
grep -rn "@InitBinder\|setAllowedFields\|setDisallowedFields" --include="*.java"

# Bean validation hints
grep -rn "@Valid\|@Validated\|@NotNull\|@Pattern\|@Min\|@Max" --include="*.java"
```

Do not treat `@Valid` alone as sufficient if sensitive fields are still client-writable.

---

## Finding Format

Emit findings using `.github/schemas/finding.schema.json`.

Recommended CWE: `CWE-915`.

Example sink names:

- `JpaRepository.save()`
- `EntityManager.merge()`
- `BeanUtils.copyProperties()`
- `ObjectMapper.readValue()`

---

## Self-Contained Check

This skill runs independently. If `.github/sast-context.md` exists, prioritize POST/PUT/PATCH endpoints and entity persistence paths; otherwise scan all controllers, DTOs, entities, and repositories.
