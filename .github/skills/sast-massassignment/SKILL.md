---
name: sast-massassignment
description: Detect unsafe Java request binding that lets clients set sensitive fields or nested objects.
---

# SKILL: sast-massassignment — Mass Assignment Detection

## References

Load [`references/java-massassignment.md`](references/java-massassignment.md) at the start of this skill for binding sink table, high-risk field list, DTO/Jackson/InitBinder/ModelMapper defense patterns, and false positives.

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

Follow the canonical format from `copilot-instructions.md`. Example:

```
### [HIGH] Mass Assignment — @RequestBody Bound Directly to User Entity

**ID:** MASS-001
**File:** `src/main/java/com/example/UserController.java:44`
**CWE:** CWE-915 | **OWASP:** A04:2021-Insecure Design
**CVSS (estimated):** 8.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N)
**Confidence:** High
**Skill:** `sast-massassignment`

**Taint Path:**
`PUT /api/users/{id} body (JSON)` → `UserController.update(@RequestBody User user) (UserController.java:44)` → `userRepository.save(user) (UserController.java:46)` — sensitive fields (role, isAdmin) bindable from request

**Vulnerable Code:**
```java
@PutMapping("/api/users/{id}")
public User update(@PathVariable Long id, @RequestBody User user) {
    user.setId(id);
    return userRepository.save(user);  // persists all fields including role, isAdmin
}
```

**Why Exploitable:**
`@RequestBody User` binds the full JSON payload to the JPA entity, including `role` and `isAdmin` fields. An authenticated user can escalate their own privileges by including `"role":"ADMIN"` in the request body.

**Proof-of-Concept:**
```http
PUT /api/users/42 HTTP/1.1
Authorization: Bearer <regular_user_token>
Content-Type: application/json

{"username":"alice","email":"alice@example.com","role":"ADMIN","isAdmin":true}
```

**Remediation:**
Use a narrow DTO that excludes sensitive fields:
```java
@PutMapping("/api/users/{id}")
public User update(@PathVariable Long id, @RequestBody UserUpdateDto dto) {
    User user = userRepository.findById(id).orElseThrow();
    user.setUsername(dto.getUsername());
    user.setEmail(dto.getEmail());
    // role and isAdmin not in UserUpdateDto — cannot be mass-assigned
    return userRepository.save(user);
}
```

**References:** https://cwe.mitre.org/data/definitions/915.html, OWASP A04:2021
```

Recommended sink names: `JpaRepository.save()`, `EntityManager.merge()`, `BeanUtils.copyProperties()`, `ObjectMapper.readValue()`

JSONL line (append to `.github/sast-findings.jsonl`):
```json
{"id":"MASS-001","skill":"sast-massassignment","cwe":"CWE-915","owasp":"A04:2021-Insecure Design","severity":"High","confidence":"High","file":"src/main/java/com/example/UserController.java","line":46,"method":"update","class":"com.example.UserController","evidence":"return userRepository.save(user);","sink":"JpaRepository.save()","source":"@RequestBody User user","taint_path":[],"sanitizer_present":false,"sanitizer_detail":"","remediation":"Replace @RequestBody User with a narrow DTO that omits role, isAdmin, and other privilege fields","references":["https://cwe.mitre.org/data/definitions/915.html"],"false_positive_indicators":["@JsonIgnore on sensitive fields","@InitBinder with allowed fields restriction"],"duplicate_of":null}
```

---

## Self-Contained Check

This skill runs independently. If `.github/sast-context.md` exists, prioritize POST/PUT/PATCH endpoints and entity persistence paths; otherwise scan all controllers, DTOs, entities, and repositories.
