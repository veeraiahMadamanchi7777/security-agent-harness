# Java SQL Injection Reference

## Dangerous APIs (Sinks)

| API | Risk | Notes |
|-----|------|-------|
| `Statement.execute(String)` | CRITICAL | No parameterization possible |
| `Statement.executeQuery(String)` | CRITICAL | No parameterization possible |
| `Statement.executeUpdate(String)` | CRITICAL | No parameterization possible |
| `Statement.executeLargeUpdate(String)` | CRITICAL | No parameterization possible |
| `Connection.createStatement()` | HIGH | Returns unparameterized Statement |
| `JdbcTemplate.query(String, ...)` | HIGH | If String is concatenated |
| `JdbcTemplate.queryForObject(String, ...)` | HIGH | If String is concatenated |
| `JdbcTemplate.update(String, ...)` | HIGH | If String is concatenated |
| `NamedParameterJdbcTemplate.query(String, ...)` | HIGH | If String is concatenated instead of using `:param` |
| `EntityManager.createNativeQuery(String)` | HIGH | Native SQL, concatenation is dangerous |
| `EntityManager.createQuery(String)` | MEDIUM | JPQL injection (limited but possible) |
| `Session.createSQLQuery(String)` | HIGH | Hibernate native SQL |
| `Session.createQuery(String)` | MEDIUM | HQL injection |

## Safe APIs (Not Findings)

| API | Why Safe |
|-----|---------|
| `PreparedStatement` with `?` params | Driver-level parameterization |
| `NamedParameterJdbcTemplate` with `MapSqlParameterSource` | Named param binding |
| Spring Data `@Query("... WHERE x = ?1")` | Positional binding |
| Spring Data `@Query("... WHERE x = :name")` with `@Param` | Named binding |
| `CriteriaBuilder` / `CriteriaQuery` | Programmatic, no string building |
| QueryDSL `JPAQueryFactory` | Type-safe, programmatic |
| `@NamedQuery` / `@NamedNativeQuery` in entity | Pre-compiled, no runtime concatenation |

## MyBatis — Critical Distinction

| Syntax | Risk | Notes |
|--------|------|-------|
| `#{param}` | Safe | Parameterized binding |
| `${param}` | CRITICAL | String substitution — direct injection |

Always report `${...}` in MyBatis XML mapper files.

## Ordering Clause Injection

Often overlooked: `ORDER BY` clauses cannot be parameterized:
```java
// Dangerous
String sql = "SELECT * FROM orders ORDER BY " + sortColumn + " " + sortDirection;

// Safe: allowlist approach
private static final Set<String> ALLOWED_COLS = Set.of("created_at", "name", "price");
if (!ALLOWED_COLS.contains(sortColumn)) throw new IllegalArgumentException();
```

## JPQL Injection Payloads

JPQL injection scope is more limited than SQL (no stacked queries, limited command injection), but data extraction is possible:
```
' OR '1'='1     → dump all records
' OR 1=1 AND '' ='  → auth bypass in login queries
```

## Second-Order SQLi Pattern

```java
// Step 1: User input stored (appears safe)
userRepository.save(new User(username));  // username = "admin'--"

// Step 2: Stored value retrieved and used in new query without parameterization
String stored = user.getUsername();  // "admin'--"
String query = "SELECT * FROM logs WHERE username = '" + stored + "'";  // NOW vulnerable
```

Always check if previously-stored data is re-used in SQL construction.

## Common Vulnerable Patterns

```java
// Pattern 1: Simple concatenation
"SELECT * FROM users WHERE id = " + userId

// Pattern 2: String.format
String.format("SELECT * FROM users WHERE name = '%s'", name)

// Pattern 3: StringBuilder
StringBuilder sb = new StringBuilder("SELECT * FROM products WHERE ");
sb.append("category = '").append(category).append("'");

// Pattern 4: Concatenation in @Query (Spring Data)
@Query("SELECT u FROM User u WHERE u.name = '" + name + "'")  // compile error, but dynamic @Query via service layer possible

// Pattern 5: JPA createNativeQuery
em.createNativeQuery("SELECT * FROM " + tableName + " WHERE id = " + id)
```
