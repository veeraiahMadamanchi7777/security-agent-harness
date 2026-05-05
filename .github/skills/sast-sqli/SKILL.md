# SKILL: sast-sqli — SQL Injection Detection

## Purpose

Identify SQL injection vulnerabilities in Java applications by tracing attacker-controlled input from HTTP entry points through to SQL execution sinks. Distinguish exploitable injections from correctly-parameterized queries.

---

## Phase 1: Sink Discovery

### 1.1 — Raw SQL Execution Sinks

```bash
# JDBC Statement (most dangerous — no parameterization possible)
grep -rn "Statement\b" --include="*.java" | grep -v "//\|PreparedStatement\|CallableStatement\|test\|Test"

# createStatement — always dangerous if query contains variables
grep -rn "\.createStatement()\|createStatement(" --include="*.java"

# executeQuery / execute / executeUpdate with string concatenation
grep -rn "\.executeQuery\s*(\|\.execute\s*(\|\.executeUpdate\s*(" --include="*.java"

# String.format in queries
grep -rn "String\.format.*SELECT\|String\.format.*INSERT\|String\.format.*UPDATE\|String\.format.*DELETE\|String\.format.*WHERE" --include="*.java"

# String concatenation with SQL keywords
grep -rn '".*SELECT.*"\s*+\|".*INSERT.*"\s*+\|".*UPDATE.*"\s*+\|".*DELETE.*"\s*+\|".*WHERE.*"\s*+\|".*FROM.*"\s*+' --include="*.java"

# StringBuilder/StringBuffer building SQL
grep -rn "StringBuilder\|StringBuffer" --include="*.java" | xargs grep -l "SELECT\|INSERT\|UPDATE\|DELETE\|WHERE" 2>/dev/null
```

### 1.2 — ORM / Framework-Level Sinks

```bash
# JPA JPQL injection (less exploitable than SQL but still dangerous)
grep -rn "createQuery\|createNamedQuery\|createNativeQuery" --include="*.java"

# Spring Data JPA — @Query with SpEL or concatenation
grep -rn "@Query" --include="*.java" -A2 | grep -v "nativeQuery\s*=\s*false\|#{\|?[0-9]"

# Native queries — most dangerous JPA path
grep -rn "nativeQuery\s*=\s*true" --include="*.java"

# JdbcTemplate with unsafe query building
grep -rn "JdbcTemplate\|NamedParameterJdbcTemplate" --include="*.java" -l

# MyBatis — ${} is unparameterized, #{} is safe
grep -rn "\${" --include="*.xml" --include="*.java" | grep -i "mapper\|mybatis\|sql"

# Hibernate raw HQL
grep -rn "session\.createQuery\|session\.createSQLQuery\|openSession\|getCurrentSession" --include="*.java"
```

### 1.3 — NoSQL Injection (MongoDB, Redis)

```bash
# MongoDB string-based queries
grep -rn "BasicDBObject\|Document\b\|BsonDocument" --include="*.java" | grep -v "//\|test"
grep -rn "MongoTemplate\|ReactiveMongoTemplate" --include="*.java" -l
grep -rn "\.find(\|\.findOne(\|\.aggregate(" --include="*.java" | grep -v "jpa\|JPA\|repository\|Repository"

# Redis command injection (EVAL, keys pattern)
grep -rn "redisTemplate\.execute\|RedisCallback\|\.eval(" --include="*.java"
```

---

## Phase 2: Taint Analysis

For each sink identified in Phase 1, trace backward to confirm attacker-controlled input reaches it:

### 2.1 — Source Identification

Identify the HTTP handler that populates variables used in the sink:

```bash
# Direct parameter injection patterns
grep -rn "getParameter\|getHeader\|getQueryString\|@RequestParam\|@PathVariable\|@RequestBody" \
  --include="*.java" -B5 -A5 | grep -A5 "SELECT\|INSERT\|WHERE\|UPDATE"
```

### 2.2 — Taint Path Validation

For a candidate sink like:
```java
String query = "SELECT * FROM users WHERE username = '" + username + "'";
stmt.executeQuery(query);
```

Confirm:
1. `username` originates from `request.getParameter("username")` or equivalent
2. No intervening sanitizer (see Section 3 — Sanitizer Patterns)
3. The query string flows directly to `executeQuery()` / `execute()` / etc.

### 2.3 — Multi-Method Taint Tracking

Trace across method boundaries:
```bash
# Find methods that accept String and build queries
grep -rn "private.*String.*query\|public.*String.*buildQuery\|protected.*String.*sql" --include="*.java"

# Find methods that return query strings (potential propagation)
grep -rn "return.*SELECT\|return.*WHERE\|return.*INSERT" --include="*.java"
```

---

## Phase 3: Sanitizer Detection (Reduce False Positives)

The following patterns indicate effective parameterization — **do not report** unless the parameterization is itself broken:

```bash
# PreparedStatement with positional parameters — SAFE
# Pattern: "SELECT * FROM users WHERE id = ?" + ps.setInt(1, id)
grep -rn "PreparedStatement\|prepareStatement" --include="*.java"
grep -rn "\.setString\|\.setInt\|\.setLong\|\.setObject\|\.setDate\|\.setTimestamp\|\.setBigDecimal" --include="*.java"

# NamedParameterJdbcTemplate — SAFE if using MapSqlParameterSource
grep -rn "MapSqlParameterSource\|BeanPropertySqlParameterSource\|SqlParameterSource" --include="*.java"

# Spring Data @Query with ?1, ?2 or :paramName — SAFE
# @Query("SELECT u FROM User u WHERE u.name = ?1")
grep -rn "@Query.*\?[0-9]\|@Query.*:[a-zA-Z]" --include="*.java"

# Criteria API — SAFE (programmatic, not string-based)
grep -rn "CriteriaBuilder\|CriteriaQuery\|Root<\|Predicate\b" --include="*.java"

# QueryDSL — SAFE
grep -rn "JPAQueryFactory\|QEntity\|BooleanExpression" --include="*.java"
```

**Broken parameterization patterns (still report):**
```bash
# PreparedStatement but still concatenating into query string
grep -rn "prepareStatement" --include="*.java" -A5 | grep "+"
# MyBatis ${} instead of #{}
grep -rn '\${[^}]*}' --include="*.xml"
```

---

## Phase 4: Exploitability Assessment

For each confirmed taint path, assess exploitability:

| Factor | Score | Criteria |
|--------|-------|---------|
| Authentication | +2 CRITICAL | No auth required |
| Authentication | +0 HIGH | Auth required |
| SQL dialect | +1 | MySQL/MSSQL/PostgreSQL (stacked queries, out-of-band) |
| SQL dialect | +0 | Oracle (restricted stacked queries) |
| Column reflection | +1 | SELECT output returned to client |
| Blind only | +0 | No direct output — blind SQLi |
| WAF present | -1 | Evidence of WAF in headers/config |
| Input length limit | -1 | Input validated to short length |

---

## Finding Format

```
### [CRITICAL/HIGH] SQL Injection — [endpoint path]

**File:** `src/main/java/com/example/UserRepository.java:47`
**CWE:** CWE-89
**CVSS:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Taint Path:**
GET /api/users?name=X → UserController.search(name) → UserRepository.findByName(name) → JDBC executeQuery()

**Vulnerable Code:**
```java
// Line 45-49
public List<User> findByName(String name) {
    String sql = "SELECT * FROM users WHERE name = '" + name + "'";
    return jdbcTemplate.query(sql, userRowMapper);
}
```

**Proof of Concept:**
```
GET /api/users?name=' OR '1'='1 HTTP/1.1
GET /api/users?name=' UNION SELECT username,password,null FROM admin_users-- HTTP/1.1
```

**Remediation:**
Replace string concatenation with parameterized query:
```java
String sql = "SELECT * FROM users WHERE name = ?";
return jdbcTemplate.query(sql, userRowMapper, name);
```

**References:** CWE-89, OWASP A03:2021
```

---

## Self-Contained Check

This skill runs independently. Phase 1 context improves coverage but is not required.
