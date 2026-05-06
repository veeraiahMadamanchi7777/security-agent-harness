---
name: sast-ldap
description: Detect LDAP, JNDI, and directory query injection in Java authentication, search, and identity integration code.
---

# SKILL: sast-ldap — LDAP and Directory Injection Review

## Purpose

Find user-controlled values inserted into LDAP filters, DNs, JNDI names, or directory queries without escaping or structured APIs.

Load [`references/java-ldap.md`](references/java-ldap.md).

## Method

1. Identify LDAP, JNDI, Active Directory, and Spring LDAP usage.
2. Trace request-controlled usernames, emails, groups, DNs, filters, and search bases into directory operations.
3. Verify filter escaping and DN escaping match the context.
4. Review authentication bypass, user enumeration, and privilege group lookup impact.

## Searches

```bash
rg -n "DirContext|InitialDirContext|LdapTemplate|LdapQueryBuilder|search\\(|lookup\\(|bind\\(|(&(|\\(|objectClass|sAMAccountName|userPrincipalName|distinguishedName" --glob "*.java"
```

## True Positive Signals

- LDAP filter string concatenates username or request data.
- DN is built from user input without DN escaping.
- Search base or group filter is user-controlled.
- Authentication logic treats a broad search result as proof of identity.
- JNDI lookup name includes user-controlled data.

## Output

Include source parameter, LDAP filter or DN sink, missing escaping, auth or data exposure impact, and safe query pattern.
