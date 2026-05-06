# Java LDAP Reference

## Risky APIs

- `DirContext.search`.
- `InitialDirContext`.
- Spring LDAP `LdapTemplate.search`.
- Raw LDAP filter strings.
- Dynamic JNDI lookup names.

## Safer Controls

- Spring LDAP query builders with parameter handling.
- LDAP filter escaping for filter values.
- DN escaping for RDN/DN components.
- Fixed search bases.
- Exact unique identity match after search.

Filter escaping and DN escaping are different; do not credit one as protection for the other.
