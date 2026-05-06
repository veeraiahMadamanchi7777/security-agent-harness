# Function Review Checklist

## Per-Function Questions

- Who can call this function?
- Does it assume authentication, role, tenant, ownership, or prior validation?
- Where is that assumption enforced?
- Can another caller bypass that enforcement?
- Does the function accept IDs, paths, URLs, templates, XML, serialized data, commands, secrets, roles, prices, balances, status, or permissions?
- Does it mutate state?
- Is mutation atomic and authorized?
- Does it cross a trust boundary?
- Does it log, render, redirect, fetch, execute, parse, or persist attacker-controlled data?

## Expected Control by Pattern

| Pattern | Expected control |
|---|---|
| Load object by ID | Owner or tenant scoping before exposure or mutation |
| Dynamic SQL or JPQL | Parameter binding and allowlisted identifiers |
| File read/write | Canonical base-directory containment |
| Outbound request | Parsed allowlist plus private network blocking |
| XML parse | DTD and external entity disabled |
| Entity update from request | Explicit DTO mapping |
| Role/status/tenant change | Server-side authority and invariant checks |
| Money/quota/balance update | Positive amount checks and atomic transaction |
| Token verification | Signature, issuer, audience, expiry, replay controls |

## Negative-Space Review

Search for pairs:

- `getX`, `updateX`, `deleteX`.
- `adminX` and `userX`.
- `findById` and `findByIdAndTenantId`.
- `save(entity)` and explicit field setters.
- `validateX` present in one path but missing in another.

Differences are review targets.
