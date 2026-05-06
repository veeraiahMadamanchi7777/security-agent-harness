# Taint Tree Format Reference

## Source Types

- HTTP request: params, path variables, headers, cookies, body DTOs.
- File upload and imported file contents.
- Message queues and event payloads.
- Webhooks and callbacks.
- JWT claims and identity provider attributes.
- Database values that originated from users and are later reused in sinks.
- Config values controlled outside the application trust boundary.

## Sink Types

- SQL, JPQL, HQL, NoSQL queries.
- File read/write/delete/extract.
- Process execution, script execution, expression evaluation, reflection.
- Outbound HTTP, sockets, DNS, cloud metadata.
- XML/YAML/deserialization/template engines.
- Redirects and forwards.
- Authorization decisions and state mutations.
- Responses that expose sensitive data.

## Control Types

- Authentication.
- Role check.
- Object ownership check.
- Tenant scoping.
- Input validation.
- Canonicalization.
- Parameter binding.
- Allowlist.
- CSRF token or origin control.
- Transaction, lock, idempotency, replay prevention.

## Good Taint Tree

A good tree names both code and security meaning:

```text
UserController.download(@PathVariable fileName) [source: path variable]
└─ FileService.download(fileName) [control: none]
   └─ Paths.get(base).resolve(fileName) [missing: normalize + startsWith(base)]
      └─ Files.readAllBytes(path) [sink: arbitrary file read]
```

## Bad Taint Tree

Avoid vague trees:

```text
user input goes to file read
```

This is not enough. Include functions, fields, controls, and missing proof.
