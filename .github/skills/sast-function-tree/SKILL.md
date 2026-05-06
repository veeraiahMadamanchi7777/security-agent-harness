---
name: sast-function-tree
description: Build a human-reviewable Java function and call tree that maps entry points, callers, callees, trust boundaries, sinks, and security controls.
---

# SKILL: sast-function-tree — Function and Call Tree Mapping

## Purpose

Create a function-level map before deep review. The goal is not a perfect compiler-grade call graph; it is a human-reviewable tree that shows which functions are reachable, what each function trusts, what it calls, and which security-sensitive operations it performs.

Write the main artifact to `.github/sast-function-tree.md`.

## Inputs

- `.github/sast-context.md` if present.
- Java, Kotlin, XML, YAML, properties, and build files in scope.
- Framework references from `sast-analysis`.
- [`references/java-function-tree.md`](references/java-function-tree.md).

## Method

### 1. Inventory Functions

For every in-scope class, identify:

- Package and class.
- Method name and signature.
- Visibility.
- Framework annotations.
- Approximate line range.
- Whether it is an entry point, internal helper, security control, data access method, async consumer, scheduled job, or sink wrapper.

Useful searches:

```bash
rg -n "class |interface |enum |record |@RestController|@Controller|@Service|@Repository|@Component|@Configuration" --glob "*.java"
rg -n "public |protected |private |@GetMapping|@PostMapping|@RequestMapping|@PreAuthorize|@Transactional" --glob "*.java"
```

### 2. Build Entry-Point Trees

For each externally reachable entry point, build a tree:

```text
ENTRY <HTTP method/path or consumer/job>
└─ Controller.method(source parameters, auth annotations)
   └─ Service.method(trust decision, validation)
      └─ Repository.method(query or persistence sink)
```

Include non-HTTP roots:

- Filters and interceptors.
- Message listeners.
- Schedulers.
- Startup runners.
- GraphQL and gRPC handlers.
- File importers.
- Webhook processors.

### 3. Annotate Security Meaning

For each function node, annotate:

- **Trust**: external, authenticated user, admin, system, internal service, unknown.
- **Inputs**: request params, body DTO, headers, path variables, cookies, message payload, file, database, config.
- **Controls**: validation, authorization, tenant scoping, CSRF, rate limit, canonicalization, parameter binding.
- **Sinks**: database, file, process, network, XML, deserialization, template, crypto, redirect, log, response.
- **State**: transaction boundary, locking, mutation, cache/session/global state.
- **Review priority**: Critical, High, Medium, Low.

### 4. Mark Unknowns

Mark a node as `UNKNOWN` when callers, callees, or controls cannot be determined. Unknowns are not findings by themselves, but high-risk unknowns must be queued for `sast-function-review`.

## Output Format

Write `.github/sast-function-tree.md` with:

```markdown
# Function Tree

## Summary
- Classes reviewed:
- Functions reviewed:
- Entry-point trees:
- High-priority functions:
- Unknown call edges:

## Entry-Point Trees

### TREE-001 <entry point>
- Root:
- Actor:
- Trust boundary:
- Security controls:
- Tree:
  - `<Class.method>` lines `<start-end>` [priority]
    - Inputs:
    - Calls:
    - Sinks:
    - Controls:
    - Unknowns:

## Orphan or Indirect Functions

## High-Risk Function Queue
```

## Completion Gate

The skill is complete when every discovered entry point has a tree or an explicit reason it could not be traced, and every high-risk unknown is queued for follow-up.
