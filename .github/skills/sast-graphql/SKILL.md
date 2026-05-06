---
name: sast-graphql
description: Review Java GraphQL APIs for resolver authorization, batching abuse, introspection exposure, injection, and excessive data access.
---

# SKILL: sast-graphql — GraphQL Security Review

## Purpose

Find GraphQL-specific weaknesses that ordinary REST-oriented review may miss.

Load [`references/java-graphql.md`](references/java-graphql.md).

## Method

1. Identify GraphQL frameworks, schema files, resolvers, data fetchers, and controller endpoints.
2. Map queries and mutations to resolver functions.
3. Verify object-level authorization per resolver and nested field.
4. Review query depth, complexity, batching, introspection, and data loader behavior.
5. Trace resolver arguments into database, file, network, template, and state-changing sinks.

## Searches

```bash
rg -n "GraphQL|@QueryMapping|@MutationMapping|@SchemaMapping|DataFetcher|RuntimeWiring|graphqls|GraphQLQuery|GraphQLMutation|DataLoader|MaxQueryDepth|Instrumentation" --glob "*.java" --glob "*.graphqls"
```

## True Positive Signals

- Resolver loads objects by ID without ownership or tenant checks.
- Field resolver exposes sensitive nested data not protected by parent authorization.
- Mutations trust client-supplied owner, role, tenant, status, or price.
- Query depth/complexity/batching permits denial of service or scraping.
- Introspection is exposed on production with sensitive schema or admin operations.

## Output

Include GraphQL operation, resolver path, missing control, affected object/field, and exploit query shape.
