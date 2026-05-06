# Phase 1 Java Foundation

## Goal

Build the first executable foundation for the Java-only security-agent-harness. Phase 1 is not a full scanner. It is an evidence collection layer that produces reliable Java project facts for later agent reasoning.

## Design Principle

```text
Evidence collectors prove facts.
Agents reason about security.
Validators reject weak findings.
```

Do not make regex scripts the brain of the system. The first milestone should collect trustworthy facts from Java code using an AST-first approach.

## Parser Decision

Use JavaParser as the primary parser for Phase 1 because the harness is Java-only and needs Java-aware information such as packages, imports, annotations, methods, parameters, and method calls.

Tree-sitter can be added later as a fast fallback parser, but JavaParser should own the first implementation.

## Phase 1 Scope

### Week 1 — Java Parser Setup

- Add a Java-based AST collector.
- Parse a real Spring Boot controller.
- Extract package name, imports, class name, class annotations, method signatures, method annotations, method parameters, and method calls.
- Output machine-readable facts.

Validation rule: avoid regex for Java structure extraction. Use AST output.

### Week 2 — Evidence Collectors

Create collectors for:

- Spring entry points
- Servlet entry points
- Struts action entry points
- request parameter/header/body sources
- JDBC/JPA/file-operation sinks

Initial test target: WebGoat or another intentionally vulnerable Java application.

### Week 3 — Knowledge Graph

Create a JSON knowledge graph:

- nodes = classes, methods, entry points, sources, sinks
- edges = calls, contains, receives-input, reaches-sink candidates

Minimum question to answer:

```text
Can attacker-controlled input reach this sink candidate?
```

Manual validation is required before agent reasoning is trusted.

## Proposed Repository Structure

```text
harness-core/
├── build.gradle.kts
└── src/main/java/dev/securityharness/
    ├── Main.java
    ├── model/
    └── collector/

scripts/
├── scan.py
├── collect_project_facts.py
├── validate_evidence.py
└── validate_findings.py
```

## Success Criteria

Phase 1 is complete when:

- the tool can parse a real Java project
- it can extract Spring controller facts
- it can identify basic source and sink candidates
- it can write facts JSON
- at least one manually validated source-to-sink candidate is represented in the graph

## Non-Goals

- Do not implement full vulnerability detection in Phase 1.
- Do not generate final security findings without validation.
- Do not claim exploitability until source, propagation path, sink, and missing control are all represented with evidence.
