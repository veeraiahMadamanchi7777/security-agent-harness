# SKILL: sast-templateinject — Server-Side Template Injection Detection

## Purpose

Identify Java code paths where attacker-controlled input is evaluated as a server-side template expression, enabling data disclosure, sandbox escape, or remote code execution.

---

## Phase 1: Sink Discovery

### 1.1 — Template Engines

```bash
# Thymeleaf dynamic templates and expression parsing
grep -rn "TemplateEngine\|process(\|StringTemplateResolver\|SpringTemplateEngine" --include="*.java"
grep -rn "th:utext\|\\[\\[.*\\]\\]\|\\$\\{.*\\}" --include="*.html" --include="*.xml"

# FreeMarker
grep -rn "freemarker\|Configuration\|Template\b\|process(" --include="*.java"
grep -rn "\\?new\\|<#assign\\|\\${" --include="*.ftl"

# Velocity
grep -rn "VelocityEngine\|VelocityContext\|evaluate(\|mergeTemplate" --include="*.java"

# Pebble / Mustache / Handlebars
grep -rn "PebbleEngine\|Mustache\|Handlebars\|compileInline\|compile(" --include="*.java"

# Spring Expression Language
grep -rn "SpelExpressionParser\|parseExpression\|getValue(" --include="*.java"
```

### 1.2 — Dynamic Template Construction

```bash
# User-controlled template string candidates
grep -rn "template\s*=\|templateName\s*=\|viewName\s*=\|expression\s*=" --include="*.java"

# Inline template evaluation
grep -rn "evaluate(\|parseExpression(\|compileInline(\|new Template(" --include="*.java" -B10 -A5
```

---

## Phase 2: Taint Analysis

Trace values passed to template evaluation from:

```bash
grep -rn "@RequestParam\|@PathVariable\|@RequestBody\|getParameter\|getHeader\|getQueryString" --include="*.java"
```

Confirm:

1. Attacker controls the template string or expression, not just safe model data.
2. The template engine evaluates expressions, method calls, class references, or includes.
3. No allowlist restricts template names to static server-side files.

Model values rendered into a fixed server-side template are usually XSS or output-encoding questions, not server-side template injection.

---

## Phase 3: Defense Detection

Effective defenses:

```bash
# Static view-name allowlists
grep -rn "allowedViews\|allowedTemplates\|templateAllowlist\|contains(viewName)" --include="*.java" -i

# Sandboxed or restricted resolvers
grep -rn "setNewBuiltinClassResolver\|TemplateClassResolver\|MemberAccess\|sandbox" --include="*.java" -i

# Escaped output rendering
grep -rn "th:text\|escapeHtml\|HtmlUtils\.htmlEscape" --include="*.java" --include="*.html"
```

Weak defenses:

- blocking `${` but allowing `#{`, `*{`, `@{`, or engine-specific expression forms
- checking for `http` or `../` when the sink is expression evaluation
- HTML escaping after server-side evaluation has already occurred

---

## Finding Format

Emit findings using `.github/schemas/finding.schema.json`.

Recommended CWE: `CWE-1336`.

Example sink names:

- `SpelExpressionParser.parseExpression().getValue()`
- `VelocityEngine.evaluate()`
- `freemarker.template.Template.process()`
- `TemplateEngine.process()`

---

## Self-Contained Check

This skill runs independently. If `.github/sast-context.md` exists, use it to prioritize controller and request-handling code; otherwise scan all Java source and template files.
