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

Follow the canonical format from `copilot-instructions.md`. Example:

```
### [CRITICAL] Template Injection — User Input Used as Thymeleaf Template Expression

**ID:** SSTI-001
**File:** `src/main/java/com/example/GreetingController.java:31`
**CWE:** CWE-1336 | **OWASP:** A03:2021-Injection
**CVSS (estimated):** 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
**Confidence:** High
**Skill:** `sast-templateinject`

**Taint Path:**
`GET /greet?name=X` → `GreetingController.greet(@RequestParam name) (GreetingController.java:29)` → `return "Hello " + name;` used as Thymeleaf view name `(GreetingController.java:31)` → template engine evaluates expressions in name

**Vulnerable Code:**
```java
@GetMapping("/greet")
public String greet(@RequestParam String name, Model model) {
    return "Hello " + name;  // ← returned as view name, not model data
}
```

**Why Exploitable:**
When a Spring MVC controller returns a `String`, Thymeleaf interprets it as a view name and evaluates it as a template. If `name` contains Thymeleaf expression syntax (e.g., `__${T(java.lang.Runtime).getRuntime().exec('id')}__`), the engine executes the expression server-side, achieving RCE.

**Proof-of-Concept:**
```http
GET /greet?name=__${T(java.lang.Runtime).getRuntime().exec('id')}__ HTTP/1.1
```

**Remediation:**
Return a static view name and pass user input via the `Model`:
```java
@GetMapping("/greet")
public String greet(@RequestParam String name, Model model) {
    model.addAttribute("name", name);  // name is model data, not template
    return "greetingView";             // static view name
}
```

**References:** https://cwe.mitre.org/data/definitions/1336.html, OWASP A03:2021
```

Recommended sink names: `SpelExpressionParser.parseExpression().getValue()`, `VelocityEngine.evaluate()`, `freemarker.template.Template.process()`, `TemplateEngine.process()`

JSONL line (append to `.github/sast-findings.jsonl`):
```json
{"id":"SSTI-001","skill":"sast-templateinject","cwe":"CWE-1336","owasp":"A03:2021-Injection","severity":"Critical","confidence":"High","file":"src/main/java/com/example/GreetingController.java","line":31,"method":"greet","class":"com.example.GreetingController","evidence":"return \"Hello \" + name;","sink":"Thymeleaf view name evaluated as template","source":"@RequestParam String name","taint_path":[],"sanitizer_present":false,"sanitizer_detail":"","remediation":"Return a static view name string; pass name as model attribute only","references":["https://cwe.mitre.org/data/definitions/1336.html"],"false_positive_indicators":[],"duplicate_of":null}
```

---

## Self-Contained Check

This skill runs independently. If `.github/sast-context.md` exists, use it to prioritize controller and request-handling code; otherwise scan all Java source and template files.
