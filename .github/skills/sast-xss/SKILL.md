---
name: sast-xss
description: Detect reflected, stored, and server-rendered XSS in Java MVC, template, API, and HTML response flows.
---

# SKILL: sast-xss — Cross-Site Scripting Review

## Purpose

Find attacker-controlled data rendered into browser-executed contexts without context-appropriate encoding or safe templating.

Load [`references/java-xss.md`](references/java-xss.md).

## Method

1. Identify browser-facing responses: MVC templates, `ModelAndView`, raw `HttpServletResponse`, HTML strings, error pages, emails rendered as HTML, and JSON embedded into pages.
2. Trace request or stored user-controlled values into HTML body, attributes, JavaScript, CSS, URL, Markdown, rich text, or template fragments.
3. Verify context-aware encoding at the exact output context.
4. Distinguish safe escaped template variables from unsafe raw HTML, expression preprocessing, dynamic fragments, and manual response writes.

## Searches

```bash
rg -n "ModelAndView|addAttribute|HttpServletResponse|getWriter\\(|ResponseEntity|text/html|HtmlUtils|StringEscapeUtils|th:utext|\\?no_esc|raw\\(|SafeHtml|Markdown|sanitize" --glob "*.java" --glob "*.html"
```

## True Positive Signals

- User input reaches `response.getWriter().write(...)` with `text/html`.
- Template uses raw output such as Thymeleaf `th:utext`, Freemarker `?no_esc`, or unsafe helpers.
- Stored rich text or Markdown is rendered without a proven sanitizer allowlist.
- JSON is embedded into inline scripts without JavaScript-context encoding.
- Error messages reflect request parameters into HTML.

## Output

For confirmed findings, include source, storage path if stored, output context, missing encoder or sanitizer, exploit payload class, and safe remediation.
