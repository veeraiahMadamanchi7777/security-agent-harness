# Java XSS Reference

## High-Risk Sinks

- `HttpServletResponse.getWriter().write`.
- Returning raw HTML strings from controllers.
- `ResponseEntity<String>` with `text/html`.
- Thymeleaf `th:utext`.
- Freemarker `?no_esc`.
- JSP scriptlets and unescaped Expression Language in old configurations.
- Markdown or rich-text rendering.

## Safer Controls

- Framework auto-escaping in the right context.
- OWASP Java Encoder: `Encode.forHtml`, `forHtmlAttribute`, `forJavaScript`, `forCssString`, `forUriComponent`.
- Strict HTML sanitizer allowlist for rich text.
- Avoid inline JavaScript with user-controlled values.

## False Positive Checks

- Template variables may be escaped by default.
- JSON APIs are not XSS unless consumed in a browser-executed context or served with dangerous content type.
- Sanitization must match context; HTML body escaping does not protect JavaScript string context.
