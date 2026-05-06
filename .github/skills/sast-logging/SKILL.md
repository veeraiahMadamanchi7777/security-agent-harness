---
name: sast-logging
description: Review Java logging and error handling for sensitive data exposure, log injection, unsafe audit gaps, and verbose exception leakage.
---

# SKILL: sast-logging — Logging, Errors, and Audit Review

## Purpose

Find security issues in logs, error responses, and audit trails: secret leakage, PII leakage, log injection, stack trace disclosure, and missing audit for sensitive actions.

Load [`references/java-logging.md`](references/java-logging.md).

## Method

1. Identify logging calls, exception handlers, audit events, access logs, and error controllers.
2. Trace secrets, tokens, passwords, PII, session IDs, auth headers, and reset links into logs or responses.
3. Check whether user-controlled log fields can inject new log lines or spoof audit records.
4. Check whether critical security actions lack audit events.

## Searches

```bash
rg -n "log\\.|Logger|printStackTrace|ExceptionHandler|ControllerAdvice|sendError|errorMessage|Authorization|password|token|secret|apiKey|session|audit|MDC" --glob "*.java"
```

## True Positive Signals

- Credentials, bearer tokens, JWTs, API keys, reset links, or session IDs logged.
- Stack traces or internal exception messages returned to clients.
- User input logged without neutralizing CR/LF where logs drive audit or alerts.
- Security-sensitive actions lack audit events: login failures, password reset, MFA changes, role changes, payment/admin actions.

## Output

Include data exposed or audit gap, log/error sink, actor, impact, and redaction/audit remediation.
