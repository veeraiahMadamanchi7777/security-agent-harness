# Security Report Format Reference

The final report should be concise, ranked, and evidence-first. Readers should be able to reproduce and fix each issue without re-running the scan.

## Required Qualities

- Findings are sorted by exploitable risk, not by discovery order.
- Every finding includes exact file and line evidence.
- Every finding explains attacker-controlled source, sink, missing defense, and impact.
- Remediation names the concrete API or code pattern to use.
- Duplicate sinks are grouped under one root-cause finding.

## Severity Language

- **Critical:** remote, unauthenticated, high-impact compromise with a direct exploit path.
- **High:** authenticated exploit, privilege escalation, significant data exposure, or one-step chain from a reachable endpoint.
- **Medium:** constrained exploitability, limited impact, or missing defense under specific conditions.
- **Low:** hardening issue with weak direct exploitability.
- **Informational:** architectural observation, not a vulnerability.

## Rejection Reasons

Use clear reasons:

- `No attacker-controlled source`
- `Sink is test-only`
- `Evidence line does not match source`
- `Sanitizer appears effective`
- `Third-party code outside scope`
- `Dependency present but vulnerable feature not reachable`
