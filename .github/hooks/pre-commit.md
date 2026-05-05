# Pre-Commit Security Review Hook

Use this hook as a lightweight review before committing Java changes.

## Trigger

Run when staged changes include:

- `*.java`
- `*.xml`
- `*.properties`
- `*.yml`
- `*.yaml`
- `pom.xml`
- `build.gradle`
- `build.gradle.kts`

## Review Steps

1. Inspect only changed files and directly related callers/callees.
2. Run `sast-analysis` only if entry points, security configuration, or dependency files changed.
3. Run the relevant Phase 2 skills for changed surfaces:
   - SQL or repository changes: `sast-sqli`
   - command/process/reflection/template changes: `sast-rce`, `sast-templateinject`
   - controller/auth/session/JWT changes: `sast-auth`, `sast-idor`, `sast-csrf`, `sast-massassignment`
   - XML parsing: `sast-xxe`
   - HTTP clients or URL handling: `sast-ssrf`, `sast-openredirect`
   - file operations: `sast-pathtraversal`
   - crypto or secrets: `sast-crypto`, `sast-secrets`
   - deserialization: `sast-deserial`
   - dependency changes: `sast-dependency`
4. Report only actionable findings with exact changed-line evidence.

## Blocking Guidance

Block the commit only for Critical or High confidence findings introduced by the staged change. Medium and Low findings should be reported with remediation guidance but do not block by default.
