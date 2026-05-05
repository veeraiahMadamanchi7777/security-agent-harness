# Pre-Push Security Review Hook

Use this hook as a broader review before pushing Java application changes.

## Trigger

Run when the branch changes Java source, security configuration, dependency manifests, or framework routing files.

## Review Steps

1. Run `sast-analysis` to refresh `.github/sast-context.md`.
2. Run all Phase 2 skills that match changed application surfaces.
3. If dependency manifests changed, run `sast-dependency`.
4. Consolidate with `sast-report`.
5. Highlight any new Critical or High findings first.

## Blocking Guidance

Block the push for confirmed Critical findings and for High findings that are remotely reachable or affect authentication, authorization, secrets, RCE, SQL injection, SSRF, deserialization, or path traversal.

If a finding is pre-existing and unchanged, include it in the report but mark it as pre-existing when the version-control context allows that determination.
