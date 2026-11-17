# Java security candidate report

Analysis completed within documented scope. 0 findings; 30/30 Java files parsed.

Candidates are not confirmed vulnerabilities. Zero findings is not a security certification. Severity is provisional.

## Findings

No candidates were emitted within this rule set and scan scope.

## Errors

None.

## Coverage and required review

- sast-api-abuse: review-required
- sast-attack-chain: review-required
- sast-auth: review-required
- sast-business-logic: review-required
- sast-cache: review-required
- sast-cors: review-required
- sast-crypto: partial-candidate-analysis
- sast-csrf: review-required
- sast-dependency: review-required
- sast-deserial: partial-candidate-analysis
- sast-file-upload: review-required
- sast-graphql: review-required
- sast-grpc: review-required
- sast-headers: review-required
- sast-idor: review-required
- sast-ldap: partial-candidate-analysis
- sast-logging: review-required
- sast-massassignment: review-required
- sast-oauth: review-required
- sast-openredirect: partial-candidate-analysis
- sast-pathtraversal: partial-candidate-analysis
- sast-rce: partial-candidate-analysis
- sast-secrets: partial-candidate-analysis
- sast-sqli: partial-candidate-analysis
- sast-ssrf: partial-candidate-analysis
- sast-templateinject: partial-candidate-analysis
- sast-websocket: review-required
- sast-xss: partial-candidate-analysis
- sast-xxe: partial-candidate-analysis

## Limitations

- Candidates need review: runtime reachability, authorization and exploitability are not proven.
- API/type matching is syntactic. Unique same-class name/arity helpers are followed to depth 8. External calls, overloads and dynamic dispatch are unresolved.
- Conservative branch/loop joins, with no path feasibility, heap/alias analysis, field taint or implicit flows. Loops use two analysis iterations.
- Sources: explicitly bound Spring parameters and servlet request accessors. Implicit binding, Struts and other frameworks require review.
- Custom sanitizers and context-dependent encoders are not trusted; primitive numeric parsing is recognized.
- Dependency CVEs, IDOR, authorization, authentication, business logic and runtime behavior require separate review.
- Secrets rules cover named string-literal variables only. Obfuscated secrets and inherited configuration can be missed.

## Excluded paths

- .git
- src/test

## AI security and business-logic review

Status: disabled

Coverage is model-reported; completed review is not proof of complete detection.

