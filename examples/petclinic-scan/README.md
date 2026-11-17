# Example run: Spring PetClinic

Executable scanner run against [spring-petclinic](https://github.com/spring-projects/spring-petclinic), the reference Spring Boot sample app (commit `500158f`, shallow clone).

```bash
git clone --depth 1 https://github.com/spring-projects/spring-petclinic.git /path/to/spring-petclinic
python3 tools/scan.py /path/to/spring-petclinic --output scan-results/petclinic
```

## Result

- Scan complete: 30/30 non-test Java files parsed, 87 methods, 0 parse errors, exit code 0.
- **0 candidates.** This is expected for a clean sample app: queries go through Spring Data repositories, Thymeleaf templates use escaped `th:text` with no `th:utext`, and every controller's `@InitBinder` disallows `id` binding.

Zero findings is not a security certification. A quick manual review of areas outside the rules' coverage found these points. They are acceptable for a demo app but should be fixed before deploying something built on it:

| Area | Observation | Skill |
|---|---|---|
| Auth / IDOR | No Spring Security dependency. All `/owners/{ownerId}/**` read and edit endpoints are unauthenticated. | sast-auth, sast-idor |
| CSRF | No CSRF protection on state-changing POST forms. | sast-csrf |
| Actuator | `management.endpoints.web.exposure.include=*` exposes all actuator endpoints (env, heapdump, etc.). The file comments that this is dev-only. | sast-headers / config |
| Error handling | `/oups` (`CrashController`) throws on purpose to demo the error page. | sast-logging |
