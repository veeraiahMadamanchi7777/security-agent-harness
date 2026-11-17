# Java security candidate report

Analysis completed within documented scope. 22 findings; 335/335 Java files parsed.

Candidates are not confirmed vulnerabilities. Zero findings is not a security certification. Severity is provisional.

## Findings

### SECRET-001 · High · candidate · CWE-798

src/main/java/org/owasp/webgoat/lessons/challenges/SolutionConstants.java:10 (<field>)

Source: literal configuration in source

Sink: credential literal

    [REDACTED credential literal]

Remediation: Remove the credential literal, rotate it if real, and use a managed secret store or runtime configuration.

Review: Syntactic API/type matching: verify actual library types and runtime reachability. Candidate only: verify deployment context and compensating controls.

### DESERIAL-001 · High · candidate · CWE-502

src/main/java/org/owasp/webgoat/lessons/deserialization/InsecureDeserializationTask.java:43 (completed)

Source: Spring-bound parameter token

Sink: new ObjectInputStream()

            new ObjectInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(b64token)))) {

Remediation: Replace native deserialization of untrusted data with an explicit schema; otherwise enforce an ObjectInputFilter allowlist.

Review: Syntactic API/type matching: verify actual library types and runtime reachability. Candidate only: verify deployment context and compensating controls. Propagation includes unresolved call semantics or a recursion/depth bound.

### SECRET-002 · High · candidate · CWE-798

src/main/java/org/owasp/webgoat/lessons/jwt/JWTRefreshEndpoint.java:45 (<field>)

Source: literal configuration in source

Sink: credential literal

    [REDACTED credential literal]

Remediation: Remove the credential literal, rotate it if real, and use a managed secret store or runtime configuration.

Review: Syntactic API/type matching: verify actual library types and runtime reachability. Candidate only: verify deployment context and compensating controls.

### PATH-001 · High · candidate · CWE-22

src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUploadRetrieval.java:101 (getProfilePicture)

Source: Servlet request getParameter()

Sink: new File()

              new File(catPicturesDirectory, (id == null ? RandomUtils.nextInt(1, 11) : id) + ".jpg");

Remediation: Resolve under an allowed base directory and verify containment, including symlinks, before file operations.

Review: Syntactic API/type matching: verify actual library types and runtime reachability. Candidate only: verify deployment context and compensating controls. Propagation includes unresolved call semantics or a recursion/depth bound.

### PATH-002 · High · candidate · CWE-22

src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileZipSlip.java:79 (processZipUpload)

Source: Spring-bound parameter file

Sink: new File()

            File f = new File(tmpZipDirectory.toFile(), e.getName());

Remediation: Resolve under an allowed base directory and verify containment, including symlinks, before file operations.

Review: Syntactic API/type matching: verify actual library types and runtime reachability. Candidate only: verify deployment context and compensating controls. Propagation includes unresolved call semantics or a recursion/depth bound.

### PATH-003 · High · candidate · CWE-22

src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileZipSlip.java:81 (processZipUpload)

Source: Spring-bound parameter file

Sink: copy()

            Files.copy(is, f.toPath(), StandardCopyOption.REPLACE_EXISTING);

Remediation: Resolve under an allowed base directory and verify containment, including symlinks, before file operations.

Review: Syntactic API/type matching: verify actual library types and runtime reachability. Candidate only: verify deployment context and compensating controls. Propagation includes unresolved call semantics or a recursion/depth bound.

### SQLI-001 · High · candidate · CWE-89

src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionChallenge.java:61 (registerNewUser)

Source: Spring-bound parameter username

Sink: executeQuery()

            ResultSet resultSet = statement.executeQuery(checkUserQuery);

Remediation: Use constant SQL/JPQL with bound parameters, not concatenated request values.

Review: Syntactic API/type matching: verify actual library types and runtime reachability. Candidate only: verify deployment context and compensating controls.

### SQLI-002 · High · candidate · CWE-89

src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6a.java:72 (executeSqlInjection)

Source: Spring-bound parameter userId

Sink: executeQuery()

          ResultSet results = statement.executeQuery(query);

Remediation: Use constant SQL/JPQL with bound parameters, not concatenated request values.

Review: Syntactic API/type matching: verify actual library types and runtime reachability. Candidate only: verify deployment context and compensating controls.

### SQLI-003 · High · candidate · CWE-89

src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson10.java:56 (injectableQueryAvailability)

Source: Spring-bound parameter action_string

Sink: executeQuery()

            ResultSet results = statement.executeQuery(query);

Remediation: Use constant SQL/JPQL with bound parameters, not concatenated request values.

Review: Syntactic API/type matching: verify actual library types and runtime reachability. Candidate only: verify deployment context and compensating controls.

### SQLI-004 · High · candidate · CWE-89

src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson2.java:49 (injectableQuery)

Source: Spring-bound parameter query

Sink: executeQuery()

          ResultSet results = statement.executeQuery(query);

Remediation: Use constant SQL/JPQL with bound parameters, not concatenated request values.

Review: Syntactic API/type matching: verify actual library types and runtime reachability. Candidate only: verify deployment context and compensating controls.

### SQLI-005 · High · candidate · CWE-89

src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson3.java:47 (injectableQuery)

Source: Spring-bound parameter query

Sink: executeUpdate()

            statement.executeUpdate(query);

Remediation: Use constant SQL/JPQL with bound parameters, not concatenated request values.

Review: Syntactic API/type matching: verify actual library types and runtime reachability. Candidate only: verify deployment context and compensating controls.

### SQLI-006 · High · candidate · CWE-89

src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson4.java:46 (injectableQuery)

Source: Spring-bound parameter query

Sink: executeUpdate()

            statement.executeUpdate(query);

Remediation: Use constant SQL/JPQL with bound parameters, not concatenated request values.

Review: Syntactic API/type matching: verify actual library types and runtime reachability. Candidate only: verify deployment context and compensating controls.

### SQLI-007 · High · candidate · CWE-89

src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson5a.java:52 (injectableQuery)

Source: Spring-bound parameter account

Sink: executeQuery()

            ResultSet results = statement.executeQuery(query);

Remediation: Use constant SQL/JPQL with bound parameters, not concatenated request values.

Review: Syntactic API/type matching: verify actual library types and runtime reachability. Candidate only: verify deployment context and compensating controls.

### SQLI-008 · High · candidate · CWE-89

src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson5b.java:48 (injectableQuery)

Source: Spring-bound parameter userid

Sink: prepareStatement()

              connection.prepareStatement(
                  queryString, ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY);

Remediation: Use constant SQL/JPQL with bound parameters, not concatenated request values.

Review: Syntactic API/type matching: verify actual library types and runtime reachability. Candidate only: verify deployment context and compensating controls.

### SQLI-009 · High · candidate · CWE-89

src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson8.java:62 (injectableQueryConfidentiality)

Source: Spring-bound parameter name

Sink: executeQuery()

            ResultSet results = statement.executeQuery(query);

Remediation: Use constant SQL/JPQL with bound parameters, not concatenated request values.

Review: Syntactic API/type matching: verify actual library types and runtime reachability. Candidate only: verify deployment context and compensating controls.

### SQLI-010 · High · candidate · CWE-89

src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson8.java:142 (log)

Source: Spring-bound parameter name

Sink: executeUpdate()

          statement.executeUpdate(logQuery);

Remediation: Use constant SQL/JPQL with bound parameters, not concatenated request values.

Review: Syntactic API/type matching: verify actual library types and runtime reachability. Candidate only: verify deployment context and compensating controls. Propagation includes unresolved call semantics or a recursion/depth bound.

### SQLI-011 · High · candidate · CWE-89

src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson9.java:65 (injectableQueryIntegrity)

Source: Spring-bound parameter name

Sink: execute()

          statement.execute(queryInjection);

Remediation: Use constant SQL/JPQL with bound parameters, not concatenated request values.

Review: Syntactic API/type matching: verify actual library types and runtime reachability. Candidate only: verify deployment context and compensating controls.

### SSRF-001 · High · candidate · CWE-918

src/main/java/org/owasp/webgoat/lessons/ssrf/SSRFTask2.java:36 (furBall)

Source: Spring-bound parameter url

Sink: openStream()

          try (InputStream in = new URL(url).openStream()) {

Remediation: Allowlist destinations and schemes, block private/link-local addresses, and revalidate redirects and DNS resolution.

Review: Syntactic API/type matching: verify actual library types and runtime reachability. Candidate only: verify deployment context and compensating controls.

### PATH-004 · High · candidate · CWE-22

src/main/java/org/owasp/webgoat/webwolf/FileServer.java:92 (importFile)

Source: Spring-bound parameter multipartFile

Sink: deleteIfExists()

          Files.deleteIfExists(destinationFile);

Remediation: Resolve under an allowed base directory and verify containment, including symlinks, before file operations.

Review: Syntactic API/type matching: verify actual library types and runtime reachability. Candidate only: verify deployment context and compensating controls. Propagation includes unresolved call semantics or a recursion/depth bound.

### PATH-005 · High · candidate · CWE-22

src/main/java/org/owasp/webgoat/webwolf/FileServer.java:93 (importFile)

Source: Spring-bound parameter multipartFile

Sink: copy()

          Files.copy(is, destinationFile);

Remediation: Resolve under an allowed base directory and verify containment, including symlinks, before file operations.

Review: Syntactic API/type matching: verify actual library types and runtime reachability. Candidate only: verify deployment context and compensating controls. Propagation includes unresolved call semantics or a recursion/depth bound.

### PATH-006 · High · candidate · CWE-22

src/main/java/org/owasp/webgoat/webwolf/FileServer.java:95 (importFile)

Source: Spring-bound parameter multipartFile

Sink: new File()

        log.debug("File saved to {}", new File(destinationDir, multipartFile.getOriginalFilename()));

Remediation: Resolve under an allowed base directory and verify containment, including symlinks, before file operations.

Review: Syntactic API/type matching: verify actual library types and runtime reachability. Candidate only: verify deployment context and compensating controls. Propagation includes unresolved call semantics or a recursion/depth bound.

### CRYPTO-001 · Medium · candidate · CWE-327

src/main/java/org/owasp/webgoat/lessons/cryptography/HashingAssignment.java:39 (getMd5)

Source: literal configuration in source

Sink: getInstance()

          MessageDigest md = MessageDigest.getInstance("MD5");

Remediation: Use modern algorithms appropriate to the security purpose, such as AES-GCM for encryption; review keys and nonces separately.

Review: Syntactic API/type matching: verify actual library types and runtime reachability. Candidate only: verify deployment context and compensating controls.

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
- src/it
- src/test

## AI security and business-logic review

Status: disabled

Coverage is model-reported; completed review is not proof of complete detection.

