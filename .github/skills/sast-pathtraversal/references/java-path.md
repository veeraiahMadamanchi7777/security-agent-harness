# Java Path Traversal / Zip Slip — SAST Reference

> Lookup table for AI agents scanning Java code for path traversal vulnerabilities.
> Produced at senior AppSec engineer depth. Every claim is based on documented CVEs and OWASP guidance.

---

## 1. Taint Sources

Sources are ranked by how directly they carry attacker-controlled data.

| Source | Trust Risk | Notes |
|---|---|---|
| `@RequestParam String filename` | **CRITICAL** | Direct user input; no implicit sanitization |
| `@RequestParam String path` | **CRITICAL** | Direct user input; often contains `../` sequences |
| `@PathVariable String filename` | **CRITICAL** | URL-decoded by Spring before reaching handler |
| `@PathVariable String path` | **CRITICAL** | URL-decoded; `%2f` becomes `/` depending on `UrlPathHelper` config |
| `MultipartFile.getOriginalFilename()` | **CRITICAL** | Browser-supplied; attacker fully controls this string |
| `request.getParameter("file")` | **CRITICAL** | Raw servlet input; no sanitization |
| `request.getHeader("X-File-Name")` | **HIGH** | Custom header; trivially spoofed |
| `request.getPart("file").getSubmittedFileName()` | **HIGH** | Same risk as `getOriginalFilename()` |
| `@RequestHeader String contentDisposition` | **HIGH** | Attacker-supplied; `Content-Disposition: filename=../etc/passwd` |
| `ServletRequest.getServletPath()` | **MEDIUM** | Container-decoded but can be manipulated by encoded slashes |
| `System.getProperty("user.input.*")` | **LOW** | Only tainted if set from user input at launch |
| Environment variables via `System.getenv()` | **LOW** | Controlled at deploy-time, not request-time |

---

## 2. Sinks

### 2a. `java.io` — File Construction

| API | Safe? | Reason |
|---|---|---|
| `new File(basePath, userInput)` | **UNSAFE** | Two-arg constructor does not prevent traversal; `../` still works |
| `new File(userInput)` | **UNSAFE** | Absolute paths and traversal accepted |
| `new FileInputStream(userInput)` | **UNSAFE** | Resolves path at OS level without canonicalization |
| `new FileOutputStream(userInput)` | **UNSAFE** | Write-path traversal; can overwrite arbitrary files |
| `new FileReader(userInput)` | **UNSAFE** | Same as `FileInputStream` |
| `new FileWriter(userInput)` | **UNSAFE** | Same as `FileOutputStream` |
| `new RandomAccessFile(userInput, "rw")` | **UNSAFE** | Read/write arbitrary file |
| `new File(canonicalBase).toPath().resolve(userInput)` | **UNSAFE** | `resolve()` replaces base if `userInput` is absolute |
| `canonicalFile.getCanonicalPath().startsWith(baseDir)` followed by use | **SAFE** | Canonical containment check — see Remediation section |

### 2b. `java.nio.file` — NIO Paths

| API | Safe? | Reason |
|---|---|---|
| `Paths.get(userInput)` | **UNSAFE** | Accepts absolute paths and `..` segments |
| `Paths.get(base, userInput)` | **UNSAFE** | Same issue as two-arg `new File()` |
| `Path.of(userInput)` | **UNSAFE** | Alias for `Paths.get()` (Java 11+) |
| `Files.readAllBytes(Paths.get(userInput))` | **UNSAFE** | Full read of attacker-chosen file |
| `Files.lines(Paths.get(userInput))` | **UNSAFE** | Streaming read; same risk |
| `Files.write(Paths.get(userInput), data)` | **UNSAFE** | Arbitrary write |
| `Files.copy(src, Paths.get(userInput))` | **UNSAFE** | File creation at arbitrary path |
| `Files.newInputStream(Paths.get(userInput))` | **UNSAFE** | Same as `FileInputStream` |
| `Files.newOutputStream(Paths.get(userInput))` | **UNSAFE** | Same as `FileOutputStream` |
| `basePath.resolve(userInput).normalize()` | **CONDITIONALLY SAFE** | Safe only if followed by `startsWith(basePath)` check |
| `basePath.resolve(userInput).normalize().toAbsolutePath()` + `startsWith` | **SAFE** | Full canonical containment pattern |

### 2c. Zip / Archive — Zip Slip

| API | Safe? | Reason |
|---|---|---|
| `ZipEntry.getName()` used in `new File(destDir, entry.getName())` | **UNSAFE** | Classic Zip Slip; `../` in entry name escapes destination |
| `ZipInputStream.getNextEntry().getName()` → direct file creation | **UNSAFE** | Same pattern via streaming API |
| `ZipFile.entries()` iterated without validation | **UNSAFE** | Each entry name must be validated |
| `TarArchiveEntry.getName()` (Apache Commons Compress) | **UNSAFE** | Same Zip Slip risk in tar archives |
| `ZipEntry.getName()` validated with canonical containment before use | **SAFE** | See Remediation for correct pattern |

### 2d. Apache Commons IO / Lang

| API | Safe? | Reason |
|---|---|---|
| `FileUtils.readFileToString(new File(userInput))` | **UNSAFE** | Wrapper; underlying `File` is unvalidated |
| `FileUtils.copyFile(src, new File(userInput))` | **UNSAFE** | Write traversal |
| `FilenameUtils.getName(userInput)` | **SAFE** | Returns only the filename component; strips all directory info |
| `FilenameUtils.normalize(userInput)` | **CONDITIONALLY SAFE** | Resolves `..` but does NOT enforce base-directory containment |
| `FilenameUtils.normalize(userInput, true)` (Unix separator) | **CONDITIONALLY SAFE** | Same caveat — must still check against base |

---

## 3. Unsafe Patterns

Patterns listed as regex-style pseudocode and literal code examples that signal vulnerability.

### Pattern 1 — Direct concatenation into File/Path

```java
// VULNERABLE: user input concatenated into file path
String filename = request.getParameter("file");
File f = new File("/uploads/" + filename);          // traversal possible

Path p = Paths.get("/uploads/" + filename);         // same risk

new FileInputStream("/data/" + userFile);           // same risk
```

### Pattern 2 — Two-argument File constructor (false sense of safety)

```java
// VULNERABLE: two-arg constructor does NOT prevent ../
File base = new File("/uploads");
File target = new File(base, userInput);            // userInput = "../../etc/passwd" works
```

### Pattern 3 — `resolve()` without `startsWith()` check

```java
// VULNERABLE: resolve replaces base when userInput is absolute
Path base = Paths.get("/uploads");
Path resolved = base.resolve(userInput);            // if userInput = "/etc/passwd", base is discarded
```

### Pattern 4 — `normalize()` alone (insufficient)

```java
// VULNERABLE: normalize resolves .. but allows escape from intended root
Path p = Paths.get("/uploads/" + userInput).normalize();
// userInput = "../../etc/passwd" → normalized = "/etc/passwd"
```

### Pattern 5 — Zip Slip

```java
// VULNERABLE: Classic Zip Slip pattern
ZipInputStream zis = new ZipInputStream(uploadedStream);
ZipEntry entry;
while ((entry = zis.getNextEntry()) != null) {
    File outFile = new File(destDir, entry.getName());  // UNSAFE
    Files.copy(zis, outFile.toPath());
}
```

### Pattern 6 — MultipartFile saved without stripping path

```java
// VULNERABLE: original filename used directly
MultipartFile file = ...;
String name = file.getOriginalFilename();           // could be "../../etc/cron.d/evil"
Files.copy(file.getInputStream(), Paths.get("/uploads/" + name));
```

---

## 4. Confidence Scoring Guide

| Scenario | Confidence | Rationale |
|---|---|---|
| Taint flows from `@RequestParam` / `@PathVariable` directly to `new File()` or `Files.*` with no intervening check | **High** | Clear unvalidated taint path; exploitable as-is |
| `MultipartFile.getOriginalFilename()` used in file write path without `FilenameUtils.getName()` | **High** | Well-documented Zip Slip / upload traversal pattern |
| Zip entry name used in file construction inside loop, no canonical check | **High** | Textbook Zip Slip; CVE-documented pattern |
| `Paths.get(base, userInput)` without `startsWith()` | **High** | No sanitization present |
| `normalize()` applied but no `startsWith()` containment check | **Medium** | Partial mitigation; `..` resolved but escape still possible |
| `FilenameUtils.normalize()` used (not `getName()`) — then passed to `new File()` | **Medium** | Resolves `..` but does not enforce root; attacker may use absolute path |
| Two-argument `new File(base, userInput)` without canonical check | **Medium-High** | Commonly mistaken as safe; still exploitable |
| User input validated against an allowlist before path construction | **Low** | Allowlist reduces risk significantly; verify allowlist is complete |
| `FilenameUtils.getName()` applied, result used under enforced base dir | **Low** | `getName()` strips all path components; residual risk only from symlinks |
| User input passes through a regex/allowlist that permits only `[a-zA-Z0-9._-]+` | **Low** | Properly restricts traversal characters |
| Input comes from internal config or environment variable (not user request) | **Low** | Not user-controlled at request time |

---

## 5. Remediation

### Fix 1 — Canonical Path Containment Check (preferred for `java.io`)

```java
public File safeResolve(File baseDir, String userInput) throws IOException {
    // Step 1: resolve against base and get canonical (symlink-resolved) path
    File resolved = new File(baseDir, userInput).getCanonicalFile();

    // Step 2: verify the resolved path is inside the base directory
    String canonicalBase = baseDir.getCanonicalPath();
    if (!resolved.getPath().startsWith(canonicalBase + File.separator)
            && !resolved.getPath().equals(canonicalBase)) {
        throw new SecurityException("Path traversal attempt detected: " + userInput);
    }
    return resolved;
}
```

### Fix 2 — NIO `Path.normalize()` + `startsWith()` containment check

```java
public Path safeResolvePath(Path baseDir, String userInput) throws IOException {
    Path base = baseDir.toRealPath();                           // resolves symlinks
    Path resolved = base.resolve(userInput).normalize().toAbsolutePath();

    if (!resolved.startsWith(base)) {
        throw new SecurityException("Path traversal attempt: " + userInput);
    }
    return resolved;
}
```

### Fix 3 — File upload: strip path with `FilenameUtils.getName()`

```java
import org.apache.commons.io.FilenameUtils;

public void handleUpload(MultipartFile file, Path uploadDir) throws IOException {
    String originalName = file.getOriginalFilename();
    // Strip all directory components — result is filename only
    String safeName = FilenameUtils.getName(originalName);

    // Additional allowlist: only alphanumeric, dots, dashes, underscores
    if (!safeName.matches("[a-zA-Z0-9._-]+")) {
        throw new IllegalArgumentException("Invalid filename: " + safeName);
    }

    Path destination = uploadDir.resolve(safeName).normalize().toAbsolutePath();
    if (!destination.startsWith(uploadDir.toAbsolutePath())) {
        throw new SecurityException("Path escape detected");
    }
    Files.copy(file.getInputStream(), destination, StandardCopyOption.REPLACE_EXISTING);
}
```

### Fix 4 — Zip Slip remediation

```java
public void extractZip(InputStream zipStream, Path destDir) throws IOException {
    Path canonicalDest = destDir.toRealPath();

    try (ZipInputStream zis = new ZipInputStream(zipStream)) {
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            // Validate BEFORE constructing the output path
            Path entryPath = canonicalDest.resolve(entry.getName()).normalize().toAbsolutePath();
            if (!entryPath.startsWith(canonicalDest)) {
                throw new SecurityException("Zip Slip detected in entry: " + entry.getName());
            }

            if (entry.isDirectory()) {
                Files.createDirectories(entryPath);
            } else {
                Files.createDirectories(entryPath.getParent());
                Files.copy(zis, entryPath, StandardCopyOption.REPLACE_EXISTING);
            }
            zis.closeEntry();
        }
    }
}
```

### Fix 5 — Filename allowlist (strictest approach)

```java
private static final Pattern SAFE_FILENAME = Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9._-]{0,254}$");

public String validateFilename(String userInput) {
    String name = FilenameUtils.getName(userInput);         // strip path
    if (!SAFE_FILENAME.matcher(name).matches()) {
        throw new IllegalArgumentException("Filename contains disallowed characters");
    }
    return name;
}
```

---

## 6. Java-Specific Notes

### Windows Path Separators
- Windows accepts both `\` and `/` as separators. Checks like `contains("..")` may miss `..\\` on mixed-OS deployments.
- Tomcat on Windows historically resolved `file.jsp\` to `file.jsp`, bypassing filters.
- Use `FilenameUtils.normalize(path, true)` (Unix separator mode) to normalize before checking, or use `File.getCanonicalPath()` which is OS-aware.

### URL Encoding Bypasses
- `%2e%2e%2f` decodes to `../`. Spring's `DispatcherServlet` URL-decodes `@PathVariable` before the handler sees it, so the value arriving in the method parameter may already be decoded.
- Double-encoding: `%252e%252e%252f` → `%2e%2e%2f` → `../` if the application decodes twice (e.g., manually calling `URLDecoder.decode()`).
- Some containers normalize `//` to `/`, but others pass it through. Absolute URLs with `//` may bypass prefix checks.

### Null Byte Injection (Legacy JVMs)
- On JVMs prior to Java 7u40 (approximately), `new File("evil.txt\0.jpg")` would truncate at the null byte at the OS level, resolving to `evil.txt`. This bypassed extension filters that checked the Java string.
- Modern JVMs (7u40+) throw `NullPointerException` or `InvalidPathException` for null bytes in paths.
- Scanners should still flag null-byte patterns (`\0`, `%00`) in user-controlled filenames for defense-in-depth.

### Symlink Attacks
- `getCanonicalPath()` resolves symlinks. However, there is a TOCTOU window between `getCanonicalPath()` and the actual file operation. An attacker with local file system access can swap the target with a symlink during this window.
- In high-security contexts, use `Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)` to refuse symlinks entirely.

### Spring `@PathVariable` Slash Encoding
- By default, Spring does not allow `/` inside `@PathVariable` even when encoded as `%2F`. Tomcat may reject such requests before they reach Spring. However, with `UrlPathHelper.setUrlDecode(false)` or certain reverse proxy configurations, `%2F` may pass through and be decoded late.
- Flag any configuration that sets `setUrlDecode(false)` alongside path-variable file lookups.

### Apache Commons `FilenameUtils.normalize()` Caveat
- `normalize("/uploads/../etc/passwd")` returns `/etc/passwd` — it resolves `..` but the result is still an absolute path outside the intended directory.
- `FilenameUtils.getName("/uploads/../etc/passwd")` returns `"passwd"` — this is the safe method when you only need the filename.
- Do not confuse these two methods. `normalize()` is NOT a security function for enforcing base-directory containment.

### `Path.resolve()` with Absolute Input
- `Paths.get("/safe/base").resolve("/etc/passwd")` returns `/etc/passwd`. The absolute user input completely replaces the base.
- This is a common mistake when developers believe `resolve()` is analogous to path concatenation. Always call `.normalize().toAbsolutePath()` and then `.startsWith(base)`.

### Resource Loading via ClassLoader
- `getClass().getResourceAsStream(userInput)` can be used for path traversal within the classpath. Restrict to a known prefix (e.g., `"/templates/" + safeName`).

### Encoding in ZIP Entry Names
- ZIP specification does not mandate UTF-8. Some archives encode entry names in local code pages. Java's `ZipInputStream` defaults to UTF-8; a mismatch can result in unexpected `../` sequences after name parsing.
- Always validate after Java has parsed the name string, not on the raw bytes.
