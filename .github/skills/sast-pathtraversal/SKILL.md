# SKILL: sast-pathtraversal — Path Traversal & File Operation Detection

## References

Load [`references/java-path.md`](references/java-path.md) at the start of this skill for file operation sink table, taint source list, unsafe/safe canonicalization patterns, Zip Slip detection, traversal payload sequences, Windows/null-byte/encoding edge cases, and confidence scoring rules.

## Purpose

Identify file system operations where attacker-controlled input determines file paths, enabling directory traversal to read, write, or delete arbitrary files outside the intended directory.

---

## Phase 1: Sink Discovery

### 1.1 — File Read Operations

```bash
# new File() — most common source of path construction
grep -rn "new File(" --include="*.java" | grep -v "//\|test\|Test\|classpath\|static"

# java.nio.file.Paths
grep -rn "Paths\.get(\|Path\.of(" --include="*.java"

# FileInputStream / FileReader with dynamic path
grep -rn "new FileInputStream(\|new FileReader(\|new RandomAccessFile(" --include="*.java"

# Files utility methods
grep -rn "Files\.readAllBytes\|Files\.readAllLines\|Files\.newInputStream\|Files\.newBufferedReader\|Files\.lines(" --include="*.java"

# ClassLoader.getResource — usually safe unless path is user-controlled
grep -rn "getResource\b\|getResourceAsStream\b" --include="*.java" | grep -v "//\|static\|final\b.*\"\|classpath:"

# Spring Resource loading
grep -rn "ResourceLoader\b\|ClassPathResource\b\|FileSystemResource\b\|new UrlResource(" --include="*.java"
grep -rn "resourceLoader\.getResource(" --include="*.java" -B5 | grep -B5 "getParameter\|@PathVariable\|@RequestParam"
```

### 1.2 — File Write Operations

```bash
# FileOutputStream / FileWriter
grep -rn "new FileOutputStream(\|new FileWriter(\|new BufferedWriter(" --include="*.java"

# Files.write / Files.copy
grep -rn "Files\.write\b\|Files\.copy\b\|Files\.move\b" --include="*.java"

# File upload — where does the file land?
grep -rn "transferTo\b\|\.transferTo(\|getOriginalFilename\|getInputStream.*multipart\|FileCopyUtils" --include="*.java"

# File delete
grep -rn "\.delete()\b\|Files\.delete\b\|Files\.deleteIfExists\b" --include="*.java" | grep -v "//\|test"
```

### 1.3 — File Serving / Download

```bash
# ResponseEntity with file content
grep -rn "ResponseEntity.*byte\[\]\|ResponseEntity.*InputStreamResource\|ResponseEntity.*Resource\b" --include="*.java"

# HttpServletResponse with output stream writing file content
grep -rn "response\.getOutputStream()\|response\.getWriter()" --include="*.java" -B10 | grep -B10 "FileInputStream\|Files\.readAllBytes\|new File"

# Resource serving by filename
grep -rn "serveFile\|downloadFile\|getFile\|readFile\|loadFile" --include="*.java" -A10 | grep -A10 "@PathVariable\|@RequestParam\|getParameter"
```

### 1.4 — Archive Extraction (Zip Slip)

```bash
# ZipInputStream / ZipFile — classic Zip Slip vector
grep -rn "ZipInputStream\|ZipFile\b\|ZipEntry\b\|getNextEntry\b" --include="*.java"

# TarArchiveInputStream / Apache Commons Compress
grep -rn "TarArchiveInputStream\|TarArchiveEntry\|ArchiveInputStream\|org\.apache\.commons\.compress" --include="*.java"

# Check for path normalization in zip extraction
grep -rn "ZipEntry\b" --include="*.java" -A10 | grep -A10 "getName\b\|getPath\b" | grep -v "normalize\|canonical\|startsWith\|contains.*\\.\\."
```

---

## Phase 2: Taint Analysis

For each file operation, trace the path back to user-supplied input:

```bash
# Request parameters used as file paths
grep -rn "new File(\|Paths\.get(\|Files\.read" --include="*.java" -B15 | \
  grep -B15 "getParameter\|@RequestParam\|@PathVariable\|@RequestBody\|getHeader\|getCookies"

# Filename from multipart upload used in file operation
grep -rn "getOriginalFilename\b" --include="*.java" -A10 | grep -A10 "new File\|Paths\.get\|transferTo"

# Path built by concatenation
grep -rn "baseDir\s*+\|uploadDir\s*+\|rootPath\s*+\|storagePath\s*+" --include="*.java" | grep -v "//\|test\|Test\|static\s.*final"
```

---

## Phase 3: Defense Detection

### 3.1 — Canonicalization Check (Best Defense)

```bash
# getCanonicalPath() / normalize() — the right defense
grep -rn "getCanonicalPath\b\|normalize()\b\|\.toRealPath\b" --include="*.java"

# startsWith() check after canonicalization — proper jail check
grep -rn "getCanonicalPath\b" --include="*.java" -A3 | grep "startsWith\b"

# Pattern: correct defense
# File canonical = new File(baseDir, filename).getCanonicalFile();
# if (!canonical.getPath().startsWith(new File(baseDir).getCanonicalPath())) { throw; }
```

### 3.2 — Path Sanitization (Weaker — often bypassable)

```bash
# Replace ".." (bypassable via URL encoding, Unicode)
grep -rn "replace.*\\.\\.\|replaceAll.*\\.\\.\|strip.*\\.\\.\\|sanitize.*path" --include="*.java" -i

# Allow-listing filename characters
grep -rn "matches.*\\[a-zA-Z0-9\|Pattern.*\\.compile.*filename" --include="*.java"
```

### 3.3 — Zip Slip Defense

```bash
# Correct zip extraction with path check
grep -rn "ZipEntry\b\|getNextEntry\b" --include="*.java" -A10 | grep -A10 "canonical\|startsWith\|normalize\|contains.*\\.\\."
```

---

## Phase 4: Traversal Payload Patterns

For confirmed sinks, the following payloads demonstrate exploitability:

**Classic traversal:**
- `../../../etc/passwd`
- `..\..\..\Windows\system32\drivers\etc\hosts` (Windows)

**URL-encoded:**
- `..%2F..%2F..%2Fetc%2Fpasswd`
- `..%252F..%252F..%252Fetc%252Fpasswd` (double URL encoding)

**Unicode/UTF-8:**
- `..%c0%af..%c0%af..%c0%afetc/passwd` (overlong UTF-8)

**Windows UNC:**
- `..\\..\\..\\etc\\passwd`

**Null byte (legacy Java):**
- `../../../etc/passwd%00.jpg`

**Zip Slip entry name:**
- `../../.bashrc` inside zip file

---

## Phase 5: Severity Assessment

| Condition | Severity |
|-----------|---------|
| Unauthenticated file read (arbitrary path) | CRITICAL |
| Authenticated file read (arbitrary path) | HIGH |
| File write to arbitrary path | CRITICAL |
| File delete arbitrary path | HIGH |
| Zip Slip during extraction | HIGH |
| File read limited to known prefix (partial traversal) | MEDIUM |
| Sanitization via blacklist (bypassable) | MEDIUM |
| Filename used in upload destination | HIGH |

---

## Finding Format

Follow the canonical format from `copilot-instructions.md`. Example:

```
### [CRITICAL] Path Traversal — Arbitrary File Read via Download Endpoint

**ID:** PATH-001
**File:** `src/main/java/com/example/FileController.java:44`
**CWE:** CWE-22 | **OWASP:** A01:2021-Broken Access Control
**CVSS (estimated):** 9.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
**Confidence:** High
**Skill:** `sast-pathtraversal`

**Taint Path:**
`GET /api/files/download?filename=X` → `FileController.download(@RequestParam filename) (FileController.java:41)` → `new File("/var/app/uploads/" + filename) (FileController.java:44)` → `Files.readAllBytes(file.toPath()) (FileController.java:45)` — no canonical path check

**Vulnerable Code:**
```java
@GetMapping("/api/files/download")
public ResponseEntity<byte[]> download(@RequestParam String filename) throws IOException {
    File file = new File("/var/app/uploads/" + filename);
    byte[] content = Files.readAllBytes(file.toPath());
    return ResponseEntity.ok()
        .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
        .body(content);
}
```

**Why Exploitable:**
`filename` is taken from `@RequestParam` and concatenated directly into a `File` path without a canonical-path containment check. An attacker uses `../` sequences (or URL-encoded variants) to escape the `/var/app/uploads/` directory and read arbitrary files accessible to the JVM process.

**Proof-of-Concept:**
```http
GET /api/files/download?filename=../../../etc/passwd HTTP/1.1
GET /api/files/download?filename=..%2F..%2F..%2Fetc%2Fshadow HTTP/1.1
GET /api/files/download?filename=../../../proc/self/environ HTTP/1.1
```
Zip Slip variant: if the endpoint also extracts ZIP uploads, supply a ZIP entry named `../../.bashrc`.

**Remediation:**
```java
File base = new File("/var/app/uploads/").getCanonicalFile();
File target = new File(base, filename).getCanonicalFile();
if (!target.getPath().startsWith(base.getPath() + File.separator)) {
    throw new SecurityException("Path traversal attempt detected");
}
byte[] content = Files.readAllBytes(target.toPath());
```

**References:** https://cwe.mitre.org/data/definitions/22.html, OWASP A01:2021
```

JSONL line (append to `.github/sast-findings.jsonl`):
```json
{"id":"PATH-001","skill":"sast-pathtraversal","cwe":"CWE-22","owasp":"A01:2021-Broken Access Control","severity":"Critical","confidence":"High","file":"src/main/java/com/example/FileController.java","line":44,"method":"download","class":"com.example.FileController","evidence":"File file = new File(\"/var/app/uploads/\" + filename);\nbyte[] content = Files.readAllBytes(file.toPath());","sink":"Files.readAllBytes()","source":"@RequestParam String filename","taint_path":[],"sanitizer_present":false,"sanitizer_detail":"","remediation":"Use getCanonicalFile() and assert target path starts with base path before reading","references":["https://cwe.mitre.org/data/definitions/22.html"],"false_positive_indicators":[],"duplicate_of":null}
```
