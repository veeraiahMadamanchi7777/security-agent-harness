---
name: sast-file-upload
description: Review Java file upload, import, archive, and media handling for unsafe storage, content validation, malware risk, and webroot exposure.
---

# SKILL: sast-file-upload — File Upload and Import Review

## Purpose

Find unsafe file upload and import flows beyond basic path traversal.

Load [`references/java-file-upload.md`](references/java-file-upload.md).

## Method

1. Identify multipart endpoints, import jobs, media upload APIs, archive extraction, and file processors.
2. Review filename generation, storage location, extension/content validation, size limits, archive limits, and post-upload execution exposure.
3. Trace uploaded content into parsers, template engines, XML/YAML/deserialization, antivirus hooks, and public serving paths.
4. Review authorization for upload, download, overwrite, delete, and sharing.

## Searches

```bash
rg -n "MultipartFile|Part|getSubmittedFileName|transferTo|Files\\.copy|ZipInputStream|TarArchive|CommonsMultipartResolver|contentType|getOriginalFilename|upload|import" --glob "*.java"
```

## True Positive Signals

- User filename used for storage or public path.
- Upload stored inside webroot or executable classpath.
- Extension allowlist missing or based only on client content type.
- No size, count, decompression, or nested archive limits.
- Uploaded content is parsed by dangerous XML/YAML/template/deserialization code.
- Public download lacks owner or tenant authorization.

## Output

Include upload endpoint, file trust boundary, storage path, processing sinks, missing controls, and exploit scenario.
