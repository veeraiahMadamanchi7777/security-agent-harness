# Java File Upload Reference

## Controls

- Server-generated filenames.
- Store outside webroot and classpath.
- Exact extension allowlist plus content sniffing where appropriate.
- Size limits, file count limits, archive depth and expansion limits.
- Malware scanning for high-risk environments.
- Canonical path containment.
- Per-object authorization for download/delete/share.

## Risky Follow-On Sinks

- XML parsing.
- ImageMagick/native media processing.
- Template rendering.
- YAML/deserialization parsing.
- Archive extraction.
- Static serving from uploaded path.
