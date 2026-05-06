# Function Review — JMusicBot

**Date:** 2026-05-05
**Skill:** sast-function-review

---

## FR-001: EvalCmd.execute

**File:** `src/main/java/com/jagrosh/jmusicbot/commands/owner/EvalCmd.java`
**Class:** `com.jagrosh.jmusicbot.commands.owner.EvalCmd`
**Auth:** Owner-only (jda-utilities framework enforcement)

**What it does:** Accepts any text from the Discord message body and passes it verbatim to a `ScriptEngine` (Nashorn/Rhino). The result is echoed back to Discord.

**Data accepted:** `event.getArgs()` — unbounded string, attacker-controlled (constrained only to bot owner).

**Security controls present:**
- jda-utilities `ownerCommand = true` — enforces Discord user ID match at framework level before `execute()` is called.

**Security controls absent:**
- No input validation, no sandboxing of the ScriptEngine, no restriction to safe API subsets.
- Nashorn/Rhino can call any Java API including `Runtime.exec()`, file I/O, network access.

**Assessment:** Intentional design — this is a debug/power-user tool. Risk materializes only if the owner's Discord account is compromised. Should be disabled by default (already is per docs) and should restrict usage to DMs.

---

## FR-002: PlaylistLoader.writePlaylist

**File:** `src/main/java/com/jagrosh/jmusicbot/playlist/PlaylistLoader.java`
**Method:** `writePlaylist(String name, String text)`
**Called from:** `PlaylistCmd.AppendlistCmd.execute`

**What it does:** Writes `text` to a file at `<playlistsFolder>/<name>.txt`.

**Data accepted:** `name` is passed in directly from `AppendlistCmd`, which takes it from `event.getArgs().split("\\s+", 2)[0]` with **no sanitization whatsoever**.

**Security controls present:** None.

**Security controls absent:**
- No path character stripping.
- No dot-dot check.
- No canonical path validation.

**Assessment:** Confirmed path traversal write. A name like `../config` would write to `<playlistsFolder>/../config.txt`, potentially overwriting the bot's configuration file.

---

## FR-003: PlaylistLoader.createPlaylist

**File:** `src/main/java/com/jagrosh/jmusicbot/playlist/PlaylistLoader.java`
**Method:** `createPlaylist(String name)`
**Called from:** `PlaylistCmd.MakelistCmd.execute`

**What it does:** Creates a new empty file at `<playlistsFolder>/<name>.txt`.

**Data accepted:** `name` is sanitized in `MakelistCmd` by stripping `\s`, `*`, `?`, `|`, `/`, `\`, `"`, `:`, `<`, `>`. However, `..` (dot-dot) is **not** stripped.

**Security controls present:** Partial — forward/backslash removed.

**Security controls absent:** Dot-dot not stripped. No canonical path check.

**Assessment:** Partial path traversal. Pure `..` (without slashes) may allow directory traversal depending on JVM/OS behavior. On Linux, `..` alone resolves relative to the folder, potentially creating `../` if combined with OS path semantics. Requires dot-dot check and canonical path guard.

---

## FR-004: PlaylistLoader.deletePlaylist

**File:** `src/main/java/com/jagrosh/jmusicbot/playlist/PlaylistLoader.java`
**Method:** `deletePlaylist(String name)`
**Called from:** `PlaylistCmd.DeletelistCmd.execute`

**What it does:** Deletes the file at `<playlistsFolder>/<name>.txt`.

**Data accepted:** `name` from `event.getArgs().replaceAll("\\s+", "_")` — only whitespace is replaced; **no path character stripping** of any kind.

**Security controls present:** Whitespace-to-underscore replacement only.

**Security controls absent:** No slash stripping, no dot-dot check, no canonical path check.

**Assessment:** Confirmed path traversal delete. Attacker could delete `../../config.txt` (or similar) by providing a name containing `../..`.

---

## FR-005: OtherUtil.imageFromUrl

**File:** `src/main/java/com/jagrosh/jmusicbot/utils/OtherUtil.java`
**Method:** `imageFromUrl(String url)`
**Called from:** `SetavatarCmd.execute`

**What it does:** Opens a `URLConnection` to the provided URL and returns an `InputStream` for the image data.

**Data accepted:** `url` from `event.getArgs()` — fully attacker-controlled string.

**Security controls present:** `try/catch IOException` — swallows errors silently.

**Security controls absent:**
- No URL scheme validation (accepts `file://`, `gopher://`, `dict://`, etc.).
- No host validation.
- No RFC-1918 / loopback / link-local blocking.
- No redirect following limit.

**Assessment:** Confirmed SSRF. Owner-restricted, but any owner account compromise enables internal network probing.

---

## FR-006: PlayerManager — HttpAudioSourceManager registration

**File:** `src/main/java/com/jagrosh/jmusicbot/audio/PlayerManager.java`
**Method:** `init()`
**Called from:** `Bot` startup

**What it does:** Registers Lavaplayer audio source managers including `HttpAudioSourceManager`, which fetches arbitrary HTTP/HTTPS URLs as audio sources.

**Data accepted:** Any string passed to `audioPlayerManager.loadItem(identifier, ...)` — in the `!play` command, `identifier = event.getArgs()` from any guild member.

**Security controls present:** None at the URL level. Lavaplayer may internally reject non-audio content types.

**Security controls absent:**
- No URL scheme allowlist.
- No host/IP blocklist.
- No RFC-1918 filtering.

**Assessment:** Confirmed SSRF. This is the highest-impact finding because it is reachable by **any guild member** without elevated permissions (assuming no DJ role is configured, or in default configurations).
