# Architecture Context — JMusicBot

**Date:** 2026-05-05
**Skill:** sast-analysis
**Target:** `targets/MusicBot/`

---

## Framework

- **JDA 4.4.1_353** — Java Discord API (significantly outdated; current is 5.x)
- **jda-utilities 3.0.5** — Command framework layer on top of JDA
- **Lavaplayer 2.2.1** — Audio playback engine (YouTube, SoundCloud, HTTP streams)
- **Logback Classic 1.2.13** — Logging
- **Typesafe Config 1.3.2** — HOCON configuration
- **JSoup 1.15.3** — HTML parsing (used in TransformativeAudioSourceManager)
- **JLyrics master-SNAPSHOT** — Lyrics retrieval (unstable snapshot)

**No HTTP server.** This is a pure Discord bot. There are no REST endpoints, no web framework, no servlet container.

---

## Entry Points

Discord command/event handlers serve as all entry points. Authorization is enforced by jda-utilities role flags and explicit permission checks.

| ID | Class | Command | Auth Level | Notes |
|----|-------|---------|------------|-------|
| EP-001 | EvalCmd | `!eval <code>` | Owner | ScriptEngine.eval — dangerous by design |
| EP-002 | PlaylistCmd.MakelistCmd | `!playlist make <name>` | Owner | File creation with sanitizer |
| EP-003 | PlaylistCmd.AppendlistCmd | `!playlist append <name> <url>` | Owner | File write — NO sanitizer on name |
| EP-004 | PlaylistCmd.DeletelistCmd | `!playlist delete <name>` | Owner | File delete — weak sanitizer |
| EP-005 | PlaylistCmd.DefaultlistCmd | `!playlist default <name>` | Owner | Sets autoplay playlist |
| EP-006 | AutoplaylistCmd | `!autoplaylist <name>` | Owner | Per-guild autoplay config |
| EP-007 | SetavatarCmd | `!setavatar <url>` | Owner | HTTP fetch of user-supplied URL |
| EP-008 | SetgameCmd | `!setgame <text>` | Owner | Sets bot presence |
| EP-009 | SetnameCmd | `!setname <name>` | Owner | Sets bot username |
| EP-010 | SetstatusCmd | `!setstatus <status>` | Owner | Sets bot status |
| EP-011 | ShutdownCmd | `!shutdown` | Owner | Shuts down bot |
| EP-012 | DebugCmd | `!debug` | Owner | Dumps debug info |
| EP-013 | PlayCmd | `!play <url/query>` | DJ or configured role | Lavaplayer HTTP fetch |
| EP-014 | SearchCmd | `!search <query>` | DJ | YouTube search |
| EP-015 | SCSearchCmd | `!scsearch <query>` | DJ | SoundCloud search |
| EP-016 | QueueCmd | `!queue` | Any member | View queue |
| EP-017 | SkipCmd | `!skip` | Any member (vote) | Vote skip |
| EP-018 | NowplayingCmd | `!nowplaying` | Any member | Current track info |
| EP-019 | LyricsCmd | `!lyrics` | Any member | Fetch lyrics (JLyrics HTTP) |
| EP-020 | VolumeCmd | `!volume <n>` | DJ | Set volume |
| EP-021 | PauseCmd | `!pause` | DJ | Pause playback |
| EP-022 | StopCmd | `!stop` | DJ | Stop and clear queue |
| EP-023 | SettcCmd | `!settc <channel>` | Admin | Set text channel |
| EP-024 | SetvcCmd | `!setvc <channel>` | Admin | Set voice channel |
| EP-025 | SetdjCmd | `!setdj <role>` | Admin | Set DJ role |
| EP-026 | SkipratioCmd | `!skipratio <n>` | Admin | Set skip vote ratio |

---

## Taint Sources

- `event.getArgs()` — raw text arguments from Discord message body (all command entry points)
- `event.getMessage().getAttachments().get(0).getUrl()` — attachment URL (PlayCmd)
- `event.getGuild()` — guild object (admin commands)
- Config file (`config.txt`) — HOCON loaded at startup, attacker-influenced only if config is writable

---

## Trust Boundaries

- **Owner:** Enforced by jda-utilities `CommandEvent.isOwner()` — matches Discord user ID configured in `config.txt`. Framework-level enforcement.
- **DJ:** Checked via `DJCommand.checkDJPermission()` — requires `MANAGE_SERVER` permission OR configured DJ role ID OR owner.
- **Admin:** Checked via `AdminCommand` — requires `MANAGE_SERVER` permission OR owner.
- **Public:** No auth check — any guild member can invoke.

**CSRF:** N/A (no web interface).
**Session policy:** N/A (stateless Discord event model).
**CORS:** N/A.

---

## High-Risk Integrations

| Integration | Location | Risk |
|---|---|---|
| `ScriptEngine.eval()` | `EvalCmd.java:63` | RCE — owner input to Nashorn/Rhino |
| `Files.createFile(path+pname+".txt")` | `PlaylistLoader.java:76` | Path traversal — create |
| `Files.delete(path+pname+".txt")` | `PlaylistLoader.java:81` | Path traversal — delete |
| `Files.write(path+pname+".txt", ...)` | `PlaylistLoader.java:86` | Path traversal — write |
| `new URL(url).openConnection()` | `OtherUtil.java:106` | SSRF — owner URL fetch |
| `HttpAudioSourceManager` (Lavaplayer) | `PlayerManager.java:63` | SSRF — any member URL fetch |
| `Jsoup.connect(url).get()` | `TransformativeAudioSourceManager` | SSRF — config-driven |
| `JLyrics` HTTP requests | `LyricsCmd` | SSRF — lyrics API fetch |

---

## Flagged Dependencies

| Library | Version | Issue |
|---|---|---|
| JDA | 4.4.1_353 | Major version behind (5.x current); missing security patches |
| jda-utilities | 3.0.5 | Outdated; tied to JDA 4 |
| JLyrics | master-SNAPSHOT | Unpinned snapshot — reproducibility and supply-chain risk |
| junit | 4.13.1 | CVE-2020-15250 (test scope only; not a production risk) |
| logback-classic | 1.2.13 | Patched (CVE-2021-42550 affected <1.2.9) |

---

## Priority Focus Areas for Phase 2

1. **EP-013 (PlayCmd):** Any guild member can supply arbitrary URL to Lavaplayer's `HttpAudioSourceManager` — highest-impact SSRF surface (no auth required).
2. **EP-003 (AppendlistCmd):** Playlist name passed directly to `Files.write` with zero sanitization — confirmed path traversal write.
3. **EP-007 (SetavatarCmd):** Owner-supplied URL passed to `java.net.URL.openConnection()` — SSRF with no scheme or host validation.
4. **EP-001 (EvalCmd):** `ScriptEngine.eval(event.getArgs())` — intentional but undocumented RCE surface.
5. **DEP-001:** JDA 4.4.1_353 significantly outdated; upgrade path complex.
