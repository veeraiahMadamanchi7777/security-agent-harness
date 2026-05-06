# Taint Trees — JMusicBot

**Date:** 2026-05-05
**Skill:** sast-taint-tree

---

## TT-001: AppendlistCmd → path traversal write

```
SOURCE: event.getArgs()                                        [PlaylistCmd.java:149]
  │  Discord message text body — attacker-controlled string
  │  e.g. "../config some-url"
  │
  ▼ parts = event.getArgs().split("\\s+", 2)                  [PlaylistCmd.java:149]
  │  Splits on whitespace. parts[0] = "../config"
  │  NO transformation of path characters
  │
  ▼ pname = parts[0]                                           [PlaylistCmd.java:149]
  │  Tainted string: "../config"
  │
  ▼ bot.getPlaylistLoader().writePlaylist(pname, content)      [PlaylistCmd.java:167]
  │  pname passed unchanged
  │
  ▼ PlaylistLoader.writePlaylist(String name, String text)     [PlaylistLoader.java:83]
  │  name = "../config"
  │
  ▼ path = OtherUtil.getPath(folder + File.separator + name + ".txt")
  │  path = "/app/playlists/../config.txt"                     [PlaylistLoader.java:85]
  │  Normalized by JVM: "/app/config.txt"
  │
  ▼ Files.write(path, text.getBytes())                         [PlaylistLoader.java:86]  ★ SINK
     Writes attacker-supplied content to /app/config.txt
     Impact: config file overwrite → bot token replacement → full bot takeover
```

**Missing control:** Input sanitization on `pname` in `AppendlistCmd`.
**Exploitability:** High — direct path construction with no guard.

---

## TT-002: DeletelistCmd → path traversal delete

```
SOURCE: event.getArgs()                                        [PlaylistCmd.java:111]
  │  Discord message text: e.g. "../../important-file"
  │
  ▼ pname = event.getArgs().replaceAll("\\s+", "_")           [PlaylistCmd.java:111]
  │  "../../important-file" → "../../important-file" (unchanged, no slashes stripped)
  │
  ▼ bot.getPlaylistLoader().deletePlaylist(pname)              [PlaylistCmd.java:118]
  │
  ▼ PlaylistLoader.deletePlaylist(String name)                 [PlaylistLoader.java:78]
  │
  ▼ path = OtherUtil.getPath(folder + sep + name + ".txt")    [PlaylistLoader.java:80]
  │  path = "/app/playlists/../../important-file.txt"
  │
  ▼ Files.delete(path)                                         [PlaylistLoader.java:81]  ★ SINK
     Deletes arbitrary .txt file outside playlists folder
```

**Missing control:** Path character stripping and dot-dot check in `DeletelistCmd`.

---

## TT-003: SetavatarCmd → SSRF

```
SOURCE: event.getArgs()                                        [SetavatarCmd.java:51]
  │  Discord message text: e.g. "file:///etc/passwd"
  │                          or "http://169.254.169.254/latest/meta-data/"
  │
  ▼ url = event.getArgs()                                      [SetavatarCmd.java:51]
  │  No transformation
  │
  ▼ OtherUtil.imageFromUrl(url)                                [SetavatarCmd.java:52]
  │
  ▼ URL u = new URL(url)                                       [OtherUtil.java:104]
  │  Parses any URL scheme
  │
  ▼ URLConnection conn = u.openConnection()                    [OtherUtil.java:106]  ★ SINK
  │  Opens connection to attacker-specified host
  │
  ▼ conn.getInputStream()                                      [OtherUtil.java:108]
     Response content read into memory
     Impact: internal network probing, metadata service access, local file read (file://)
```

**Missing control:** URL scheme allowlist, RFC-1918 blocklist.
**Exploitability:** Requires owner account compromise; then enables internal network recon.

---

## TT-004: PlayCmd → Public SSRF via Lavaplayer

```
SOURCE: event.getArgs()                                        [PlayCmd.java:86]
  │  Discord message text from any guild member: e.g. "http://192.168.1.1/admin"
  │  OR event.getMessage().getAttachments().get(0).getUrl()   [PlayCmd.java:88]
  │
  ▼ args = event.getArgs() (or attachment URL)                 [PlayCmd.java:86-91]
  │  No URL validation
  │
  ▼ bot.getPlayerManager().loadItemOrdered(guild, args, ...)   [PlayCmd.java:92]
  │
  ▼ audioPlayerManager.loadItemOrdered(guild, args, handler)   [PlayerManager.java:72]
  │  Lavaplayer source manager chain iterates registered managers
  │
  ▼ HttpAudioSourceManager.loadItem(AudioReference ref)        [PlayerManager.java:63 registration]  ★ SINK
     Lavaplayer fetches the URL via Apache HttpClient
     Impact: SSRF — any guild member can probe internal network, cloud metadata endpoints
```

**Missing control:** URL scheme/host allowlist before passing to Lavaplayer.
**Exploitability:** Any guild member (no DJ role required in default config). Highest-impact finding.

---

## Hypotheses (Unconfirmed — Require Manual Verification)

### [HYPOTHESIS] H-001: BotConfig reads attacker-controlled external file

If `config.txt` is writable by a compromised owner (via PATH-001 overwrite), subsequent bot restarts would load attacker-modified config including a replaced bot token. This creates a **two-step takeover chain**: PATH-001 write to config.txt → bot restart → attacker controls bot token.

**What would confirm:** Verify that `config.txt` path is inside the playlists folder (likely not, reducing risk), or that the playlist folder path traversal can actually reach `config.txt`.

### [HYPOTHESIS] H-002: LyricsCmd SSRF via query injection

JLyrics constructs search URLs from `event.getArgs()`. If JLyrics does not properly encode the query, URL injection may be possible. However, since the URL is constructed by JLyrics (not passed directly), and the attacker cannot control the base URL, exploitability is low.

**What would confirm:** Read JLyrics source to check URL construction and encoding.

### [HYPOTHESIS] H-003: DebugCmd information disclosure

`DebugCmd` dumps JVM and bot state. If this includes environment variables or memory contents containing the bot token, it could leak credentials to the owner (who already has access, so risk is minimal). Not exploitable by non-owners.
