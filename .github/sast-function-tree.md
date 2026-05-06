# Function Tree — JMusicBot

**Date:** 2026-05-05
**Skill:** sast-function-tree

All entry points are Discord command `execute()` methods dispatched by jda-utilities `CommandClient`.

---

## High-Risk Call Chains

### Chain 1 — EvalCmd → ScriptEngine.eval (RCE)

```
EvalCmd.execute(CommandEvent event)                            [EvalCmd.java:43]
  └─ se.eval(event.getArgs())                                  [EvalCmd.java:63]  ★ SINK
       └─ Nashorn/Rhino JS engine evaluates arbitrary Java-capable script
```

**Risk:** RCE. `event.getArgs()` is raw Discord message content with zero transformation.

---

### Chain 2 — PlaylistCmd.AppendlistCmd → Files.write (Path Traversal Write)

```
PlaylistCmd.AppendlistCmd.execute(CommandEvent event)          [PlaylistCmd.java:143]
  ├─ parts = event.getArgs().split("\\s+", 2)                  [PlaylistCmd.java:149]
  ├─ pname = parts[0]                                          [PlaylistCmd.java:149]  NO SANITIZATION
  ├─ bot.getPlaylistLoader().writePlaylist(pname, content)     [PlaylistCmd.java:167]
  │     └─ PlaylistLoader.writePlaylist(String name, String text)  [PlaylistLoader.java:83]
  │           └─ Files.write(                                  [PlaylistLoader.java:86]  ★ SINK
  │                 OtherUtil.getPath(folder + sep + name + ".txt"),
  │                 text.getBytes())
```

**Risk:** Path traversal write. `pname` has no sanitization.

---

### Chain 3 — PlaylistCmd.MakelistCmd → Files.createFile (Path Traversal Create)

```
PlaylistCmd.MakelistCmd.execute(CommandEvent event)            [PlaylistCmd.java:68]
  ├─ pname = event.getArgs()
  │         .replaceAll("\\s+", "_")
  │         .replaceAll("[*?|\\/\":<>]", "")                   [PlaylistCmd.java:74-75]  PARTIAL SANITIZER
  ├─ bot.getPlaylistLoader().createPlaylist(pname)             [PlaylistCmd.java:84]
  │     └─ PlaylistLoader.createPlaylist(String name)          [PlaylistLoader.java:73]
  │           └─ Files.createFile(                             [PlaylistLoader.java:76]  ★ SINK
  │                 OtherUtil.getPath(folder + sep + name + ".txt"))
```

**Risk:** Partial path traversal. `..` not stripped. Forward/backslash stripped but dotdot traversal possible on some OSes.

---

### Chain 4 — PlaylistCmd.DeletelistCmd → Files.delete (Path Traversal Delete)

```
PlaylistCmd.DeletelistCmd.execute(CommandEvent event)          [PlaylistCmd.java:105]
  ├─ pname = event.getArgs().replaceAll("\\s+", "_")           [PlaylistCmd.java:111]  WEAK SANITIZER
  ├─ bot.getPlaylistLoader().deletePlaylist(pname)             [PlaylistCmd.java:118]
  │     └─ PlaylistLoader.deletePlaylist(String name)          [PlaylistLoader.java:78]
  │           └─ Files.delete(                                 [PlaylistLoader.java:81]  ★ SINK
  │                 OtherUtil.getPath(folder + sep + name + ".txt"))
```

**Risk:** Path traversal delete. Only whitespace sanitization applied; no path char stripping.

---

### Chain 5 — SetavatarCmd → OtherUtil.imageFromUrl → URL.openConnection (SSRF)

```
SetavatarCmd.execute(CommandEvent event)                       [SetavatarCmd.java:43]
  ├─ url = event.getArgs()                                     [SetavatarCmd.java:51]  NO SANITIZATION
  ├─ OtherUtil.imageFromUrl(url)                               [SetavatarCmd.java:52]
  │     └─ OtherUtil.imageFromUrl(String url)                  [OtherUtil.java:99]
  │           ├─ URL u = new URL(url)                          [OtherUtil.java:104]
  │           └─ URLConnection conn = u.openConnection()       [OtherUtil.java:106]  ★ SINK
  └─ event.getSelfUser().getManager().setAvatar(icon).queue()
```

**Risk:** SSRF. Any URL scheme accepted (file://, gopher://, http://, etc.).

---

### Chain 6 — PlayCmd → PlayerManager → HttpAudioSourceManager (Public SSRF)

```
PlayCmd.doCommand(CommandEvent event)                          [PlayCmd.java:76]
  ├─ args = event.getArgs()                                    [PlayCmd.java:86]
  │   OR  event.getMessage().getAttachments().get(0).getUrl() [PlayCmd.java:88]
  ├─ bot.getPlayerManager().loadItemOrdered(guild, args, ...)  [PlayCmd.java:92]
  │     └─ PlayerManager.loadItemOrdered(guild, identifier, handler)
  │           └─ audioPlayerManager.loadItemOrdered(...)       [PlayerManager.java:72]
  │                 └─ HttpAudioSourceManager.loadItem(ref)    [PlayerManager.java:63 registration]  ★ SINK
```

**Risk:** SSRF. Available to any guild member with Play permission (or all members if no DJ role configured). Lavaplayer fetches arbitrary URLs.

---

### Chain 7 — LyricsCmd → JLyrics HTTP (SSRF via SNAPSHOT dependency)

```
LyricsCmd.execute(CommandEvent event)                          [LyricsCmd.java]
  └─ GeniusSearcher / other searcher → HTTP request           ★ SINK (external, SNAPSHOT dep)
```

**Risk:** SSRF via unstable snapshot dependency; limited exploitability (query is bot-determined, not raw user input passed as URL).

---

## Low-Risk Chains (No Confirmed Vulnerability)

| Chain | Description | Conclusion |
|---|---|---|
| SkipCmd → AudioHandler.skip() | Vote skip, ratio-gated | No injection surface |
| VolumeCmd → AudioHandler.setVolume(int) | Parsed as int, bounded | No injection |
| QueueCmd → FormatUtil.filter() | Read-only display | No injection |
| SettingsCmd → SettingsManager.getSettings() | Read-only | No injection |
| DebugCmd → JDA.getStatus(), heap info | Read-only dump | Information disclosure to owner only |
| ShutdownCmd → System.exit(0) | Owner-only | Intentional |

---

## High-Risk Node Queue

| Node | File | Risk Class | Reviewed? |
|---|---|---|---|
| `EvalCmd.execute` | EvalCmd.java:43 | RCE | Yes — see sast-function-review.md |
| `PlaylistLoader.writePlaylist` | PlaylistLoader.java:83 | Path Traversal | Yes |
| `PlaylistLoader.createPlaylist` | PlaylistLoader.java:73 | Path Traversal | Yes |
| `PlaylistLoader.deletePlaylist` | PlaylistLoader.java:78 | Path Traversal | Yes |
| `OtherUtil.imageFromUrl` | OtherUtil.java:99 | SSRF | Yes |
| `PlayerManager` HttpAudioSourceManager | PlayerManager.java:63 | SSRF | Yes |
