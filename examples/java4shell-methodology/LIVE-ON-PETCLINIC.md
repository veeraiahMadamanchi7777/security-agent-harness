# Live end-to-end demonstration on a running Spring PetClinic

For learning. This shows the vulnerable code path exercised by a REAL HTTP
request inside the live PetClinic server process. It does NOT corrupt memory and
is NOT the CVE trigger -- it proves reachability of the exact intrinsic, live.

## What was done

1. Stock PetClinic has no route that decodes untrusted Base64, so one realistic
   feature was added: `TokenController.java.example` -> `GET /api/session?token=`
   that Base64-decodes an attacker-controlled token (models a "remember me"
   cookie / API key). It was dropped into PetClinic's source and the real app
   was rebuilt (`mvn package`).

2. PetClinic was started on Java 17 with intrinsic logging:
   `java -XX:+UnlockDiagnosticVMOptions -XX:+PrintIntrinsics -jar target/spring-petclinic-*.jar`

3. A real attacker-style request was sent, then traffic to force JIT compilation:
   ```
   curl "http://localhost:8080/api/session?token=$(printf 'userId=1&role=admin' | base64 -w0)"
   -> decoded 19 bytes
   ```

## Evidence captured from the LIVE process

```
# intrinsic ON (default): the live PetClinic JVM used the hand-written assembly
@ 63  java.util.Base64$Decoder::decodeBlock (186 bytes)   (intrinsic)

# restarted with -XX:-UseBASE64Intrinsics (interim mitigation):
count=0   # decodeBlock is no longer swapped for assembly; safe Java decoder runs
          # endpoint still works: "decoded 6 bytes"
```

So, on the actual running app:
- attacker HTTP input reached `Base64.getDecoder().decode()` in a real handler, and
- the live JVM compiled that decode into the AVX-512 intrinsic (the CVE-2026-114938
  code path), and
- the mitigation flag verifiably removes that code path while keeping the feature.

## The honest boundary
- This proves the sink is reachable and the vulnerable code runs. It is not a
  memory-corruption exploit and carries no CVE trigger.
- Stock PetClinic (no such endpoint) is not exploitable via its own routes; the
  added endpoint stands in for the countless real apps that do decode untrusted
  Base64. That gap IS the lesson: clean app code + affected JVM = exposure the
  moment any decode of attacker bytes exists.
- `TokenController.java.example` is a teaching artifact; do not ship it.
