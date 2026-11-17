# How to learn what Java4Shell does without the real trigger

You can't see the real CVE-2026-114938 (no public trigger, and you shouldn't need
one). But the bug is an *instance of a well-understood class*: a hand-written
native decoder miscounts output length and writes past a heap buffer. You learn
what it does by reproducing that class in a sandbox you control and observing it.

Three safe, observable layers, cheapest first:

## Layer 1 - Build a faithful miniature of the bug class  (`minibase64.c`)
A tiny native Base64 decoder with the SAME shape of mistake as the intrinsic:
it writes 3 output bytes for every 4 input chars, even for a padded final group
("Mw==" decodes to 1 byte but the buggy loop writes 3). Raw pointers, no bounds
checks -- exactly like the JVM intrinsic, unlike normal bounds-checked Java.

```bash
gcc -g -fsanitize=address minibase64.c -o mb_asan && ./mb_asan   # caught + located
gcc -g               minibase64.c -o mb       && ./mb            # silent corruption
```

Observed here:
- Under ASan: `heap-buffer-overflow ... WRITE of size 1 ... 0 bytes after a
  1-byte region ... in decode_buggy minibase64.c:49`. The sanitizer turns the
  invisible bug into a precise, located crash. **This is how it is found.**
- Without ASan: `exit=0`, no error -- the 2 extra bytes landed in adjacent heap
  memory. **This is why it is dangerous:** a production JVM says nothing.

That single contrast is the core of the vulnerability: a length miscount in
unchecked native code either (a) gets caught by a sanitizer during research, or
(b) silently corrupts memory in production, which is the attacker's foothold.

## Layer 2 - Watch the REAL intrinsic activate (no bug, just the mechanism)
On a running JVM (e.g. PetClinic's), prove HotSpot swaps the safe Java decoder
for the hand-written assembly -- see `ON-PETCLINIC.md`:
```bash
java -XX:+UnlockDiagnosticVMOptions -XX:+PrintIntrinsics DecodeToken | grep -i base64
# -> java.util.Base64$Decoder::decodeBlock ... (intrinsic)
```
You're now looking at the real code path (safe to run) that the real bug lives
in -- without any exploit.

## Layer 3 - Read the actual assembly the JVM emits
```bash
java -XX:+UnlockDiagnosticVMOptions -XX:+PrintAssembly \
     -XX:CompileCommand=print,java.util.Base64$Decoder::decodeBlock ...   # needs hsdis
```
Line up the vector loads/stores against the input length registers and you can
see where a tail would be mishandled. This is the same artifact a researcher
reads to confirm the exact off-by-N and to verify a fix.

## Why you can learn it fully this way
- The *mechanism* (miscount -> OOB write -> silent corruption -> potential RCE)
  is identical whether it's our 50-line C model or the JVM's AVX-512 routine.
- Layer 1 shows the effect, Layer 2 shows the real code path is active, Layer 3
  shows the real code. Together that is the whole bug, minus a weaponized trigger
  you don't need in order to understand, detect, or mitigate it.
- To then *find* the real one you add the detection methodology in `README.md`
  (differential fuzzing + boundary inputs + an ASan JVM oracle).

## Boundaries
No exploit, no CVE trigger, no heap grooming. `minibase64.c` is an intentionally
buggy teaching model, not derived from OpenJDK source. Mitigate real systems per
your vendor advisory (`-XX:-UseBASE64Intrinsics` as an interim, patched JVM as the fix).
