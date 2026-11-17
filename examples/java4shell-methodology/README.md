# How a JVM intrinsic bug like Java4Shell (CVE-2026-114938) is found

Educational walkthrough of the *methodology* security researchers use to find
memory bugs in JVM intrinsics. It includes a working differential fuzzer
(`Base64DiffFuzz.java`). It is a **detector**, not an exploit: it looks for
inputs where two decoders disagree. It never attempts memory corruption or code
execution, and it contains no exploit for the real CVE.

## Why these bugs exist (recap)

Java code is bounds-checked, so an app's own `Base64.getDecoder().decode()` call
cannot normally corrupt memory. But on CPUs with AVX-512, HotSpot replaces the
Java decoder with a hand-written assembly **intrinsic** (added in JDK-8268276).
That assembly does raw pointer math with no automatic bounds checks. A wrong
length calculation there reads or writes outside the buffer -- a heap bug that
the application code cannot cause and cannot see.

## The five techniques, in the order a researcher reaches for them

### 1. Differential testing (what the demo does)
Run the same input through two implementations that *must* agree:
the intrinsic vs. the pure-Java decoder. Any mismatch means one of them
miscounts. This is the cheapest, highest-signal first pass.

```bash
javac Base64DiffFuzz.java
java -XX:+UseBASE64Intrinsics Base64DiffFuzz 42 2000000 > intrinsic.txt
java -XX:-UseBASE64Intrinsics Base64DiffFuzz 42 2000000 > plain.txt
diff intrinsic.txt plain.txt   # any line = a candidate bug
```
`-XX:-UseBASE64Intrinsics` forces the safe path, so you are comparing the exact
same JVM with and without the hand-written assembly. A clean `diff` (our result)
means the generic fuzzer did not hit the trigger -- not that no bug exists.

### 2. Boundary-aware input generation
Random strings rarely hit the bug. The AVX-512 path handles 64-byte blocks plus
a scalar "tail", so mistakes cluster at block boundaries and in tail handling.
The fuzzer biases lengths toward `n*64 +/- a few` and injects mid-stream padding
(`=`) to stress exactly those seams. Real research narrows further: lengths that
leave 1, 2, or 3 leftover chars; inputs that are all-valid except the final
group; MIME vs. URL-safe alphabets.

### 3. Invariant / round-trip checking
You do not always have a reference decoder. Instead assert properties that must
hold: `decode(encode(decode(x)))` must equal `decode(x)`; output length must be
exactly `floor(3*n/4)` minus padding. A broken length calc violates these even
when nothing throws. The demo checks the round-trip invariant.

### 4. Sanitizer / crash oracles
Normally you run the target under a memory sanitizer so an over-read/over-write
is caught the instant it happens, not millions of iterations later when output
happens to differ. For the JVM that means an **ASan build of libjvm**, plus
`-Xcheck:jni` and running under `gdb`/`rr` so a corrupt write trips immediately.
A plain JVM often *silently* corrupts memory; the sanitizer turns a subtle
mismatch into a loud, located crash with a stack trace into the intrinsic.

### 5. Reading the generated assembly
Once a candidate input is in hand, confirm the mechanism by inspecting the code
HotSpot actually emits:
```bash
java -XX:+UnlockDiagnosticVMOptions -XX:+PrintAssembly \
     -XX:CompileCommand=print,java.util.Base64$Decoder::decode ...
```
(needs the `hsdis` disassembler plugin). You line up the vector loads/stores and
the length registers against the input size to see the off-by-N. This is also
how you'd verify a proposed fix, and the source of record is the OpenJDK bug
tracker entry and the `macroAssembler_x86.cpp` Base64 routines.

## What the demo found here

On this machine (OpenJDK 21.0.13, AVX-512 VBMI present, intrinsic on by
default), 2,000,000 boundary-biased inputs produced **zero** discrepancies and
an identical checksum on both paths. That is the realistic day-to-day result:
differential fuzzing mostly prints "identical", and the skill is in steps 2-5 --
shaping inputs, adding a sanitizer oracle, and reading the assembly -- to reach
the one input that doesn't.

## What this does NOT show
- No exploit, no heap-grooming, no RCE, and no trigger for the real CVE.
- A clean run is not proof the JVM is safe; patch per your vendor's advisory.
- Application-level SAST (this repo's scanners) cannot find this class of bug,
  because the defect is in the JVM, not in application source.
