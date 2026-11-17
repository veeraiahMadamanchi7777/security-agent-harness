# Seeing the Java4Shell exposure on a running Spring PetClinic

For learning. No exploit, no memory corruption, no trigger for the real CVE.
This shows *where* the vulnerable code lives relative to a real app, and proves
the vulnerable JVM code path is actually active under PetClinic.

## The key lesson first

PetClinic's **own code is clean**. The repo scan found 0 findings, and PetClinic
never Base64-decodes attacker input anywhere. You therefore cannot "see" this bug
by reading or clicking through the app. The defect is in the **JVM**, not the app.

So the real exposure question is two parts:
1. Is PetClinic running on a JVM whose vulnerable Base64 intrinsic is active?  -> YES (proven below)
2. Does attacker input ever reach a `Base64.decode()` on that JVM?            -> Not in PetClinic as shipped; it would the moment any feature/filter/dependency decodes a token, cookie, or signed param.

## Step 1 - Run PetClinic (Java 17, on an AVX-512 host)

```bash
cd spring-petclinic
JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64 mvn package -DskipTests
java -jar target/spring-petclinic-*.jar      # Tomcat on :8080
grep avx512_vbmi /proc/cpuinfo                # host has the affected CPU feature
```
App comes up: `/`, `/owners/find`, `/vets.html` all 200. (Also note
`/actuator/env` is 200 -- an unrelated, real misconfig in this sample.)

## Step 2 - Prove the vulnerable intrinsic is LIVE in that JVM

`DecodeToken.java` mimics what a normal Spring handler does with a token: read an
attacker-supplied string and `Base64.getDecoder().decode()` it. Run it on
PetClinic's exact JDK and ask HotSpot what it compiled:

```bash
java -XX:+UnlockDiagnosticVMOptions -XX:+PrintIntrinsics DecodeToken 2>/dev/null | grep -i base64
```
Output on this machine:
```
@ 63  java.util.Base64$Decoder::decodeBlock (186 bytes)   (intrinsic)
UseBASE64Intrinsics = true  {product} {default}
```
`(intrinsic)` means HotSpot swapped the safe Java decoder for the hand-written
AVX-512 assembly -- the code with no bounds checks. That is the exact code path
CVE-2026-114938 is reported to break, and it is on by default in the JVM serving
PetClinic.

## Step 3 - Trace the reachability (the part that turns it into a bug)

```
HTTP request (attacker-controlled bytes)
   -> some feature decodes a token/cookie/param   <-- the reachable SINK
      -> java.util.Base64.Decoder.decode(...)
         -> decodeBlock INTRINSIC (AVX-512 assembly)   <-- the defect lives here
```
PetClinic ships without that middle step, so it is not exploitable as-is via its
own routes. Add one ordinary feature that decodes untrusted Base64 -- an API
token param, a "remember me" cookie, a Basic-Auth filter, or a dependency that
does it for you -- and the same clean-looking app now feeds the attacker's bytes
straight into the vulnerable assembly.

## Step 4 - Detect / mitigate (safe, verifiable)

- Detection methodology: `README.md` in this folder (differential fuzzing of the
  two decoders, boundary inputs, sanitizer oracle, reading the assembly).
- Interim mitigation to evaluate: start the JVM with `-XX:-UseBASE64Intrinsics`
  so `decodeBlock` is no longer swapped for the assembly. Re-run Step 2 and the
  `(intrinsic)` line disappears. Confirm against your vendor's advisory and
  measure the Base64 throughput cost before using in production.
- Real fix: patched JVM per the OpenJDK/vendor advisory.

## What this is NOT
- Not an exploit and not the CVE trigger -- it only shows code-path reachability.
- A clean app scan does not mean a safe deployment when the JVM itself is affected.
- Application SAST (this repo's scanners) cannot find this; the bug is below the app.
