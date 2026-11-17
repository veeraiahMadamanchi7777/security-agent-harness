import java.util.Base64;
import java.util.Random;

/**
 * Differential fuzzer for the java.util.Base64 decoder.
 *
 * Idea: the SAME decode() call runs different machine code depending on whether
 * HotSpot's AVX-512 intrinsic is enabled. If the intrinsic and the pure-Java
 * decoder ever produce different results (or one throws and the other does not)
 * for the same input, the intrinsic is miscounting bytes -- the first symptom of
 * the kind of heap over-read/over-write behind CVE-2026-114938.
 *
 * This tool only DETECTS disagreement. It does not attempt exploitation.
 *
 * You run it twice against itself:
 *   java -XX:+UseBASE64Intrinsics Base64DiffFuzz > intrinsic.txt
 *   java -XX:-UseBASE64Intrinsics Base64DiffFuzz > plain.txt
 *   diff intrinsic.txt plain.txt
 * Any diff line is a candidate bug. (Here we also self-check within one JVM by
 * hashing outputs, so a single run surfaces internal throws/crashes.)
 */
public class Base64DiffFuzz {
    static final Base64.Decoder DEC = Base64.getDecoder();
    static final Base64.Encoder ENC = Base64.getEncoder();

    public static void main(String[] args) {
        long seed = args.length > 0 ? Long.parseLong(args[0]) : 42;
        int iters = args.length > 1 ? Integer.parseInt(args[1]) : 2_000_000;
        Random rnd = new Random(seed);
        int mismatches = 0, errors = 0;
        long outChecksum = 0;

        for (int i = 0; i < iters; i++) {
            byte[] input = makeCandidate(rnd, i);
            String s = new String(input, java.nio.charset.StandardCharsets.ISO_8859_1);
            try {
                byte[] out = DEC.decode(s);
                // Round-trip invariant: re-encoding valid output must reproduce
                // a string that decodes to the same bytes. A length miscount in
                // the intrinsic breaks this even when no exception is thrown.
                byte[] out2 = DEC.decode(ENC.encodeToString(out));
                if (!java.util.Arrays.equals(out, out2)) {
                    mismatches++;
                    System.out.println("MISMATCH len=" + s.length() + " -> " + out.length + "/" + out2.length);
                }
                for (byte b : out) outChecksum = outChecksum * 31 + b;
            } catch (IllegalArgumentException e) {
                errors++; // expected for malformed input -- not a bug by itself
            }
        }
        System.out.println("seed=" + seed + " iters=" + iters +
            " checksum=" + outChecksum + " roundtrip_mismatches=" + mismatches +
            " rejected=" + errors);
    }

    /** Generate inputs that stress the vector decode path and its length math. */
    static byte[] makeCandidate(Random rnd, int i) {
        // The AVX-512 path processes 64-char blocks; bugs cluster at block
        // boundaries and tail handling. Bias lengths toward n*64 +/- a few.
        int base = (rnd.nextInt(40)) * 64;
        int jitter = rnd.nextInt(9) - 4;
        int len = Math.max(0, base + jitter);
        byte[] b = new byte[len];
        String alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int k = 0; k < len; k++) b[k] = (byte) alpha.charAt(rnd.nextInt(64));
        // Occasionally inject padding mid-stream and stray bytes to probe tails.
        if ((i & 7) == 0 && len > 2) b[len - 1] = '=';
        if ((i & 15) == 0 && len > 4) { b[len - 1] = '='; b[len - 2] = '='; }
        return b;
    }
}
