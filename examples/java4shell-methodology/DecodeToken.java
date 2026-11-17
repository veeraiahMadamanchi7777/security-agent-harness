import java.util.Base64;
// Mimics a realistic Spring handler: @GetMapping that reads an attacker-supplied
// token and Base64-decodes it. PetClinic has no such endpoint, but countless
// real apps do (API tokens, cookies, signed params). This is the SINK.
public class DecodeToken {
  public static void main(String[] a) {
    byte[] sum = new byte[1];
    // Warm up so HotSpot JIT-compiles the decoder into the AVX-512 intrinsic.
    for (int i = 0; i < 200_000; i++) {
      byte[] tokenBytes = ("userId=" + i + "&role=guest").getBytes();
      String attackerToken = Base64.getEncoder().encodeToString(tokenBytes);
      byte[] decoded = Base64.getDecoder().decode(attackerToken); // <-- sink
      sum[0] ^= decoded[0];
    }
    System.out.println("decoded tokens, guard=" + sum[0]);
  }
}
