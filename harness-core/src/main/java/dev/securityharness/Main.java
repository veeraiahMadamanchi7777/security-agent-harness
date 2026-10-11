package dev.securityharness;

import com.google.gson.GsonBuilder;
import java.nio.file.Files;
import java.nio.file.Path;

/** Never loads or executes the target project's build. */
public final class Main {
    public static void main(String[] args) {
        if (args.length < 2 || args.length > 3 || (args.length == 3 && !args[2].equals("--include-tests"))) {
            System.err.println("Usage: harness-core <source-directory> <result.json> [--include-tests]");
            System.exit(2);
        }
        try {
            var result = new JavaAnalyzer().scan(Path.of(args[0]), args.length == 3);
            Path output = Path.of(args[1]).toAbsolutePath();
            Files.createDirectories(output.getParent());
            Files.writeString(output, new GsonBuilder().setPrettyPrinting().create().toJson(result));
            System.out.printf("Parsed %d/%d Java files; %d candidates; complete=%s%n",
                    result.parsedFiles, result.discoveredFiles, result.findings.size(), result.complete);
            if (!result.complete) System.exit(2);
        } catch (Exception e) {
            System.err.println("Scan failed: " + e.getMessage());
            System.exit(2);
        }
    }
}
