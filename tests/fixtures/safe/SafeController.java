// Paired counterexamples for the supported syntactic rules, not a secure-app certification.
import java.sql.*;
import javax.crypto.*;
import jakarta.servlet.http.*;
import org.springframework.web.bind.annotation.*;

@RestController
class SafeController {
    String apiKey = System.getenv("API_KEY");
    @GetMapping("/sql")
    void sql(@RequestParam String id, Connection connection) throws Exception {
        PreparedStatement statement = connection.prepareStatement("SELECT * FROM users WHERE id = ?");
        statement.setString(1, id);
        statement.executeQuery();
    }
    @GetMapping("/numeric")
    void numeric(@RequestParam String id, Statement statement) throws Exception {
        int numericId = Integer.parseInt(id);
        statement.executeQuery("SELECT * FROM users WHERE id = " + numericId);
    }
    @GetMapping("/command")
    void command(@RequestParam String ignored) throws Exception {
        Runtime.getRuntime().exec("/usr/bin/true");
    }
    @GetMapping("/redirect")
    void redirect(@RequestParam String ignored, HttpServletResponse response) throws Exception {
        response.sendRedirect("/home");
    }
    @GetMapping("/html")
    void html(@RequestParam String ignored, HttpServletResponse response) throws Exception {
        response.getWriter().write("Hello");
    }
    void crypto() throws Exception {
        Cipher.getInstance("AES/GCM/NoPadding");
    }
}
