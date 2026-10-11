// Deliberately unsafe AST fixtures. Never deploy or execute these methods.
import java.sql.*;
import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.naming.directory.*;
import javax.script.*;
import javax.xml.parsers.*;
import jakarta.servlet.http.*;
import org.springframework.web.bind.annotation.*;

@RestController
class UnsafeController {
    String apiKey = "fixture-only-not-a-real-key";

    @GetMapping("/sql")
    void sql(@RequestParam String id, Statement statement) throws Exception {
        String query = "SELECT * FROM users WHERE id=" + id;
        statement.executeQuery(query);
    }
    @GetMapping("/command")
    void command(@RequestParam String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
    }
    @GetMapping("/file")
    void file(@RequestParam String path) throws Exception {
        new FileInputStream(path);
    }
    @GetMapping("/fetch")
    void fetch(@RequestParam String destination) throws Exception {
        new URL(destination).openConnection();
    }
    @GetMapping("/redirect")
    void redirect(@RequestParam String next, HttpServletResponse response) throws Exception {
        response.sendRedirect(next);
    }
    @GetMapping("/html")
    void html(@RequestParam String name, HttpServletResponse response) throws Exception {
        response.getWriter().write(name);
    }
    @GetMapping("/ldap")
    void ldap(@RequestParam String name, DirContext context) throws Exception {
        context.search("ou=users", "(uid=" + name + ")", null);
    }
    @PostMapping("/script")
    void script(@RequestBody String code, ScriptEngine engine) throws Exception {
        engine.eval(code);
    }
    @PostMapping("/xml")
    void xml(@RequestBody String document, DocumentBuilder builder) throws Exception {
        builder.parse(document);
    }
    void deserialize(HttpServletRequest request) throws Exception {
        new ObjectInputStream(request.getInputStream()).readObject();
    }
    void crypto() throws Exception {
        Cipher.getInstance("AES/ECB/PKCS5Padding");
    }
}
