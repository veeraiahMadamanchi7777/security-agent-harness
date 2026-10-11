package dev.securityharness;

import java.nio.file.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class MainTest {
    @TempDir Path temp;
    private JavaAnalyzer.Result scan(String source) throws Exception {
        Files.writeString(temp.resolve("Example.java"), source);
        return new JavaAnalyzer().scan(temp, true);
    }
    private String controller(String body) {
        return "class C { void endpoint(@RequestParam String input, java.sql.Statement statement) throws Exception { " + body + " } }";
    }
    @Test void tracksAssignmentsToSql() throws Exception {
        var r = scan(controller("String query = \"SELECT \" + input; statement.executeQuery(query);"));
        assertTrue(r.complete); assertEquals(1, r.findings.size());
        assertEquals("CWE-89", r.findings.get(0).get("cwe"));
        assertEquals("candidate", r.findings.get(0).get("status"));
    }
    @Test void constantOverwriteKillsTaint() throws Exception {
        assertTrue(scan(controller("String q = input; q = \"constant\"; statement.executeQuery(q);")).findings.isEmpty());
    }
    @Test void bothSafeBranchesKillTaint() throws Exception {
        assertTrue(scan(controller("String q = input; if (input.isEmpty()) q = \"a\"; else q = \"b\"; statement.executeQuery(q);")).findings.isEmpty());
    }
    @Test void unsafeBranchRemainsTainted() throws Exception {
        assertEquals(1, scan(controller("String q = \"safe\"; if (input.isEmpty()) q = input; statement.executeQuery(q);")).findings.size());
    }
    @Test void followsSameClassHelperSink() throws Exception {
        var r = scan("class C { java.sql.Statement statement; void endpoint(@RequestParam String id) { helper(id); } void helper(String value) { statement.executeQuery(value); } }");
        assertEquals(1, r.findings.size()); assertEquals("helper", r.findings.get(0).get("method"));
    }
    @Test void followsHelperReturn() throws Exception {
        var r = scan("class C { java.sql.Statement statement; void endpoint(@RequestParam String id) { statement.executeQuery(query(id)); } String query(String value) { return \"SELECT \" + value; } }");
        assertEquals(1, r.findings.size());
    }
    @Test void recursiveHelperTerminates() throws Exception {
        var r = scan("class C { java.sql.Statement statement; void endpoint(@RequestParam String id) { statement.executeQuery(query(id)); } String query(String value) { return query(value); } }");
        assertTrue(r.complete); assertEquals("Low", r.findings.get(0).get("confidence"));
    }
    @Test void doesNotTreatAllParametersAsUntrusted() throws Exception {
        assertTrue(scan("class C { void helper(String input, java.sql.Statement statement) { statement.executeQuery(input); } }").findings.isEmpty());
    }
    @Test void numericParsingIsRecognized() throws Exception {
        assertTrue(scan(controller("statement.executeQuery(\"SELECT \" + Integer.parseInt(input));")).findings.isEmpty());
    }
    @Test void commentsAndStringsAreNotCode() throws Exception {
        assertTrue(scan(controller("// Runtime.getRuntime().exec(input);\nString x = \"statement.executeQuery(input)\";")).findings.isEmpty());
    }
    @Test void servletSource() throws Exception {
        var r = scan("class C { void doGet(HttpServletRequest request, java.sql.Statement statement) { statement.executeQuery(request.getParameter(\"id\")); } }");
        assertEquals(1, r.findings.size()); assertEquals(true, r.methods.get(0).get("entryPoint"));
    }
    @Test void parseErrorsFailClosed() throws Exception {
        var r = scan("class Broken { void nope( {"); assertFalse(r.complete); assertFalse(r.errors.isEmpty());
    }
    @Test void emptyProjectsAreIncomplete() throws Exception {
        assertFalse(new JavaAnalyzer().scan(temp, false).complete);
    }
    @Test void excludesBuildAndTests() throws Exception {
        Files.createDirectories(temp.resolve("src/test")); Files.createDirectories(temp.resolve("target"));
        Files.writeString(temp.resolve("src/test/A.java"), "class A {}"); Files.writeString(temp.resolve("target/B.java"), "class B {}");
        var r = new JavaAnalyzer().scan(temp, false); assertEquals(0, r.discoveredFiles);
        assertEquals(1, new JavaAnalyzer().scan(temp, true).discoveredFiles);
    }
    @Test void deterministicOutput() throws Exception {
        scan(controller("statement.executeQuery(input);"));
        var a = new JavaAnalyzer().scan(temp, true); var b = new JavaAnalyzer().scan(temp, true);
        assertEquals(a.findings, b.findings); assertEquals(a.calls, b.calls);
    }
    @Test void rejectsMissingTarget() {
        assertThrows(java.io.IOException.class, () -> new JavaAnalyzer().scan(temp.resolve("absent"), false));
    }
    @Test void secretIsRedacted() throws Exception {
        var r = scan("class C { String password = \"fixture-super-secret\"; }");
        assertEquals(1, r.findings.size()); assertFalse(r.findings.toString().contains("fixture-super-secret"));
    }
    @Test void fileWriterIsNotAnHtmlSink() throws Exception {
        var r = scan("class C { void log(@RequestParam String text) { PrintWriter writer = new PrintWriter(\"app.log\"); writer.println(text); } }");
        assertTrue(r.findings.isEmpty());
    }
    @Test void assignedResponseWriterIsAnHtmlCandidate() throws Exception {
        var r = scan("class C { void render(@RequestParam String text, HttpServletResponse response) { PrintWriter writer = response.getWriter(); writer.println(text); } }");
        assertEquals(1, r.findings.size()); assertEquals("CWE-79", r.findings.get(0).get("cwe"));
    }
    @Test void doesNotScanSymlinks() throws Exception {
        Path outside = Files.createTempFile("outside-source", ".java");
        try {
            Files.writeString(outside, "class Other {}"); Files.createSymbolicLink(temp.resolve("Other.java"), outside);
            var r = new JavaAnalyzer().scan(temp, true); assertEquals(0, r.discoveredFiles); assertEquals(1, r.excludedPaths.size());
        } finally { Files.deleteIfExists(outside); }
    }
}
