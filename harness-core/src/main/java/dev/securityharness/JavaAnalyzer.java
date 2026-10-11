package dev.securityharness;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.*;
import com.github.javaparser.ast.body.*;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.stmt.*;
import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;

/** AST-based candidate analysis. Does not claim exploitability or full Java semantics. */
public final class JavaAnalyzer {
    public static final List<String> LIMITATIONS = List.of(
        "Candidates need review: runtime reachability, authorization and exploitability are not proven.",
        "API/type matching is syntactic. Unique same-class name/arity helpers are followed to depth 8. External calls, overloads and dynamic dispatch are unresolved.",
        "Conservative branch/loop joins, with no path feasibility, heap/alias analysis, field taint or implicit flows. Loops use two analysis iterations.",
        "Sources: explicitly bound Spring parameters and servlet request accessors. Implicit binding, Struts and other frameworks require review.",
        "Custom sanitizers and context-dependent encoders are not trusted; primitive numeric parsing is recognized.",
        "Dependency CVEs, IDOR, authorization, authentication, business logic and runtime behavior require separate review.",
        "Secrets rules cover named string-literal variables only. Obfuscated secrets and inherited configuration can be missed.");
    private static final Set<String> EXCLUDED = Set.of(".git", ".gradle", "build", "target", "node_modules", "vendor", "generated", ".idea");
    private static final Set<String> BINDINGS = Set.of("RequestParam", "PathVariable", "RequestBody", "RequestHeader", "CookieValue", "ModelAttribute", "RequestPart");
    private static final Set<String> ROUTES = Set.of("RequestMapping", "GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "PatchMapping");
    private final JavaParser parser = new JavaParser(new ParserConfiguration().setLanguageLevel(ParserConfiguration.LanguageLevel.BLEEDING_EDGE));
    private Result result;
    private final Map<String, Map<String, Object>> emitted = new LinkedHashMap<>();
    private String file;
    private List<String> lines;
    private TypeDeclaration<?> owner;

    public static final class Result {
        public String engine = "java-ast-candidates/1";
        public boolean complete;
        public int discoveredFiles, parsedFiles;
        public List<String> excludedPaths = new ArrayList<>(), errors = new ArrayList<>();
        public Map<String, String> sourceSha256 = new TreeMap<>();
        public List<String> limitations = LIMITATIONS;
        public List<Map<String, Object>> classes = new ArrayList<>(), methods = new ArrayList<>(), calls = new ArrayList<>(), findings = new ArrayList<>();
    }
    private record Flow(List<Map<String, Object>> path, boolean uncertain) {
        static Flow clean() { return new Flow(List.of(), false); }
        boolean tainted() { return !path.isEmpty(); }
        Flow step(String text, String file, int line) {
            if (!tainted()) return this;
            var p = new ArrayList<>(path);
            var s = Map.<String, Object>of("step", text, "file", file, "line", line);
            if (!p.contains(s) && p.size() < 64) p.add(s);
            return new Flow(p, uncertain);
        }
        Flow merge(Flow other) {
            var p = new ArrayList<>(path);
            for (var s : other.path) if (!p.contains(s) && p.size() < 64) p.add(s);
            return new Flow(p, uncertain || other.uncertain);
        }
        Flow unknown() { return new Flow(path, true); }
    }
    private static final class State {
        Map<String, Flow> values = new HashMap<>();
        Map<String, String> types = new HashMap<>();
        Flow returned = Flow.clean();
        State copy() { State s = new State(); s.values.putAll(values); s.types.putAll(types); s.returned = returned; return s; }
        void join(State s) {
            s.values.forEach((k, v) -> values.merge(k, v, Flow::merge));
            types.putAll(s.types); returned = returned.merge(s.returned);
        }
    }
    public Result scan(Path root, boolean includeTests) throws IOException {
        if (!Files.isDirectory(root)) throw new IOException("Target is not a directory: " + root);
        result = new Result(); emitted.clear();
        Path base = root.toRealPath(); List<Path> files = new ArrayList<>();
        Files.walkFileTree(base, new SimpleFileVisitor<>() {
            @Override public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes a) {
                String name = dir.getFileName().toString();
                boolean testDirectory = Set.of("test", "tests", "fixtures", "integrationTest").contains(name) ||
                    (name.equals("it") && dir.getParent().getFileName().toString().equals("src"));
                if (!dir.equals(base) && (EXCLUDED.contains(name) || (!includeTests && testDirectory))) {
                    result.excludedPaths.add(base.relativize(dir).toString()); return FileVisitResult.SKIP_SUBTREE;
                }
                return FileVisitResult.CONTINUE;
            }
            @Override public FileVisitResult visitFile(Path p, BasicFileAttributes a) {
                if (a.isSymbolicLink()) result.excludedPaths.add(base.relativize(p).toString());
                else if (a.isRegularFile() && p.toString().endsWith(".java")) files.add(p);
                return FileVisitResult.CONTINUE;
            }
            @Override public FileVisitResult visitFileFailed(Path p, IOException e) {
                result.errors.add(base.relativize(p) + ": unreadable file/directory"); return FileVisitResult.CONTINUE;
            }
        });
        files.sort(Comparator.naturalOrder()); result.discoveredFiles = files.size();
        for (Path path : files) {
            file = base.relativize(path).toString().replace('\\', '/');
            try {
                String content = Files.readString(path); lines = content.lines().toList();
                result.sourceSha256.put(file, sha256(content));
                var parsed = parser.parse(content);
                if (!parsed.isSuccessful() || parsed.getResult().isEmpty()) {
                    result.errors.add(file + ": Java parse failed (" + parsed.getProblems().size() + " problems)"); continue;
                }
                result.parsedFiles++;
                CompilationUnit unit = parsed.getResult().orElseThrow();
                for (TypeDeclaration<?> type : unit.findAll(TypeDeclaration.class)) analyzeType(type, unit);
            } catch (IOException | RuntimeException e) {
                result.errors.add(file + ": analysis failed (" + e.getClass().getSimpleName() + ")");
            }
        }
        if (files.isEmpty()) result.errors.add("No Java source files found within the selected scope");
        result.findings = new ArrayList<>(emitted.values());
        result.findings.sort(Comparator.comparing((Map<String,Object> f) -> (String)f.get("file"))
                .thenComparingInt(f -> (Integer)f.get("line")).thenComparingInt(f -> (Integer)f.get("column")).thenComparing(f -> (String)f.get("skill")));
        Map<String, Integer> counters = new HashMap<>();
        for (var f : result.findings) {
            String code = (String) f.remove("code");
            f.put("id", code + "-" + String.format(Locale.ROOT, "%03d", counters.merge(code, 1, Integer::sum)));
        }
        Collections.sort(result.excludedPaths); result.complete = result.errors.isEmpty(); return result;
    }
    private void analyzeType(TypeDeclaration<?> type, CompilationUnit unit) {
        owner = type;
        result.classes.add(Map.of("file", file, "line", line(type), "name", type.getNameAsString(),
            "package", unit.getPackageDeclaration().map(p -> p.getNameAsString()).orElse(""),
            "imports", unit.getImports().stream().map(i -> i.getNameAsString()).toList(),
            "annotations", type.getAnnotations().stream().map(a -> a.getNameAsString()).toList()));
        for (MethodDeclaration method : type.getMethods()) {
            boolean entry = method.getAnnotations().stream().anyMatch(a -> ROUTES.contains(a.getName().getIdentifier())) ||
                (Set.of("doGet", "doPost", "doPut", "doDelete", "service", "doFilter").contains(method.getNameAsString()) &&
                 method.getParameters().stream().anyMatch(p -> p.getTypeAsString().contains("ServletRequest")));
            result.methods.add(Map.of("id", methodId(method), "file", file, "line", line(method),
                "class", owner.getNameAsString(), "signature", method.getSignature().asString(), "entryPoint", entry,
                "parameters", method.getParameters().stream().map(p -> p.getTypeAsString() + " " + p.getNameAsString()).toList(),
                "annotations", method.getAnnotations().stream().map(a -> a.getNameAsString()).toList()));
            for (MethodCallExpr call : method.findAll(MethodCallExpr.class)) result.calls.add(Map.of(
                "from", methodId(method), "targetName", call.getNameAsString(), "arity", call.getArguments().size(),
                "file", file, "line", line(call), "resolution", "syntactic-candidate"));
            run(method, null, new HashSet<>(), 0);
        }
        for (FieldDeclaration field : type.getFields()) for (VariableDeclarator v : field.getVariables()) secret(v, null);
    }
    private String methodId(MethodDeclaration m) { return file + ":" + owner.getNameAsString() + ":" + m.getSignature().asString(); }
    private Flow run(MethodDeclaration method, List<Flow> args, Set<String> stack, int depth) {
        if (depth > 8 || stack.contains(methodId(method))) return combine(args == null ? List.of() : args).unknown();
        Set<String> next = new HashSet<>(stack); next.add(methodId(method)); State s = new State();
        for (var f : owner.getFields()) for (var v : f.getVariables()) s.types.put(v.getNameAsString(), v.getTypeAsString());
        for (int i = 0; i < method.getParameters().size(); i++) {
            Parameter p = method.getParameter(i); s.types.put(p.getNameAsString(), p.getTypeAsString());
            Flow f = args == null ? Flow.clean() : args.get(i);
            if (args == null && p.getAnnotations().stream().anyMatch(a -> BINDINGS.contains(a.getName().getIdentifier()))) f = source("Spring-bound parameter " + p.getNameAsString(), p);
            s.values.put(p.getNameAsString(), f.step("parameter " + method.getNameAsString() + "." + p.getNameAsString(), file, line(p)));
        }
        method.getBody().ifPresent(b -> statement(b, s, method, next, depth)); return s.returned;
    }
    private void statement(Statement st, State s, MethodDeclaration m, Set<String> stack, int depth) {
        if (st instanceof BlockStmt b) {
            for (var child : b.getStatements()) { statement(child, s, m, stack, depth); if (child.isReturnStmt() || child.isThrowStmt()) break; }
        } else if (st instanceof ExpressionStmt e) expr(e.getExpression(), s, m, stack, depth);
        else if (st instanceof ReturnStmt r) r.getExpression().ifPresent(e -> s.returned = s.returned.merge(expr(e, s, m, stack, depth)));
        else if (st instanceof IfStmt i) {
            expr(i.getCondition(), s, m, stack, depth); State yes = s.copy(), no = s.copy();
            statement(i.getThenStmt(), yes, m, stack, depth); i.getElseStmt().ifPresent(e -> statement(e, no, m, stack, depth));
            yes.join(no); s.values = yes.values; s.types = yes.types; s.returned = yes.returned;
        } else if (st instanceof TryStmt t) {
            t.getResources().forEach(e -> expr(e, s, m, stack, depth)); State original = s.copy();
            statement(t.getTryBlock(), s, m, stack, depth);
            for (var c : t.getCatchClauses()) { State alternative = original.copy(); statement(c.getBody(), alternative, m, stack, depth); s.join(alternative); }
            t.getFinallyBlock().ifPresent(b -> statement(b, s, m, stack, depth));
        } else {
            State loop = s.copy();
            for (int iteration = 0; iteration < 2; iteration++) for (Node n : st.getChildNodes()) {
                if (n instanceof Expression e) expr(e, loop, m, stack, depth);
                else if (n instanceof Statement child) statement(child, loop, m, stack, depth);
                else if (n instanceof SwitchEntry entry) for (var child : entry.getStatements()) statement(child, loop, m, stack, depth);
            }
            s.join(loop);
        }
    }
    private Flow expr(Expression e, State s, MethodDeclaration m, Set<String> stack, int depth) {
        if (e instanceof NameExpr n) return s.values.getOrDefault(n.getNameAsString(), Flow.clean());
        if (e instanceof LiteralExpr || e instanceof ClassExpr || e instanceof ThisExpr) return Flow.clean();
        if (e instanceof VariableDeclarationExpr v) {
            Flow all = Flow.clean();
            for (var d : v.getVariables()) {
                Flow f = d.getInitializer().map(x -> expr(x, s, m, stack, depth)).orElse(Flow.clean());
                s.values.put(d.getNameAsString(), f.step("assign " + d.getNameAsString(), file, line(d)));
                String type = d.getTypeAsString();
                if (type.equals("var") && d.getInitializer().isPresent()) type = typeOf(d.getInitializer().get(), s);
                if (d.getInitializer().isPresent() && typeOf(d.getInitializer().get(), s).equals("HttpResponseWriter")) type = "HttpResponseWriter";
                s.types.put(d.getNameAsString(), type); all = all.merge(f); secret(d, m);
            }
            return all;
        }
        if (e instanceof AssignExpr a) {
            Flow f = expr(a.getValue(), s, m, stack, depth);
            if (a.getTarget().isNameExpr()) {
                String name = a.getTarget().asNameExpr().getNameAsString();
                if (a.getOperator() != AssignExpr.Operator.ASSIGN) f = f.merge(s.values.getOrDefault(name, Flow.clean()));
                s.values.put(name, f.step("assign " + name, file, line(a)));
            }
            return f;
        }
        if (e instanceof ConditionalExpr c) {
            expr(c.getCondition(), s, m, stack, depth); State yes = s.copy(), no = s.copy();
            Flow a = expr(c.getThenExpr(), yes, m, stack, depth), b = expr(c.getElseExpr(), no, m, stack, depth);
            yes.join(no); s.values = yes.values; s.types = yes.types; return a.merge(b);
        }
        if (e instanceof MethodCallExpr c) {
            Flow receiver = c.getScope().map(x -> expr(x, s, m, stack, depth)).orElse(Flow.clean());
            List<Flow> args = c.getArguments().stream().map(x -> expr(x, s, m, stack, depth)).toList();
            String name = c.getNameAsString(), type = c.getScope().map(x -> typeOf(x, s)).orElse("");
            if (type.contains("ServletRequest") && Set.of("getParameter", "getParameterValues", "getHeader", "getHeaders", "getQueryString", "getInputStream", "getReader", "getCookies").contains(name)) return source("Servlet request " + name + "()", c);
            inspectCall(c, type, args, receiver, m);
            if (Set.of("Integer", "Long", "Short", "Byte", "Double", "Float", "java.lang.Integer", "java.lang.Long").contains(type) && Set.of("parseInt", "parseLong", "parseShort", "parseByte", "parseDouble", "parseFloat").contains(name)) return Flow.clean();
            if (c.getScope().isEmpty() || c.getScope().get().isThisExpr()) {
                var targets = owner.getMethodsByName(name).stream().filter(x -> x.getParameters().size() == args.size()).toList();
                if (targets.size() == 1) return run(targets.get(0), args, stack, depth + 1).step("return from " + name, file, line(c));
            }
            return combine(args).merge(receiver).step("call " + name + " (unresolved semantics)", file, line(c)).unknown();
        }
        if (e instanceof ObjectCreationExpr c) {
            Flow f = combine(c.getArguments().stream().map(a -> expr(a, s, m, stack, depth)).toList()); String type = c.getType().getNameAsString();
            if (f.tainted()) {
                if (Set.of("File", "FileInputStream", "FileOutputStream", "FileReader", "FileWriter", "RandomAccessFile").contains(type)) emit(Rule.PATH, c, m, f, false);
                if (type.equals("ObjectInputStream")) emit(Rule.DESERIAL, c, m, f, false);
                if (type.equals("ProcessBuilder")) emit(Rule.RCE, c, m, f, false);
            }
            return f.step("construct " + type, file, line(c));
        }
        Flow f = Flow.clean(); for (Node child : e.getChildNodes()) if (child instanceof Expression x) f = f.merge(expr(x, s, m, stack, depth)); return f;
    }
    private void inspectCall(MethodCallExpr c, String type, List<Flow> args, Flow receiver, MethodDeclaration m) {
        String name = c.getNameAsString(); Flow first = args.isEmpty() ? Flow.clean() : args.get(0);
        if (first.tainted()) {
            if ((type.contains("Statement") && Set.of("execute", "executeQuery", "executeUpdate", "addBatch", "executeLargeUpdate").contains(name)) ||
                (type.contains("Connection") && Set.of("prepareStatement", "prepareCall").contains(name)) ||
                (type.contains("EntityManager") && Set.of("createQuery", "createNativeQuery").contains(name)) ||
                (type.contains("JdbcTemplate") && Set.of("query", "queryForObject", "queryForList", "update", "execute").contains(name))) emit(Rule.SQLI, c, m, first, false);
            if (type.contains("Runtime") && name.equals("exec")) emit(Rule.RCE, c, m, first, false);
            if (type.contains("Response") && name.equals("sendRedirect")) emit(Rule.REDIRECT, c, m, first, false);
            if (type.equals("HttpResponseWriter") && Set.of("write", "print", "println", "append").contains(name)) emit(Rule.XSS, c, m, first, false);
            if ((type.contains("RestTemplate") || type.contains("WebClient")) && Set.of("getForObject", "getForEntity", "postForObject", "exchange", "uri").contains(name)) emit(Rule.SSRF, c, m, first, false);
            if (Set.of("Files", "java.nio.file.Files").contains(type) && Set.of("readString", "readAllBytes", "newInputStream", "newOutputStream", "write", "writeString", "delete", "deleteIfExists", "copy", "move").contains(name)) emit(Rule.PATH, c, m, first, false);
            if (type.contains("ScriptEngine") && name.equals("eval")) emit(Rule.TEMPLATE, c, m, first, false);
            if ((type.contains("DocumentBuilder") || type.contains("SAXParser") || type.contains("XMLReader")) && name.equals("parse")) emit(Rule.XXE, c, m, first, false);
        }
        if (type.contains("DirContext") && name.equals("search") && args.size() > 1 && args.get(1).tainted()) emit(Rule.LDAP, c, m, args.get(1), false);
        if (receiver.tainted() && type.contains("URL") && Set.of("openConnection", "openStream").contains(name)) emit(Rule.SSRF, c, m, receiver, false);
        if (name.equals("getInstance") && !c.getArguments().isEmpty() && c.getArgument(0).isStringLiteralExpr() && (type.contains("Cipher") || type.contains("MessageDigest"))) {
            String alg = c.getArgument(0).asStringLiteralExpr().asString().toUpperCase(Locale.ROOT);
            if (Set.of("MD5", "SHA1", "SHA-1", "DES", "DESEDE", "RC4", "ARCFOUR", "AES").contains(alg) || alg.contains("/ECB/")) emit(Rule.CRYPTO, c, m, Flow.clean(), false);
        }
    }
    private String typeOf(Expression e, State s) {
        if (e instanceof NameExpr n) return s.types.getOrDefault(n.getNameAsString(), n.getNameAsString());
        if (e instanceof ObjectCreationExpr o) return o.getTypeAsString();
        if (e instanceof EnclosedExpr x) return typeOf(x.getInner(), s);
        if (e instanceof CastExpr x) return x.getTypeAsString();
        if (e instanceof FieldAccessExpr f) return f.getScope().isThisExpr() ? s.types.getOrDefault(f.getNameAsString(), "") : f.toString();
        if (e instanceof MethodCallExpr c) {
            String parent = c.getScope().map(x -> typeOf(x, s)).orElse("");
            if (c.getNameAsString().equals("getRuntime") && parent.contains("Runtime")) return "Runtime";
            if (c.getNameAsString().equals("getWriter") && parent.contains("Response")) return "HttpResponseWriter";
            if (c.getNameAsString().equals("createStatement") && parent.contains("Connection")) return "Statement";
            if (c.getNameAsString().equals("prepareStatement") && parent.contains("Connection")) return "PreparedStatement";
            if (c.getNameAsString().equals("toURL") && parent.contains("URI")) return "URL";
        }
        return "";
    }
    private void secret(VariableDeclarator v, MethodDeclaration m) {
        String name = v.getNameAsString().toLowerCase(Locale.ROOT);
        if (Set.of("password", "passwd", "secret", "apikey", "api_key", "access_token", "accesstoken", "clientsecret", "client_secret", "privatekey").contains(name) && v.getInitializer().filter(Expression::isStringLiteralExpr).isPresent()) {
            String value = v.getInitializer().get().asStringLiteralExpr().asString();
            if (value.length() >= 8 && !value.startsWith("${") && !Set.of("changeme", "password", "placeholder").contains(value.toLowerCase(Locale.ROOT))) emit(Rule.SECRET, v, m, Flow.clean(), true);
        }
    }
    private void emit(Rule rule, Node sink, MethodDeclaration m, Flow flow, boolean redact) {
        String key = file + ":" + line(sink) + ":" + sink.getBegin().orElseThrow().column + ":" + rule;
        if (emitted.containsKey(key)) return;
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("code", rule.name()); f.put("skill", "sast-" + rule.skill); f.put("cwe", "CWE-" + rule.cwe); f.put("severity", rule.severity);
        f.put("confidence", flow.tainted() && !flow.uncertain ? "Medium" : "Low"); f.put("status", "candidate");
        f.put("file", file); f.put("line", line(sink)); f.put("column", sink.getBegin().orElseThrow().column);
        f.put("method", m == null ? "<field>" : m.getNameAsString()); f.put("class", owner.getNameAsString());
        int start = line(sink) - 1, end = Math.min(lines.size(), Math.min(start + 3, sink.getEnd().orElseThrow().line));
        String snippet = String.join("\n", lines.subList(start, end));
        f.put("evidence", redact ? "[REDACTED credential literal]" : snippet); f.put("evidence_redacted", redact);
        if (redact) { f.put("evidence_sha256", sha256(snippet)); f.put("evidence_line_count", end - start); }
        String api = sink instanceof MethodCallExpr c ? c.getNameAsString() + "()" : sink instanceof ObjectCreationExpr c ? "new " + c.getTypeAsString() + "()" : "credential literal";
        f.put("sink", api); f.put("source", flow.tainted() ? flow.path.get(0).get("step") : "literal configuration in source");
        f.put("taint_path", flow.step("sink " + api, file, line(sink)).path);
        f.put("sanitizer_present", false); f.put("sanitizer_detail", "No trusted sanitizer proved; external controls may exist.");
        f.put("remediation", rule.fix); f.put("references", List.of("https://cwe.mitre.org/data/definitions/" + rule.cwe + ".html"));
        List<String> caveats = new ArrayList<>(List.of("Syntactic API/type matching: verify actual library types and runtime reachability.", "Candidate only: verify deployment context and compensating controls."));
        if (flow.uncertain) caveats.add("Propagation includes unresolved call semantics or a recursion/depth bound.");
        if (rule == Rule.XXE) caveats.add("Parser factory configuration is unresolved and may already disable external entities.");
        if (rule == Rule.XSS) caveats.add("The writer may target a non-HTML destination; verify content type and context encoding.");
        f.put("false_positive_indicators", caveats); emitted.put(key, f);
    }
    private Flow source(String text, Node n) { return new Flow(List.of(Map.of("step", text, "file", file, "line", line(n))), false); }
    private static Flow combine(List<Flow> flows) { Flow f = Flow.clean(); for (Flow x : flows) f = f.merge(x); return f; }
    private static int line(Node n) { return n.getBegin().orElseThrow().line; }
    private static String sha256(String content) {
        try { return HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(content.getBytes(java.nio.charset.StandardCharsets.UTF_8))); }
        catch (java.security.NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }
}
