package dev.aiguard.analysis.rules;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.*;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.stmt.*;
import dev.aiguard.analysis.SourceProject.JavaSource;
import java.util.*;

/** Deliberately bounded syntax analysis; a missing fact is not a negative proof. */
public final class AstSupport {
    public enum Origin { WEB_INPUT, TOOL_INPUT, MODEL_OUTPUT }
    private static final Set<String> MAPPINGS = Set.of("RequestMapping", "GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "PatchMapping");
    private AstSupport() {}

    public static boolean imported(Node node, String simple, String qualified) {
        var cu = node.findCompilationUnit();
        if (cu.isEmpty()) return false;
        if (cu.get().findAll(TypeDeclaration.class).stream().anyMatch(t -> t.getNameAsString().equals(simple))) return false;
        return cu.get().getImports().stream().anyMatch(i -> !i.isStatic() &&
            (i.getNameAsString().equals(qualified) || i.isAsterisk() && qualified.startsWith(i.getNameAsString() + ".") &&
                qualified.substring(i.getNameAsString().length() + 1).equals(simple)));
    }
    public static boolean type(Node at, String actual, String qualified) {
        String simple = qualified.substring(qualified.lastIndexOf('.') + 1);
        String clean = actual.replaceAll("<.*>", "").trim();
        return clean.equals(qualified) || clean.equals(simple) && imported(at, simple, qualified);
    }
    public static boolean annotation(Node node, String qualified) {
        String simple = qualified.substring(qualified.lastIndexOf('.') + 1);
        if (!(node instanceof com.github.javaparser.ast.nodeTypes.NodeWithAnnotations<?> annotated)) return false;
        return annotated.getAnnotations().stream().anyMatch(a -> a.getNameAsString().equals(qualified) ||
            a.getNameAsString().equals(simple) && imported(node, simple, qualified));
    }
    public static boolean web(MethodDeclaration method) {
        return MAPPINGS.stream().anyMatch(n -> annotation(method, "org.springframework.web.bind.annotation." + n));
    }
    public static boolean tool(MethodDeclaration method) { return annotation(method, "org.springframework.ai.tool.annotation.Tool"); }
    public static Optional<MethodDeclaration> method(Node at) { return at.findAncestor(MethodDeclaration.class); }
    public static int line(Node n) { return n.getBegin().map(p -> p.line).orElse(1); }
    public static boolean before(Node a, Node b) {
        return a.getBegin().isPresent() && b.getBegin().isPresent() && a.getBegin().get().isBefore(b.getBegin().get());
    }
    public static Optional<Node> declaration(NameExpr name) {
        // Walk lexical blocks, considering declarations only before the reference.
        Node cursor = name;
        while (cursor.getParentNode().isPresent()) {
            Node parent = cursor.getParentNode().get();
            if (parent instanceof BlockStmt block) {
                List<VariableDeclarator> candidates = new ArrayList<>();
                for (Statement s : block.getStatements()) {
                    if (s instanceof ExpressionStmt e && e.getExpression() instanceof VariableDeclarationExpr vd)
                        for (var v : vd.getVariables()) if (v.getNameAsString().equals(name.getNameAsString()) && before(v, name)) candidates.add(v);
                }
                if (!candidates.isEmpty()) return Optional.of(candidates.getLast());
            }
            if (parent instanceof LambdaExpr lambda) {
                for (var p : lambda.getParameters()) if (p.getNameAsString().equals(name.getNameAsString())) return Optional.of(p);
            }
            if (parent instanceof MethodDeclaration m) {
                for (var p : m.getParameters()) if (p.getNameAsString().equals(name.getNameAsString())) return Optional.of(p);
            }
            if (parent instanceof ConstructorDeclaration c) {
                for (var p : c.getParameters()) if (p.getNameAsString().equals(name.getNameAsString())) return Optional.of(p);
            }
            if (parent instanceof ClassOrInterfaceDeclaration cls) {
                for (var f : cls.getFields()) for (var v : f.getVariables())
                    if (v.getNameAsString().equals(name.getNameAsString())) return Optional.of(v);
            }
            cursor = parent;
        }
        return Optional.empty();
    }
    public static String declaredType(Expression expr) {
        if (expr instanceof EnclosedExpr e) return declaredType(e.getInner());
        if (expr instanceof NameExpr n) {
            var d = declaration(n);
            if (d.orElse(null) instanceof Parameter p) return p.getTypeAsString();
            if (d.orElse(null) instanceof VariableDeclarator v) return v.getTypeAsString();
        }
        if (expr instanceof FieldAccessExpr f && f.getScope() instanceof ThisExpr) {
            var cls = f.findAncestor(ClassOrInterfaceDeclaration.class);
            if (cls.isPresent()) for (var field : cls.get().getFields()) for (var v : field.getVariables())
                if (v.getNameAsString().equals(f.getNameAsString())) return v.getTypeAsString();
        }
        if (expr instanceof ObjectCreationExpr c) return c.getTypeAsString();
        return "";
    }
    public static boolean receiverType(MethodCallExpr call, String qualified) {
        return call.getScope().map(s -> type(s, declaredType(s), qualified)).orElse(false);
    }
    public static boolean staticScope(MethodCallExpr call, String qualified) {
        String simple = qualified.substring(qualified.lastIndexOf('.') + 1);
        return call.getScope().map(s -> s.toString().equals(qualified) ||
            s instanceof NameExpr n && n.getNameAsString().equals(simple) && declaration(n).isEmpty() && imported(call, simple, qualified)).orElse(false);
    }
    public static boolean chainType(Expression expr, String qualified) {
        if (type(expr, declaredType(expr), qualified)) return true;
        if (expr instanceof MethodCallExpr call) return call.getScope().map(s -> chainType(s, qualified)).orElse(false);
        return false;
    }
    public static boolean chat(Expression expr) { return chainType(expr, "org.springframework.ai.chat.client.ChatClient"); }
    public static List<MethodCallExpr> chainCalls(Expression expr) {
        List<MethodCallExpr> result = new ArrayList<>();
        Expression cursor = expr;
        while (cursor instanceof MethodCallExpr call) {
            result.add(call);
            if (call.getScope().isEmpty()) break;
            cursor = call.getScope().get();
        }
        return result;
    }
    public static boolean aiStream(Expression expr) {
        return chat(expr) && chainCalls(expr).stream().anyMatch(c -> c.getNameAsString().equals("stream"));
    }
    public static boolean modelOutput(Expression expr) {
        if (!(expr instanceof MethodCallExpr call)) return false;
        if (receiverType(call, "org.springframework.ai.chat.model.ChatModel") && call.getNameAsString().equals("call")) return true;
        return Set.of("content", "chatResponse", "entity").contains(call.getNameAsString()) && chat(call) &&
            chainCalls(call).stream().anyMatch(c -> c.getNameAsString().equals("call") || c.getNameAsString().equals("stream"));
    }
    public static boolean origin(Expression expr, Origin origin) { return origin(expr, origin, 0, new HashSet<>()); }
    private static boolean origin(Expression expr, Origin origin, int depth, Set<Node> visited) {
        if (depth > 12 || !visited.add(expr)) return false;
        if (origin == Origin.MODEL_OUTPUT && modelOutput(expr)) return true;
        if (expr instanceof EnclosedExpr e) return origin(e.getInner(), origin, depth + 1, visited);
        if (expr instanceof CastExpr e) return origin(e.getExpression(), origin, depth + 1, visited);
        if (expr instanceof BinaryExpr e) return origin(e.getLeft(), origin, depth + 1, visited) || origin(e.getRight(), origin, depth + 1, visited);
        if (expr instanceof NameExpr n) {
            var declaration = declaration(n).orElse(null);
            if (declaration instanceof Parameter p) {
                if (!parameterUnmodified(p, n)) return false;
                if (p.getParentNode().orElse(null) instanceof MethodDeclaration m)
                    return origin == Origin.WEB_INPUT && web(m) || origin == Origin.TOOL_INPUT && tool(m);
                if (origin == Origin.MODEL_OUTPUT && p.getParentNode().orElse(null) instanceof LambdaExpr lambda &&
                    lambda.getParentNode().orElse(null) instanceof MethodCallExpr call &&
                    Set.of("subscribe", "doOnNext", "map", "flatMap").contains(call.getNameAsString()))
                    return aiStream(call) && call.getScope().map(s -> chainCalls(s).stream().noneMatch(c ->
                        Set.of("map", "flatMap", "transform", "handle", "cast", "ofType").contains(c.getNameAsString()))).orElse(false);
            }
            if (declaration instanceof VariableDeclarator v && v.getInitializer().isPresent() && unmodified(v, n))
                return origin(v.getInitializer().get(), origin, depth + 1, visited);
        }
        // Method calls, returned values, conditionals and mutable fields are unresolved intentionally.
        return false;
    }
    private static boolean unmodified(VariableDeclarator v, NameExpr use) {
        var block = v.findAncestor(BlockStmt.class);
        if (block.isEmpty()) return false;
        return block.get().findAll(AssignExpr.class).stream().noneMatch(a ->
            a.getTarget().isNameExpr() && a.getTarget().asNameExpr().getNameAsString().equals(v.getNameAsString()) && before(v, a) && before(a, use)) &&
            block.get().findAll(UnaryExpr.class).stream().noneMatch(a -> a.getExpression().isNameExpr() &&
                a.getExpression().asNameExpr().getNameAsString().equals(v.getNameAsString()) && before(v, a) && before(a, use));
    }
    private static boolean parameterUnmodified(Parameter parameter, NameExpr use) {
        Node owner = parameter.getParentNode().orElse(parameter);
        return owner.findAll(AssignExpr.class).stream().noneMatch(a -> a.getTarget().isNameExpr() &&
            a.getTarget().asNameExpr().getNameAsString().equals(parameter.getNameAsString()) && before(a, use)) &&
            owner.findAll(UnaryExpr.class).stream().noneMatch(a -> a.getExpression().isNameExpr() &&
                a.getExpression().asNameExpr().getNameAsString().equals(parameter.getNameAsString()) && before(a, use));
    }
    public static boolean constant(Expression e) { return e.isLiteralExpr() || e.isBinaryExpr() && constant(e.asBinaryExpr().getLeft()) && constant(e.asBinaryExpr().getRight()); }
    public static boolean key(Expression e, String owner, String name) {
        if (!(e instanceof FieldAccessExpr f) || !f.getNameAsString().equals(name)) return false;
        String simple = owner.substring(owner.lastIndexOf('.') + 1);
        return f.getScope().toString().equals(owner) || f.getScope().toString().equals(simple) && imported(e, simple, owner);
    }
    public static boolean sink(MethodCallExpr call) {
        String name = call.getNameAsString();
        if (name.equals("exec") && call.getScope().orElse(null) instanceof MethodCallExpr runtime && runtime.getNameAsString().equals("getRuntime"))
            return runtime.getScope().map(s -> s.toString().equals("java.lang.Runtime") || s.toString().equals("Runtime") &&
                javaLangUnshadowed(runtime, "Runtime") && (!(s instanceof NameExpr n) || declaration(n).isEmpty())).orElse(false);
        if (name.equals("exec") && call.getScope().map(s -> declaredType(s).equals("java.lang.Runtime") ||
            declaredType(s).equals("Runtime") && javaLangUnshadowed(call, "Runtime")).orElse(false)) return true;
        return Set.of("execute", "update", "query", "queryForObject", "queryForList", "batchUpdate").contains(name) &&
            receiverType(call, "org.springframework.jdbc.core.JdbcTemplate");
    }
    public static boolean processBuilder(ObjectCreationExpr expr) {
        return expr.getTypeAsString().equals("java.lang.ProcessBuilder") || expr.getTypeAsString().equals("ProcessBuilder") &&
            javaLangUnshadowed(expr, "ProcessBuilder");
    }
    public static boolean javaLangUnshadowed(Node node, String simple) {
        return node.findCompilationUnit().map(c ->
            c.findAll(TypeDeclaration.class).stream().noneMatch(t -> t.getNameAsString().equals(simple)) &&
            c.getImports().stream().noneMatch(i -> !i.isStatic() && !i.isAsterisk() &&
                i.getNameAsString().endsWith("." + simple) && !i.getNameAsString().equals("java.lang." + simple))).orElse(false);
    }
    public static boolean logger(MethodCallExpr call) {
        if (!Set.of("trace", "debug", "info", "warn", "error").contains(call.getNameAsString())) return false;
        if (receiverType(call, "org.slf4j.Logger")) return true;
        return call.getScope().map(s -> s instanceof NameExpr n && n.getNameAsString().equals("log") && declaration(n).isEmpty()).orElse(false) &&
            call.findAncestor(ClassOrInterfaceDeclaration.class).map(c -> annotation(c, "lombok.extern.slf4j.Slf4j")).orElse(false);
    }
    public static List<MethodCallExpr> calls(JavaSource source) { return source.unit().findAll(MethodCallExpr.class); }
}
