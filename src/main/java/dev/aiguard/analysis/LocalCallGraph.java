package dev.aiguard.analysis;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.*;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.type.ClassOrInterfaceType;
import dev.aiguard.analysis.SourceProject.JavaSource;
import dev.aiguard.analysis.rules.AstSupport;
import dev.aiguard.model.ScanModel.Diagnostic;
import java.util.*;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/** Offline source-only declaration graph. A resolved edge is not proof of runtime execution. */
public final class LocalCallGraph {
    public record MethodId(String path, String ownerFqn, String name, List<String> parameterTypes, int line) {
        public MethodId { parameterTypes = List.copyOf(parameterTypes); }
    }
    public record MethodInfo(MethodId id, JavaSource source, MethodDeclaration declaration) {}
    public enum Resolution { RESOLVED, CANDIDATE, UNKNOWN }
    public enum Reason {
        EXPLICIT_SOURCE_TARGET, VIRTUAL_DISPATCH, INTERFACE_DISPATCH, DUPLICATE_TYPE,
        AMBIGUOUS_OVERLOAD, UNKNOWN_RECEIVER, EXTERNAL_TYPE, MUTABLE_ALIAS,
        UNSUPPORTED_EXPRESSION, BUDGET
    }
    public record Edge(MethodId caller, MethodCallExpr callsite, List<MethodId> targets,
                       Resolution resolution, Set<Reason> reasons) {
        public Edge { targets = List.copyOf(targets); reasons = Set.copyOf(reasons); }
    }
    private record TypeInfo(String name, JavaSource source, TypeDeclaration<?> declaration) {}
    private record Selection(List<MethodInfo> targets, boolean uncertain, int score) {}
    private record RawType(Node context, String text) {}
    private static final int MAX_METHODS = 30_000, MAX_CALLS = 100_000, MAX_TARGETS = 16, MAX_DEPTH = 8, MAX_EXPRESSION_DEPTH = 24;
    private static final Set<String> PRIMITIVES = Set.of("boolean", "byte", "short", "int", "long", "float", "double", "char", "void");
    private static final Set<String> JAVA_LANG = Set.of("String", "Object", "Boolean", "Byte", "Short", "Integer", "Long", "Float", "Double", "Character", "Void", "Number", "Class", "Enum", "Record", "Throwable", "Exception", "RuntimeException", "StringBuilder", "StringBuffer", "Iterable", "Comparable", "Runnable", "Runtime", "ProcessBuilder");
    private static final Map<String, Set<String>> KNOWN_WILDCARDS = Map.of(
        "java.util", Set.of("List", "Map", "Set", "Collection", "ArrayList", "HashMap", "LinkedHashMap", "HashSet", "LinkedHashSet", "Optional", "Iterator", "Collections", "Arrays", "Objects", "UUID"),
        "java.util.function", Set.of("Consumer", "BiConsumer", "Function", "BiFunction", "Supplier", "Predicate", "UnaryOperator", "BinaryOperator"),
        "java.util.concurrent", Set.of("CompletableFuture", "Future", "Executor", "ExecutorService", "ConcurrentHashMap"),
        "okhttp3", Set.of("OkHttpClient", "Request", "Response", "RequestBody", "MediaType", "ResponseBody"),
        "okhttp3.sse", Set.of("EventSource", "EventSources", "EventSourceListener"),
        "com.fasterxml.jackson.databind", Set.of("ObjectMapper", "JsonNode"));
    private final BooleanSupplier cancelled;
    private final Map<String, List<TypeInfo>> types = new LinkedHashMap<>();
    private final Map<Node, String> owners = new IdentityHashMap<>();
    private final Map<MethodId, MethodInfo> methods = new LinkedHashMap<>();
    private final Map<MethodDeclaration, MethodInfo> declarations = new IdentityHashMap<>();
    private final Map<String, List<MethodInfo>> ownerMethods = new HashMap<>();
    private final Map<String, List<String>> parents = new HashMap<>(), children = new HashMap<>();
    private final Map<String, List<String>> subtypeCache = new HashMap<>();
    private final Map<MethodCallExpr, Edge> edges = new IdentityHashMap<>();
    private final Map<MethodId, List<Edge>> outgoing = new LinkedHashMap<>();
    private final List<Diagnostic> diagnostics = new ArrayList<>();
    private final Set<String> diagnosticKeys = new HashSet<>();
    private final Set<MethodCallExpr> resolving = Collections.newSetFromMap(new IdentityHashMap<>());
    private int indexedCalls;

    private LocalCallGraph(BooleanSupplier cancelled) { this.cancelled = cancelled; }
    public static LocalCallGraph build(SourceProject project, BooleanSupplier cancelled) {
        var graph = new LocalCallGraph(cancelled);
        graph.index(project);
        return graph;
    }
    public List<MethodInfo> methods() { return List.copyOf(methods.values()); }
    public Optional<MethodInfo> method(MethodId id) { return Optional.ofNullable(methods.get(id)); }
    public List<Edge> callsFrom(MethodId id) { return outgoing.getOrDefault(id, List.of()); }
    public List<Diagnostic> diagnostics() { return List.copyOf(diagnostics); }
    public Optional<MethodInfo> enclosing(Node node) {
        Node current = node;
        while (current != null) {
            if (current instanceof MethodDeclaration m) return Optional.ofNullable(declarations.get(m));
            current = current.getParentNode().orElse(null);
        }
        return Optional.empty();
    }
    public Edge resolve(MethodCallExpr call) { return resolve(call, 0); }
    public String expressionType(Expression expression) { return expressionType(expression, 0); }
    public String qualifiedType(Node context, String raw) { return qualifiedType(context, raw, 0); }

    public List<Edge> reachable(MethodId entry, int maxDepth) {
        int limit = Math.max(0, Math.min(MAX_DEPTH, maxDepth));
        record Step(MethodId method, int depth) {}
        var queue = new ArrayDeque<Step>();
        var visited = new HashSet<MethodId>();
        var found = new LinkedHashSet<Edge>();
        queue.add(new Step(entry, 0));
        while (!queue.isEmpty()) {
            check();
            var step = queue.remove();
            if (!visited.add(step.method())) continue;
            if (step.depth() >= limit) {
                if (!callsFrom(step.method()).isEmpty()) diagnostic("CALL_GRAPH_DEPTH_LIMIT", step.method().path(), "Call graph traversal reached its depth budget; deeper source paths remain unresolved.");
                continue;
            }
            for (Edge edge : callsFrom(step.method())) {
                check();
                if (found.size() >= MAX_CALLS) { diagnostic("CALL_GRAPH_TRAVERSAL_LIMIT", "", "Call graph traversal reached its edge budget; coverage is incomplete."); return List.copyOf(found); }
                found.add(edge);
                for (MethodId target : edge.targets()) queue.add(new Step(target, step.depth() + 1));
            }
        }
        return List.copyOf(found);
    }

    private void index(SourceProject project) {
        var sources = project.sources().stream().sorted(Comparator.comparing(JavaSource::path)).toList();
        for (JavaSource source : sources) {
            check();
            for (TypeDeclaration<?> declaration : source.unit().findAll(TypeDeclaration.class)) {
                check();
                if (declaration.findAncestor(MethodDeclaration.class).isPresent()) {
                    diagnostic("CALL_GRAPH_LOCAL_TYPE", source.path(), "Local class declarations are outside the supported type binding scope.");
                    continue;
                }
                String name = typeName(declaration);
                types.computeIfAbsent(name, ignored -> new ArrayList<>()).add(new TypeInfo(name, source, declaration));
                owners.put(declaration, name);
            }
        }
        for (var item : types.entrySet()) {
            check();
            if (item.getValue().size() > 1) diagnostic("CALL_GRAPH_DUPLICATE_TYPE", item.getValue().getFirst().source().path(), "Duplicate source type names prevent unique binding; no declaration is preferred.");
        }
        for (var list : types.values()) for (TypeInfo type : list) {
            check();
            List<ClassOrInterfaceType> supers = new ArrayList<>();
            if (type.declaration() instanceof ClassOrInterfaceDeclaration c) { supers.addAll(c.getExtendedTypes()); supers.addAll(c.getImplementedTypes()); }
            if (type.declaration() instanceof RecordDeclaration r) supers.addAll(r.getImplementedTypes());
            if (type.declaration() instanceof EnumDeclaration e) supers.addAll(e.getImplementedTypes());
            for (var parent : supers) {
                String q = qualifiedType(type.declaration(), parent.asString());
                if (!q.isEmpty()) {
                    parents.computeIfAbsent(type.name(), ignored -> new ArrayList<>()).add(q);
                    children.computeIfAbsent(q, ignored -> new ArrayList<>()).add(type.name());
                }
            }
        }
        for (JavaSource source : sources) for (MethodDeclaration declaration : source.unit().findAll(MethodDeclaration.class)) {
            check();
            if (methods.size() >= MAX_METHODS) { diagnostic("CALL_GRAPH_METHOD_LIMIT", source.path(), "The source method index reached its budget; coverage is incomplete."); break; }
            String owner = owner(declaration);
            if (owner.isEmpty()) continue;
            var parameters = declaration.getParameters().stream().map(p -> {
                String type = qualifiedType(p, p.getTypeAsString());
                return (type.isEmpty() ? "?" + erase(p.getTypeAsString()) : type) + (p.isVarArgs() ? "[]" : "");
            }).toList();
            var id = new MethodId(source.path(), owner, declaration.getNameAsString(), parameters, AstSupport.line(declaration));
            var info = new MethodInfo(id, source, declaration);
            // Duplicate declarations retain separate unknown binding rather than replacing indexed methods.
            if (methods.containsKey(id)) { diagnostic("CALL_GRAPH_DUPLICATE_METHOD", source.path(), "Duplicate method declarations prevent unique binding."); continue; }
            methods.put(id, info); declarations.put(declaration, info);
            ownerMethods.computeIfAbsent(owner, ignored -> new ArrayList<>()).add(info);
        }
        for (MethodInfo info : methods.values()) {
            check();
            var calls = new ArrayList<Edge>();
            for (MethodCallExpr call : info.declaration().findAll(MethodCallExpr.class)) {
                check();
                if (!enclosing(call).map(m -> m.id().equals(info.id())).orElse(false)) continue;
                if (indexedCalls++ >= MAX_CALLS) { diagnostic("CALL_GRAPH_CALL_LIMIT", info.id().path(), "The source call index reached its budget; coverage is incomplete."); break; }
                calls.add(resolve(call));
            }
            outgoing.put(info.id(), List.copyOf(calls));
        }
    }

    private Edge resolve(MethodCallExpr call, int depth) {
        check();
        Edge cached = edges.get(call);
        if (cached != null) return cached;
        if (edges.size() >= MAX_CALLS) {
            diagnostic("CALL_GRAPH_CALL_LIMIT", enclosing(call).map(m -> m.id().path()).orElse(""), "The source call index reached its budget; coverage is incomplete.");
            return unknown(call, Reason.BUDGET);
        }
        if (depth > MAX_EXPRESSION_DEPTH || !resolving.add(call)) return unknown(call, Reason.UNSUPPORTED_EXPRESSION);
        try {
            Edge edge = bind(call, depth + 1);
            edges.put(call, edge);
            return edge;
        } finally { resolving.remove(call); }
    }
    private Edge bind(MethodCallExpr call, int depth) {
        var caller = enclosing(call).map(MethodInfo::id).orElse(null);
        String receiver;
        boolean explicit = false, staticReceiver = false;
        if (call.getScope().isPresent()) {
            Expression scope = call.getScope().get();
            if (unwrap(scope) instanceof ObjectCreationExpr creation && creation.getAnonymousClassBody().isPresent())
                return unknown(call, Reason.UNSUPPORTED_EXPRESSION);
            receiver = expressionType(scope, depth);
            explicit = unwrap(scope) instanceof ObjectCreationExpr || scope instanceof SuperExpr;
            if (receiver.isEmpty() && (scope instanceof NameExpr || scope instanceof FieldAccessExpr)) {
                boolean isVariable = scope instanceof NameExpr n && declaration(n).isPresent();
                if (!isVariable) { receiver = qualifiedType(scope, scope.toString()); staticReceiver = !receiver.isEmpty(); }
            }
        } else receiver = owner(call);
        if (receiver.isEmpty()) return unknown(call, Reason.UNKNOWN_RECEIVER);
        List<TypeInfo> matches = types.getOrDefault(receiver, List.of());
        if (matches.size() > 1) return unknown(call, Reason.DUPLICATE_TYPE);
        if (matches.isEmpty()) {
            if (call.getScope().isEmpty()) {
                Edge imported = staticImport(call, depth);
                if (imported != null) return imported;
            }
            return unknown(call, Reason.EXTERNAL_TYPE);
        }
        TypeInfo type = matches.getFirst();
        Selection selected = select(receiver, call, depth, new HashSet<>());
        if (selected.targets().isEmpty() && call.getScope().isEmpty()) {
            Edge imported = staticImport(call, depth);
            if (imported != null) return imported;
        }
        var targets = new LinkedHashMap<MethodId, MethodInfo>();
        boolean uncertain = selected.uncertain();
        boolean contract = type.declaration() instanceof ClassOrInterfaceDeclaration c && c.isInterface();
        boolean fixed = explicit || isFinal(type.declaration()) || staticReceiver || !selected.targets().isEmpty() && selected.targets().stream().allMatch(m -> m.declaration().isPrivate() || m.declaration().isStatic() || m.declaration().isFinal());
        if (!contract || fixed) for (MethodInfo m : selected.targets()) targets.put(m.id(), m);
        if (!fixed) {
            for (String subtype : subtypes(receiver)) {
                check();
                if (types.getOrDefault(subtype, List.of()).size() != 1) { uncertain = true; continue; }
                Selection selection = select(subtype, call, depth, new HashSet<>());
                uncertain |= selection.uncertain();
                for (MethodInfo m : selection.targets()) if (m.declaration().getBody().isPresent()) targets.put(m.id(), m);
                if (targets.size() > MAX_TARGETS) break;
            }
        }
        if (targets.isEmpty()) for (MethodInfo m : selected.targets()) targets.put(m.id(), m);
        if (staticReceiver) targets.values().removeIf(m -> !m.declaration().isStatic());
        if (targets.isEmpty()) return unknown(call, Reason.UNSUPPORTED_EXPRESSION);
        Set<Reason> reasons = EnumSet.noneOf(Reason.class);
        if (contract) reasons.add(Reason.INTERFACE_DISPATCH);
        else if (!fixed) reasons.add(Reason.VIRTUAL_DISPATCH);
        if (selected.targets().size() > 1 || uncertain) reasons.add(Reason.AMBIGUOUS_OVERLOAD);
        List<MethodId> ids = new ArrayList<>(targets.keySet());
        if (ids.size() > MAX_TARGETS) {
            ids = ids.subList(0, MAX_TARGETS); reasons.add(Reason.BUDGET); uncertain = true;
            diagnostic("CALL_GRAPH_TARGET_LIMIT", caller == null ? "" : caller.path(), "A call has more source candidates than the supported budget; coverage is incomplete.");
        }
        Resolution resolution = fixed && !uncertain && ids.size() == 1 ? Resolution.RESOLVED : Resolution.CANDIDATE;
        if (resolution == Resolution.RESOLVED) reasons.add(Reason.EXPLICIT_SOURCE_TARGET);
        return new Edge(caller, call, ids, resolution, reasons);
    }

    private Selection select(String owner, MethodCallExpr call, int depth, Set<String> visited) {
        check();
        if (!visited.add(owner) || visited.size() > MAX_DEPTH) return new Selection(List.of(), true, Integer.MAX_VALUE);
        int best = Integer.MAX_VALUE;
        boolean uncertain = false;
        List<MethodInfo> chosen = new ArrayList<>();
        for (MethodInfo info : ownerMethods.getOrDefault(owner, List.of())) {
            check();
            if (!info.id().name().equals(call.getNameAsString())) continue;
            var parameters = info.declaration().getParameters();
            boolean varargs = !parameters.isEmpty() && parameters.get(parameters.size() - 1).isVarArgs();
            if ((!varargs && parameters.size() != call.getArguments().size()) || varargs && call.getArguments().size() < parameters.size() - 1) continue;
            int score = varargs ? 4 : 0;
            boolean unknown = false, compatible = true;
            for (int i = 0; i < call.getArguments().size(); i++) {
                check();
                var p = parameters.get(Math.min(i, parameters.size() - 1));
                String expected = qualifiedType(p, p.getTypeAsString());
                String actual = expressionType(call.getArgument(i), depth + 1);
                if (expected.isEmpty() || actual.isEmpty() || actual.equals("<null>")) { score += 8; unknown = true; }
                else if (expected.equals(actual)) { /* exact */ }
                else if (boxed(expected).equals(boxed(actual))) score++;
                else if (expected.equals("java.lang.Object") && !PRIMITIVES.contains(actual) || isSubtype(actual, expected, new HashSet<>())) score += 2;
                else { compatible = false; break; }
            }
            if (!compatible) continue;
            if (score < best) { chosen.clear(); best = score; uncertain = unknown; }
            if (score == best) { chosen.add(info); uncertain |= unknown; }
        }
        for (String parent : parents.getOrDefault(owner, List.of())) {
            Selection inherited = select(parent, call, depth + 1, visited);
            List<MethodInfo> visible = inherited.targets().stream().filter(m -> !m.declaration().isPrivate() &&
                ownerMethods.getOrDefault(owner, List.of()).stream().noneMatch(local -> local.id().name().equals(m.id().name()) &&
                    local.id().parameterTypes().equals(m.id().parameterTypes()))).toList();
            if (visible.isEmpty()) continue;
            if (inherited.score() < best) { chosen.clear(); best = inherited.score(); uncertain = inherited.uncertain(); }
            if (inherited.score() == best) { chosen.addAll(visible); uncertain |= inherited.uncertain(); }
        }
        return new Selection(List.copyOf(chosen), uncertain, best);
    }
    private Edge staticImport(MethodCallExpr call, int depth) {
        var unit = call.findCompilationUnit();
        if (unit.isEmpty()) return null;
        List<MethodInfo> targets = new ArrayList<>();
        boolean uncertain = false;
        for (var imp : unit.get().getImports()) {
            check();
            if (!imp.isStatic()) continue;
            String imported = imp.getNameAsString();
            if (!imp.isAsterisk() && !imported.endsWith("." + call.getNameAsString())) continue;
            String owner = imp.isAsterisk() ? imported : imported.substring(0, imported.lastIndexOf('.'));
            if (types.getOrDefault(owner, List.of()).size() != 1) continue;
            Selection selection = select(owner, call, depth, new HashSet<>());
            targets.addAll(selection.targets().stream().filter(m -> m.declaration().isStatic()).toList());
            uncertain |= selection.uncertain();
        }
        if (targets.isEmpty()) return null;
        return new Edge(enclosing(call).map(MethodInfo::id).orElse(null), call, targets.stream().limit(MAX_TARGETS).map(MethodInfo::id).toList(),
            targets.size() == 1 && !uncertain ? Resolution.RESOLVED : Resolution.CANDIDATE,
            Set.of(targets.size() == 1 && !uncertain ? Reason.EXPLICIT_SOURCE_TARGET : Reason.AMBIGUOUS_OVERLOAD));
    }

    private String expressionType(Expression expression, int depth) {
        check();
        if (depth > MAX_EXPRESSION_DEPTH) return "";
        Expression e = unwrap(expression);
        if (e instanceof StringLiteralExpr || e instanceof TextBlockLiteralExpr) return "java.lang.String";
        if (e instanceof BooleanLiteralExpr) return "boolean";
        if (e instanceof IntegerLiteralExpr) return "int";
        if (e instanceof LongLiteralExpr) return "long";
        if (e instanceof DoubleLiteralExpr d) return d.getValue().toLowerCase(Locale.ROOT).endsWith("f") ? "float" : "double";
        if (e instanceof CharLiteralExpr) return "char";
        if (e instanceof NullLiteralExpr) return "<null>";
        if (e instanceof ObjectCreationExpr creation) return qualifiedType(e, creation.getTypeAsString());
        if (e instanceof CastExpr cast) return qualifiedType(e, cast.getTypeAsString());
        if (e instanceof ThisExpr) return owner(e);
        if (e instanceof SuperExpr) return parents.getOrDefault(owner(e), List.of()).stream().findFirst().orElse("");
        if (e instanceof ClassExpr) return "java.lang.Class";
        if (e instanceof NameExpr name) {
            var declaration = declaration(name).orElse(null);
            if (declaration instanceof Parameter p) return qualifiedType(p, p.getTypeAsString());
            if (declaration instanceof VariableDeclarator v) {
                if (v.getType().isVarType()) return v.getInitializer().map(i -> expressionType(i, depth + 1)).orElse("");
                return qualifiedType(v, v.getTypeAsString());
            }
            return "";
        }
        if (e instanceof FieldAccessExpr field) {
            String receiver = expressionType(field.getScope(), depth + 1);
            return fieldType(receiver, field.getNameAsString(), depth + 1, new HashSet<>());
        }
        if (e instanceof ArrayAccessExpr array) {
            String type = expressionType(array.getName(), depth + 1);
            return type.endsWith("[]") ? type.substring(0, type.length() - 2) : "";
        }
        if (e instanceof MethodCallExpr call) {
            Edge edge = resolve(call, depth + 1);
            Set<String> returns = new HashSet<>();
            for (MethodId id : edge.targets()) {
                MethodInfo info = methods.get(id);
                if (info != null) returns.add(qualifiedType(info.declaration(), info.declaration().getTypeAsString()));
            }
            if (returns.size() == 1 && !returns.contains("")) return returns.iterator().next();
            if (edge.targets().isEmpty() && call.getScope().isPresent() && call.getArguments().isEmpty()) {
                String type = expressionType(call.getScope().get(), depth + 1);
                List<TypeInfo> matches = types.getOrDefault(type, List.of());
                if (matches.size() == 1 && matches.getFirst().declaration() instanceof RecordDeclaration record)
                    for (Parameter p : record.getParameters()) if (p.getNameAsString().equals(call.getNameAsString())) return qualifiedType(p, p.getTypeAsString());
            }
            if (call.getNameAsString().equals("get") && call.getArguments().size() == 1 && call.getScope().isPresent()) {
                String receiver = expressionType(call.getScope().get(), depth + 1);
                if (Set.of("java.util.List", "java.util.ArrayList", "java.util.Collection").contains(receiver)) {
                    RawType raw = rawType(call.getScope().get(), depth + 1);
                    if (raw != null) { String arg = singleTypeArgument(raw.text()); if (!arg.isEmpty()) return qualifiedType(raw.context(), arg); }
                }
            }
            return "";
        }
        if (e instanceof ConditionalExpr conditional) {
            String first = expressionType(conditional.getThenExpr(), depth + 1);
            return first.equals(expressionType(conditional.getElseExpr(), depth + 1)) ? first : "";
        }
        if (e instanceof BinaryExpr binary) {
            String left = expressionType(binary.getLeft(), depth + 1), right = expressionType(binary.getRight(), depth + 1);
            if (binary.getOperator() == BinaryExpr.Operator.PLUS && (left.equals("java.lang.String") || right.equals("java.lang.String"))) return "java.lang.String";
            return left.equals(right) ? left : "";
        }
        return "";
    }
    private RawType rawType(Expression expression, int depth) {
        if (depth > MAX_EXPRESSION_DEPTH) return null;
        Expression e = unwrap(expression);
        if (e instanceof NameExpr name) {
            Node declaration = declaration(name).orElse(null);
            if (declaration instanceof Parameter p) return new RawType(p, p.getTypeAsString());
            if (declaration instanceof VariableDeclarator v) return new RawType(v, v.getTypeAsString());
        }
        if (e instanceof MethodCallExpr call) {
            Edge edge = resolve(call, depth + 1);
            if (edge.targets().size() == 1) {
                MethodInfo info = methods.get(edge.targets().getFirst());
                return new RawType(info.declaration(), info.declaration().getTypeAsString());
            }
            if (call.getScope().isPresent()) {
                var matches = types.getOrDefault(expressionType(call.getScope().get(), depth + 1), List.of());
                if (matches.size() == 1 && matches.getFirst().declaration() instanceof RecordDeclaration record)
                    for (Parameter p : record.getParameters()) if (p.getNameAsString().equals(call.getNameAsString())) return new RawType(p, p.getTypeAsString());
            }
        }
        return null;
    }
    private String fieldType(String receiver, String name, int depth, Set<String> visited) {
        if (depth > MAX_DEPTH || !visited.add(receiver)) return "";
        var matches = types.getOrDefault(receiver, List.of());
        if (matches.size() != 1) return "";
        for (FieldDeclaration field : matches.getFirst().declaration().getFields()) for (VariableDeclarator variable : field.getVariables())
            if (variable.getNameAsString().equals(name)) return qualifiedType(variable, variable.getTypeAsString());
        for (String parent : parents.getOrDefault(receiver, List.of())) {
            String type = fieldType(parent, name, depth + 1, visited);
            if (!type.isEmpty()) return type;
        }
        return "";
    }
    private Optional<Node> declaration(NameExpr name) {
        return AstSupport.declaration(name);
    }

    private String qualifiedType(Node context, String raw, int depth) {
        check();
        if (depth > MAX_DEPTH || raw == null || raw.length() > 4096) return "";
        String name = erase(raw);
        if (name.isEmpty() || name.equals("var") || name.contains("?") || name.contains(" ")) return "";
        if (name.endsWith("[]")) {
            String element = qualifiedType(context, name.substring(0, name.length() - 2), depth + 1);
            return element.isEmpty() ? "" : element + "[]";
        }
        if (PRIMITIVES.contains(name)) return name;
        Node typeContext = context;
        while (typeContext != null) {
            if (typeContext instanceof com.github.javaparser.ast.nodeTypes.NodeWithTypeParameters<?> generic &&
                generic.getTypeParameters().stream().anyMatch(p -> p.getNameAsString().equals(name))) return "";
            typeContext = typeContext.getParentNode().orElse(null);
        }
        if (name.contains(".") && Character.isLowerCase(name.charAt(0)) && types.containsKey(name)) return uniqueType(name);
        String owner = owner(context);
        while (!owner.isEmpty() && types.containsKey(owner)) {
            String nested = owner + "." + name;
            if (types.containsKey(nested)) return uniqueType(nested);
            int dot = owner.lastIndexOf('.'); owner = dot < 0 ? "" : owner.substring(0, dot);
        }
        if (name.contains(".") && Character.isUpperCase(name.charAt(0))) {
            int dot = name.indexOf('.');
            String outer = qualifiedType(context, name.substring(0, dot), depth + 1);
            if (!outer.isEmpty()) {
                String nested = outer + name.substring(dot);
                if (types.containsKey(outer)) return uniqueType(nested);
                return nested;
            }
        }
        var unit = context.findCompilationUnit();
        if (unit.isPresent()) {
            String first = name.contains(".") ? name.substring(0, name.indexOf('.')) : name;
            Set<String> imports = new LinkedHashSet<>();
            for (var imp : unit.get().getImports()) {
                if (!imp.isAsterisk() && (!imp.isStatic() || types.containsKey(imp.getNameAsString())) && imp.getNameAsString().endsWith("." + first))
                    imports.add(imp.getNameAsString() + name.substring(first.length()));
            }
            if (imports.size() > 1) return "";
            if (imports.size() == 1) { String imported = imports.iterator().next(); return types.containsKey(imported) ? uniqueType(imported) : imported; }
            String packageName = unit.get().getPackageDeclaration().map(p -> p.getNameAsString() + ".").orElse("");
            if (types.containsKey(packageName + name)) return uniqueType(packageName + name);
            Set<String> wildcards = new LinkedHashSet<>();
            for (var imp : unit.get().getImports()) if (imp.isAsterisk() && !imp.isStatic()) {
                String candidate = imp.getNameAsString() + "." + name;
                if (types.containsKey(candidate) || KNOWN_WILDCARDS.getOrDefault(imp.getNameAsString(), Set.of()).contains(first)) wildcards.add(candidate);
            }
            if (wildcards.size() == 1) { String wildcard = wildcards.iterator().next(); return types.containsKey(wildcard) ? uniqueType(wildcard) : wildcard; }
            if (wildcards.size() > 1) return "";
        }
        if (JAVA_LANG.contains(name)) return "java.lang." + name;
        if (name.contains(".") && Character.isLowerCase(name.charAt(0))) return name;
        return "";
    }
    private String uniqueType(String name) { return types.getOrDefault(name, List.of()).size() == 1 ? name : ""; }
    private String owner(Node node) {
        Node current = node;
        while (current != null) {
            if (current instanceof ObjectCreationExpr creation && creation.getAnonymousClassBody().isPresent()) {
                String outer = owner(creation.getParentNode().orElse(null));
                return outer + "$anonymous" + AstSupport.line(creation) + "_" + creation.getBegin().map(p -> p.column).orElse(0);
            }
            String found = owners.get(current);
            if (found != null) return found;
            if (current instanceof TypeDeclaration<?> declaration) return typeName(declaration);
            current = current.getParentNode().orElse(null);
        }
        return "";
    }
    private static String typeName(TypeDeclaration<?> type) {
        List<String> names = new ArrayList<>();
        Node cursor = type;
        while (cursor != null) {
            if (cursor instanceof TypeDeclaration<?> declaration) names.addFirst(declaration.getNameAsString());
            cursor = cursor.getParentNode().orElse(null);
        }
        String prefix = type.findCompilationUnit().flatMap(c -> c.getPackageDeclaration()).map(p -> p.getNameAsString() + ".").orElse("");
        return prefix + String.join(".", names);
    }
    private List<String> subtypes(String type) {
        var cached = subtypeCache.get(type);
        if (cached != null) return cached;
        var result = new LinkedHashSet<String>();
        var queue = new ArrayDeque<String>(children.getOrDefault(type, List.of()));
        while (!queue.isEmpty()) {
            check();
            String current = queue.remove();
            if (!result.add(current)) continue;
            if (result.size() >= MAX_METHODS) { diagnostic("CALL_GRAPH_TYPE_LIMIT", "", "Subtype traversal reached its budget; coverage is incomplete."); break; }
            queue.addAll(children.getOrDefault(current, List.of()));
        }
        var output = List.copyOf(result); subtypeCache.put(type, output); return output;
    }
    private boolean isSubtype(String type, String parent, Set<String> visited) {
        check();
        if (type.equals(parent)) return true;
        if (!visited.add(type) || visited.size() > MAX_DEPTH) return false;
        for (String candidate : parents.getOrDefault(type, List.of())) if (isSubtype(candidate, parent, visited)) return true;
        return false;
    }
    private Edge unknown(MethodCallExpr call, Reason reason) { return new Edge(enclosing(call).map(MethodInfo::id).orElse(null), call, List.of(), Resolution.UNKNOWN, Set.of(reason)); }
    private void diagnostic(String code, String path, String message) {
        if (diagnosticKeys.add(code + "\0" + path)) diagnostics.add(new Diagnostic(code, path, message));
    }
    private void check() { if (cancelled.getAsBoolean() || Thread.currentThread().isInterrupted()) throw new CancellationException("Scan cancelled"); }
    private static Expression unwrap(Expression expression) {
        while (expression instanceof EnclosedExpr enclosed) expression = enclosed.getInner();
        return expression;
    }
    private static boolean isFinal(TypeDeclaration<?> declaration) { return declaration instanceof RecordDeclaration || declaration instanceof EnumDeclaration || declaration instanceof ClassOrInterfaceDeclaration c && c.isFinal(); }
    private static String erase(String raw) {
        var result = new StringBuilder(); int depth = 0;
        for (char c : raw.trim().toCharArray()) { if (c == '<') depth++; else if (c == '>') depth--; else if (depth == 0) result.append(c); }
        return result.toString().trim();
    }
    private static String singleTypeArgument(String text) {
        int first = text.indexOf('<'), last = text.lastIndexOf('>');
        if (first < 0 || last <= first) return "";
        String argument = text.substring(first + 1, last).trim();
        return argument.contains(",") || argument.startsWith("?") ? "" : argument;
    }
    private static String boxed(String type) {
        return switch (type) {
            case "boolean" -> "java.lang.Boolean"; case "byte" -> "java.lang.Byte"; case "short" -> "java.lang.Short";
            case "int" -> "java.lang.Integer"; case "long" -> "java.lang.Long"; case "float" -> "java.lang.Float";
            case "double" -> "java.lang.Double"; case "char" -> "java.lang.Character"; default -> type;
        };
    }
}
