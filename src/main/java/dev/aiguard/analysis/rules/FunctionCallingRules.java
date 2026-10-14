package dev.aiguard.analysis.rules;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.*;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.stmt.*;
import dev.aiguard.analysis.GatewayModel;
import dev.aiguard.analysis.LocalCallGraph;
import dev.aiguard.analysis.LocalCallGraph.MethodInfo;
import dev.aiguard.analysis.SourceProject;
import dev.aiguard.model.ScanModel.*;
import java.util.*;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/** Protocol-shaped, source-bound function dispatch evidence; never a general authorization proof. */
public final class FunctionCallingRules {
    private static final String REFERENCE = "https://genai.owasp.org/llmrisk/llm062025-excessive-agency/";
    public static final List<Rule> CATALOG = List.of(
        new Rule("AI-FC-001", Domain.L2, "Function Calling 分派边界",
            "关联模型返回字段与局部分派方法，观察固定 switch、Map 查找及未知名称拒绝结构，检查名称/参数到命令或反射选择的直接路径。",
            "仅分派到服务端允许的操作；未知名称应拒绝，执行前独立鉴权，禁止模型字段直接决定命令或反射目标。", List.of(REFERENCE)),
        new Rule("AI-FC-002", Domain.L7, "Function Calling 参数验证",
            "区分工具参数提取、JSON 解码和显式验证调用；工具目录的 schema 声明与解析成功均不能证明执行前验证。",
            "在执行前验证参数类型、范围和业务约束，并检查拒绝结果；限制参数大小、工具调用次数与结果大小。", List.of(REFERENCE)),
        new Rule("AI-FC-003", Domain.L2, "Function Calling 上下文来源",
            "观察模型名称/参数与额外分派实参是否分离；不以变量名推断用户身份或授权语义。",
            "从已认证的服务端上下文获得身份和租户，独立校验每个工具的授权与资源归属，不接受模型传入的权限。", List.of(REFERENCE))
    );
    private enum Kind { NAME, ARGUMENTS }
    private record Flow(Kind kind, List<Evidence> evidence, boolean candidate) {}
    private final LocalCallGraph graph;
    private final GatewayModel gateways;
    private final BooleanSupplier cancelled;
    private final Map<LocalCallGraph.MethodId, List<LocalCallGraph.Edge>> incoming = new HashMap<>();
    private final Map<String, Bucket> results = new LinkedHashMap<>();
    private final Map<Node, List<AssignExpr>> writes = new IdentityHashMap<>();
    private final Map<MethodDeclaration, Map<String, Set<String>>> protocolKeys = new IdentityHashMap<>();
    private int budget = 200_000;

    private FunctionCallingRules(LocalCallGraph graph, GatewayModel gateways, BooleanSupplier cancelled) {
        this.graph = graph; this.gateways = gateways; this.cancelled = cancelled;
        CATALOG.forEach(rule -> results.put(rule.id(), new Bucket(rule)));
        for (MethodInfo method : graph.methods()) {
            check();
            for (var edge : graph.callsFrom(method.id())) {
                check();
                for (var target : edge.targets()) incoming.computeIfAbsent(target, ignored -> new ArrayList<>()).add(edge);
            }
        }
    }
    public static List<Assessment> assess(SourceProject project, LocalCallGraph graph, GatewayModel gateways,
                                          BooleanSupplier cancelled) {
        return new FunctionCallingRules(graph, gateways, cancelled).run(project);
    }
    public static List<Rule> catalog() { return CATALOG; }

    private List<Assessment> run(SourceProject project) {
        check();
        boolean detected = false;
        methods: for (MethodInfo method : graph.methods()) {
            check();
            for (var call : method.declaration().findAll(MethodCallExpr.class)) {
                check();
                if (budget <= 0) break methods;
                if (call.findAncestor(MethodDeclaration.class).orElse(null) != method.declaration()) continue;
                var argumentFlows = new HashMap<Integer, Flow>();
                for (int i = 0; i < call.getArguments().size(); i++) {
                    Flow flow = flow(call.getArgument(i), 0, new HashSet<>());
                    if (flow != null) argumentFlows.put(i, flow);
                }
                int dangerous = dangerousArgument(call);
                if (argumentFlows.containsKey(dangerous)) {
                    detected = true;
                    Flow flow = argumentFlows.get(dangerous);
                    results.get("AI-FC-001").add(flow.candidate ? Disposition.UNKNOWN : Disposition.VIOLATED, method, call,
                        "模型工具字段直接进入命令文本或反射目标选择；候选来源仅作未知证据。", flow.evidence);
                    unknown("AI-FC-002", method, call, "工具字段的执行前参数验证与拒绝路径仍未证明。");
                    unknown("AI-FC-003", method, call, "工具执行的服务端授权与身份来源仍未证明。");
                }
                if (argumentFlows.values().stream().noneMatch(f -> f.kind == Kind.NAME) ||
                    argumentFlows.values().stream().noneMatch(f -> f.kind == Kind.ARGUMENTS)) continue;
                // A resolved application call, not a log/JSON builder with two protocol fields.
                var edge = graph.resolve(call);
                if (edge.targets().isEmpty()) continue;
                detected = true;
                observe("AI-FC-001", method, call, "模型工具名称与参数字段进入本地方法调用；来源候选、接口选择和运行时分派仍需核实。");
                unknown("AI-FC-001", method, call, "局部分派结构不证明完整允许列表、所有调用入口、插件注册或运行时授权。");
                observe("AI-FC-002", method, call, "已关联工具参数字段与分派实参；提取 JSON 字段本身不构成参数验证。");
                unknown("AI-FC-002", method, call, "未证明所有执行路径都完成参数 schema、范围及业务约束验证并处理拒绝结果。");
                if (argumentFlows.size() < call.getArguments().size())
                    observe("AI-FC-003", method, call, "分派调用另有独立实参，未在支持的局部来源范围内归为模型名称或参数；不推断其身份语义或可信度。");
                unknown("AI-FC-003", method, call, "服务端认证主体、租户来源、工具授权和资源归属不能由实参分离结构证明。");
                for (var id : edge.targets()) graph.method(id).ifPresent(target -> {
                    Map<String, Flow> bindings = new HashMap<>();
                    argumentFlows.forEach((i, f) -> {
                        if (i < target.declaration().getParameters().size()) bindings.put(target.declaration().getParameter(i).getNameAsString(),
                            new Flow(f.kind, f.evidence, f.candidate || edge.resolution() != LocalCallGraph.Resolution.RESOLVED));
                    });
                    inspectTarget(target, bindings, 0, new HashSet<>());
                });
            }
            for (ObjectCreationExpr creation : method.declaration().findAll(ObjectCreationExpr.class)) {
                check();
                if (budget <= 0) break methods;
                Expression argument = processArgument(creation);
                if (argument == null) continue;
                Flow flow = flow(argument, 0, new HashSet<>());
                if (flow == null) continue;
                detected = true;
                results.get("AI-FC-001").add(flow.candidate ? Disposition.UNKNOWN : Disposition.VIOLATED, method, creation,
                    "模型工具字段直接进入 ProcessBuilder 的可执行目标或 shell 命令文本。", flow.evidence);
                unknown("AI-FC-002", method, creation, "工具字段的执行前参数验证与拒绝路径仍未证明。");
                unknown("AI-FC-003", method, creation, "工具执行的服务端授权与身份来源仍未证明。");
            }
        }
        if (budget <= 0) for (Bucket bucket : results.values()) bucket.unknown.add(new Evidence("", 1, "Function Calling 分析达到有界预算；其他路径未分析。"));
        var output = new ArrayList<Assessment>();
        for (Bucket bucket : results.values()) output.addAll(bucket.finish(detected || project.metadata().aiDetected(), !project.diagnostics().isEmpty()));
        return List.copyOf(output);
    }

    private void inspectTarget(MethodInfo target, Map<String, Flow> bindings, int depth, Set<LocalCallGraph.MethodId> seen) {
        check();
        if (depth > 3 || budget-- <= 0 || !seen.add(target.id())) return;
        for (SwitchStmt statement : target.declaration().findAll(SwitchStmt.class)) {
            Flow selection = bound(statement.getSelector(), bindings, 0);
            if (selection != null && selection.kind == Kind.NAME && statement.getEntries().stream()
                .allMatch(entry -> entry.getLabels().stream().allMatch(Expression::isStringLiteralExpr))) {
                observe("AI-FC-001", target, statement, "工具名称进入固定字符串 switch 分派；仅证明列举分支结构，不证明工具权限。");
                statement.getEntries().stream().filter(entry -> entry.getLabels().isEmpty()).findFirst().ifPresent(entry -> {
                    if (entry.findAll(MethodCallExpr.class).isEmpty() && entry.findAll(ObjectCreationExpr.class).isEmpty())
                        observe("AI-FC-001", target, entry, "switch 默认分支未包含方法调用或对象构造；该局部默认分支没有直接工具调用。");
                });
            }
        }
        for (MethodCallExpr call : target.declaration().findAll(MethodCallExpr.class)) {
            if (call.findAncestor(MethodDeclaration.class).orElse(null) != target.declaration()) continue;
            check();
            if (call.getNameAsString().equals("get") && call.getArguments().size() == 1 && mapReceiver(call) &&
                Optional.ofNullable(bound(call.getArgument(0), bindings, 0)).map(f -> f.kind == Kind.NAME).orElse(false))
                observe("AI-FC-001", target, call, "工具名称用于 Map 查找；注册来源、未知名称处理及映射值权限仍未证明。");
            if (call.getNameAsString().equals("containsKey") && call.getArguments().size() == 1 && mapReceiver(call) &&
                bound(call.getArgument(0), bindings, 0) != null)
                observe("AI-FC-001", target, call, "发现名称的 Map 成员检查；未证明检查结果支配所有执行路径或与执行注册表同源。");
            if (isJsonParse(call) && call.getArguments().stream().anyMatch(a -> bound(a, bindings, 0) != null))
                observe("AI-FC-002", target, call, "工具字段经过显式 Jackson JSON 解码；解码成功不等于 schema 或业务验证。");
            if (isValidation(call) && call.getArguments().stream().anyMatch(a -> bound(a, bindings, 0) != null))
                observe("AI-FC-002", target, call, "参数传入已知 Validator/JsonSchema 的 validate 调用；未证明结果已阻断执行或约束足够严格。");
            int dangerous = dangerousArgument(call);
            if (dangerous >= 0 && dangerous < call.getArguments().size()) {
                Flow flow = bound(call.getArgument(dangerous), bindings, 0);
                if (flow != null) {
                    if (flow.candidate) unknown("AI-FC-001", target, call, "工具字段候选进入命令文本或反射目标选择；来源或分派不唯一，未升级为违规。");
                    else results.get("AI-FC-001").add(Disposition.VIOLATED, target, call,
                        "模型工具字段直接决定命令文本或反射目标选择；该路径把不可信模型数据提升为执行选择。", flow.evidence);
                }
            }
            var edge = graph.resolve(call);
            if (edge.targets().isEmpty()) continue;
            for (var id : edge.targets()) graph.method(id).ifPresent(next -> {
                Map<String, Flow> nextBindings = new HashMap<>();
                for (int i = 0; i < Math.min(call.getArguments().size(), next.declaration().getParameters().size()); i++) {
                    Flow flow = bound(call.getArgument(i), bindings, 0);
                    if (flow != null) nextBindings.put(next.declaration().getParameter(i).getNameAsString(),
                        new Flow(flow.kind, flow.evidence, flow.candidate || edge.resolution() != LocalCallGraph.Resolution.RESOLVED));
                }
                if (!nextBindings.isEmpty()) inspectTarget(next, nextBindings, depth + 1, new HashSet<>(seen));
            });
        }
        for (ObjectCreationExpr creation : target.declaration().findAll(ObjectCreationExpr.class)) {
            Expression argument = processArgument(creation);
            if (argument == null) continue;
            Flow flow = bound(argument, bindings, 0);
            if (flow != null) results.get("AI-FC-001").add(flow.candidate ? Disposition.UNKNOWN : Disposition.VIOLATED,
                target, creation, "工具字段进入 ProcessBuilder 的可执行目标或 shell 命令文本；独立普通数据参数不作命令文本处理。", flow.evidence);
        }
    }

    private Flow flow(Expression expression, int depth, Set<Node> seen) {
        check();
        if (depth > 12 || budget-- <= 0 || !seen.add(expression)) return null;
        if (expression instanceof EnclosedExpr e) return flow(e.getInner(), depth + 1, seen);
        if (expression instanceof CastExpr e) return flow(e.getExpression(), depth + 1, seen);
        if (expression instanceof NameExpr name) {
            Node declaration = AstSupport.declaration(name).orElse(null);
            if (!unchanged(declaration, name)) return null;
            if (declaration instanceof VariableDeclarator variable && variable.getInitializer().isPresent())
                return flow(variable.getInitializer().get(), depth + 1, seen);
            return null;
        }
        if (!(expression instanceof MethodCallExpr call)) return null;
        String key = jsonKey(call);
        if (key != null && call.getScope().isPresent()) {
            Kind kind = Set.of("name", "tool").contains(key) ? Kind.NAME : Set.of("arguments", "args").contains(key) ? Kind.ARGUMENTS : null;
            if (kind != null && protocolPair(call, key)) {
                var origin = modelOrigin(call.getScope().get(), depth + 1, new HashSet<>());
                if (origin.isPresent()) return new Flow(kind, origin.get().evidence(), origin.get().candidateDispatch());
                // Protocol-shaped data alone is not proof of a model source.
                var owner = graph.enclosing(call);
                if (owner.isPresent() && gateways.participatingMethods().contains(owner.get().id()))
                    return new Flow(kind, List.of(evidence(owner.get(), call, "工具调用协议字段出现在模型相关方法中，精确数据来源仍未解析。")), true);
            }
        }
        if (Set.of("asText", "textValue", "asInt", "asLong", "toString").contains(call.getNameAsString()) && call.getArguments().isEmpty() && call.getScope().isPresent())
            return flow(call.getScope().get(), depth + 1, seen);
        if (isJsonParse(call) && !call.getArguments().isEmpty()) return flow(call.getArgument(0), depth + 1, seen);
        if (call.getArguments().isEmpty() && call.getScope().isPresent())
            return recordAccessor(call.getScope().get(), call.getNameAsString(), depth + 1, seen);
        return null;
    }

    private Flow recordAccessor(Expression value, String accessor, int depth, Set<Node> seen) {
        if (depth > 12 || !seen.add(value)) return null;
        if (value instanceof NameExpr name) {
            Node declaration = AstSupport.declaration(name).orElse(null);
            if (declaration instanceof VariableDeclarator variable && unchanged(declaration, name) && variable.getInitializer().isPresent())
                return recordAccessor(variable.getInitializer().get(), accessor, depth + 1, seen);
        }
        if (!(value instanceof MethodCallExpr factory)) return null;
        var edge = graph.resolve(factory);
        if (edge.targets().size() != 1) return null;
        var method = graph.method(edge.targets().getFirst()).orElse(null);
        if (method == null) return null;
        Flow result = null;
        for (ReturnStmt statement : method.declaration().findAll(ReturnStmt.class)) {
            if (statement.getExpression().orElse(null) instanceof ObjectCreationExpr creation) {
                String wanted = graph.qualifiedType(creation, creation.getTypeAsString());
                RecordDeclaration record = method.source().unit().findAll(RecordDeclaration.class).stream()
                    .filter(r -> graph.qualifiedType(r, r.getNameAsString()).equals(wanted)).findFirst().orElse(null);
                if (record == null) continue;
                for (int i = 0; i < Math.min(record.getParameters().size(), creation.getArguments().size()); i++)
                    if (record.getParameter(i).getNameAsString().equals(accessor)) {
                        Flow found = flow(creation.getArgument(i), depth + 1, new HashSet<>(seen));
                        if (found != null) {
                            if (result != null && result.kind != found.kind) return null;
                            result = new Flow(found.kind, found.evidence, found.candidate || edge.resolution() != LocalCallGraph.Resolution.RESOLVED);
                        }
                    }
            }
        }
        return result;
    }

    private Optional<GatewayModel.Origin> modelOrigin(Expression expression, int depth, Set<Node> seen) {
        if (depth > 12 || budget-- <= 0 || !seen.add(expression)) return Optional.empty();
        var known = gateways.origin(expression);
        if (known.isPresent()) return known;
        if (expression instanceof NameExpr name) {
            Node declaration = AstSupport.declaration(name).orElse(null);
            if (!unchanged(declaration, name)) return Optional.empty();
            if (declaration instanceof VariableDeclarator variable && variable.getInitializer().isPresent())
                return modelOrigin(variable.getInitializer().get(), depth + 1, seen);
            if (declaration instanceof Parameter parameter && parameter.getParentNode().orElse(null) instanceof MethodDeclaration method) {
                var owner = graph.enclosing(name).orElse(null);
                if (owner == null) return Optional.empty();
                int index = method.getParameters().indexOf(parameter);
                for (var edge : incoming.getOrDefault(owner.id(), List.of())) if (index >= 0 && index < edge.callsite().getArguments().size()) {
                    var upstream = modelOrigin(edge.callsite().getArgument(index), depth + 1, new HashSet<>(seen));
                    if (upstream.isPresent()) return Optional.of(new GatewayModel.Origin(upstream.get().evidence(),
                        upstream.get().candidateDispatch() || edge.resolution() != LocalCallGraph.Resolution.RESOLVED || incoming.getOrDefault(owner.id(), List.of()).size() > 1));
                }
            }
        }
        if (expression instanceof MethodCallExpr call) {
            if ((jsonKey(call) != null || Set.of("asText", "textValue").contains(call.getNameAsString())) && call.getScope().isPresent())
                return modelOrigin(call.getScope().get(), depth + 1, seen);
            if (isJsonParse(call) && !call.getArguments().isEmpty()) return modelOrigin(call.getArgument(0), depth + 1, seen);
        }
        return Optional.empty();
    }

    private Flow bound(Expression expression, Map<String, Flow> bindings, int depth) {
        check();
        if (depth > 12 || budget-- <= 0) return null;
        if (expression instanceof NameExpr name) {
            Node declaration = AstSupport.declaration(name).orElse(null);
            if (!unchanged(declaration, name)) return null;
            if (declaration instanceof Parameter) return bindings.get(name.getNameAsString());
            if (declaration instanceof VariableDeclarator variable && variable.getInitializer().isPresent())
                return bound(variable.getInitializer().get(), bindings, depth + 1);
        }
        if (expression instanceof EnclosedExpr e) return bound(e.getInner(), bindings, depth + 1);
        if (expression instanceof CastExpr e) return bound(e.getExpression(), bindings, depth + 1);
        if (expression instanceof BinaryExpr e) {
            Flow left = bound(e.getLeft(), bindings, depth + 1);
            return left != null ? left : bound(e.getRight(), bindings, depth + 1);
        }
        if (expression instanceof MethodCallExpr call && call.getScope().isPresent() &&
            (jsonKey(call) != null || Set.of("asText", "textValue", "asInt", "asLong").contains(call.getNameAsString())))
            return bound(call.getScope().get(), bindings, depth + 1);
        if (expression instanceof MethodCallExpr call && isJsonParse(call) && !call.getArguments().isEmpty())
            return bound(call.getArgument(0), bindings, depth + 1);
        return null;
    }

    private boolean protocolPair(MethodCallExpr call, String key) {
        var method = call.findAncestor(MethodDeclaration.class);
        if (method.isEmpty()) return false;
        String pair = switch (key) { case "tool" -> "args"; case "args" -> "tool"; case "name" -> "arguments"; default -> "name"; };
        String scope = call.getScope().map(s -> scopeKey(s, 0)).orElse(null);
        if (scope == null) return false;
        Map<String, Set<String>> keys = protocolKeys.computeIfAbsent(method.get(), owner -> {
            Map<String, Set<String>> found = new HashMap<>();
            for (var other : owner.findAll(MethodCallExpr.class)) {
                check();
                String field = jsonKey(other);
                String container = other.getScope().map(s -> scopeKey(s, 0)).orElse(null);
                if (field != null && container != null) found.computeIfAbsent(container, ignored -> new HashSet<>()).add(field);
            }
            return found;
        });
        return keys.getOrDefault(scope, Set.of()).contains(pair);
    }
    private static String scopeKey(Expression expression, int depth) {
        if (depth > 4) return null;
        if (expression instanceof NameExpr name) return "name:" + name.getNameAsString();
        if (expression instanceof FieldAccessExpr field && field.getScope() instanceof ThisExpr) return "this:" + field.getNameAsString();
        if (expression instanceof MethodCallExpr call && call.getScope().isPresent() && call.getArguments().size() == 1 &&
            Set.of("path", "get").contains(call.getNameAsString()) && call.getArgument(0).isLiteralExpr()) {
            String parent = scopeKey(call.getScope().get(), depth + 1);
            return parent == null ? null : parent + "/" + call.getNameAsString() + ":" + call.getArgument(0);
        }
        return null;
    }
    private static String jsonKey(MethodCallExpr call) {
        if (!Set.of("get", "path").contains(call.getNameAsString()) || call.getArguments().size() != 1 || !call.getArgument(0).isStringLiteralExpr()) return null;
        return call.getArgument(0).asStringLiteralExpr().asString();
    }
    private boolean mapReceiver(MethodCallExpr call) {
        if (call.getScope().isEmpty()) return false;
        String type = graph.expressionType(call.getScope().get());
        return type.equals("java.util.Map") || type.startsWith("java.util.Map<") ||
            AstSupport.type(call, AstSupport.declaredType(call.getScope().get()), "java.util.Map");
    }
    private boolean isJsonParse(MethodCallExpr call) {
        return Set.of("readTree", "readValue").contains(call.getNameAsString()) && call.getScope().isPresent() &&
            (graph.expressionType(call.getScope().get()).equals("com.fasterxml.jackson.databind.ObjectMapper") ||
                AstSupport.type(call, AstSupport.declaredType(call.getScope().get()), "com.fasterxml.jackson.databind.ObjectMapper"));
    }
    private boolean isValidation(MethodCallExpr call) {
        if (!call.getNameAsString().equals("validate") || call.getScope().isEmpty()) return false;
        String type = graph.expressionType(call.getScope().get());
        return Set.of("jakarta.validation.Validator", "javax.validation.Validator", "com.networknt.schema.JsonSchema").contains(type);
    }
    private int dangerousArgument(MethodCallExpr call) {
        if (call.getScope().isEmpty() || call.getArguments().isEmpty()) return -1;
        Expression scope = call.getScope().get();
        String type = graph.expressionType(scope);
        if (call.getNameAsString().equals("exec") && (type.equals("java.lang.Runtime") || scope instanceof MethodCallExpr runtime &&
            runtime.getNameAsString().equals("getRuntime") && runtime.getScope().map(s -> typeReference(s, "java.lang.Runtime")).orElse(false))) return 0;
        if (Set.of("getMethod", "getDeclaredMethod").contains(call.getNameAsString()) && (type.equals("java.lang.Class") || scope.isClassExpr())) return 0;
        if (call.getNameAsString().equals("forName") && typeReference(scope, "java.lang.Class")) return 0;
        return -1;
    }
    private boolean typeReference(Expression expression, String qualified) {
        if (expression instanceof NameExpr name && AstSupport.declaration(name).isPresent()) return false;
        return graph.qualifiedType(expression, expression.toString()).equals(qualified);
    }
    private Expression processArgument(ObjectCreationExpr creation) {
        if (!graph.qualifiedType(creation, creation.getTypeAsString()).equals("java.lang.ProcessBuilder") || creation.getArguments().isEmpty()) return null;
        if (creation.getArguments().size() >= 3 && creation.getArgument(0).isStringLiteralExpr() && creation.getArgument(1).isStringLiteralExpr()) {
            String executable = creation.getArgument(0).asStringLiteralExpr().asString().replace('\\', '/');
            executable = executable.substring(executable.lastIndexOf('/') + 1).toLowerCase(Locale.ROOT);
            String flag = creation.getArgument(1).asStringLiteralExpr().asString();
            boolean shellCommand = Set.of("sh", "bash", "zsh", "dash", "ksh").contains(executable) && Set.of("-c", "-lc").contains(flag)
                || Set.of("cmd", "cmd.exe").contains(executable) && flag.equalsIgnoreCase("/c")
                || Set.of("powershell", "powershell.exe", "pwsh", "pwsh.exe").contains(executable) && flag.equalsIgnoreCase("-Command");
            if (shellCommand) return creation.getArgument(2);
        }
        return creation.getArgument(0);
    }
    private boolean unchanged(Node declaration, NameExpr use) {
        if (declaration == null) return false;
        Node owner = declaration instanceof Parameter ? declaration.getParentNode().orElse(declaration) : declaration.findAncestor(BlockStmt.class).orElse(null);
        if (owner == null || declaration instanceof VariableDeclarator v && v.getParentNode().orElse(null) instanceof FieldDeclaration) return false;
        return writes.computeIfAbsent(owner, node -> node.findAll(AssignExpr.class)).stream().noneMatch(a -> a.getTarget().isNameExpr() &&
            a.getTarget().asNameExpr().getNameAsString().equals(use.getNameAsString()) && AstSupport.before(declaration, a) && AstSupport.before(a, use));
    }
    private void check() { if (cancelled.getAsBoolean() || Thread.currentThread().isInterrupted()) throw new CancellationException(); }
    private void observe(String id, MethodInfo method, Node node, String detail) { results.get(id).add(Disposition.OBSERVED, method, node, detail, List.of()); }
    private void unknown(String id, MethodInfo method, Node node, String detail) { results.get(id).add(Disposition.UNKNOWN, method, node, detail, List.of()); }
    private static Evidence evidence(MethodInfo method, Node node, String detail) { return new Evidence(method.source().path(), AstSupport.line(node), detail); }

    private static final class Bucket {
        final Rule rule;
        final List<Evidence> observed = new ArrayList<>(), unknown = new ArrayList<>(), violated = new ArrayList<>();
        Bucket(Rule rule) { this.rule = rule; }
        void add(Disposition disposition, MethodInfo method, Node node, String detail, List<Evidence> provenance) {
            List<Evidence> list = switch (disposition) { case VIOLATED -> violated; case OBSERVED -> observed; default -> unknown; };
            Evidence e = evidence(method, node, detail);
            if (list.size() < 40 && !list.contains(e)) list.add(e);
            for (Evidence source : provenance) if (list.size() < 40 && !list.contains(source)) list.add(source);
        }
        List<Assessment> finish(boolean applicable, boolean incomplete) {
            var output = new ArrayList<Assessment>();
            if (!violated.isEmpty()) output.add(result(Disposition.VIOLATED, violated));
            if (!unknown.isEmpty()) output.add(result(Disposition.UNKNOWN, unknown));
            if (!observed.isEmpty()) output.add(result(Disposition.OBSERVED, observed));
            if (output.isEmpty()) output.add(result(applicable || incomplete ? Disposition.UNKNOWN : Disposition.NOT_APPLICABLE, List.of()));
            return output;
        }
        Assessment result(Disposition disposition, List<Evidence> evidence) {
            return new Assessment(rule.id(), rule.domain(), disposition, disposition == Disposition.VIOLATED ? Severity.HIGH : Severity.INFO,
                rule.title(), switch (disposition) {
                    case VIOLATED -> "模型工具字段直接进入受支持的执行选择边界；仅报告所列有界路径。";
                    case OBSERVED -> "观察到 Function Calling 局部结构；不代表控制有效或应用安全通过。";
                    case UNKNOWN -> "Function Calling 来源、分派、验证或授权仍有无法证明的路径。";
                    case NOT_APPLICABLE -> "已解析源码未识别支持的模型 Function Calling 路径。";
                }, rule.recommendation(), evidence, List.of(
                    "仅关联 name/arguments、tool/args JSON 字段、不可变局部别名、局部 record 返回和最多三层分派参数传递。",
                    "接口候选及来源不唯一不升级为违规；反射、动态注册、AOP、外部授权与完整控制流未证明。",
                    "JSON 解码、schema 声明、验证方法调用和独立上下文实参均不证明业务授权或拒绝策略生效。",
                    "每种状态最多保留 40 个位置；分析有预算，未执行目标或工具。"));
        }
    }
}
