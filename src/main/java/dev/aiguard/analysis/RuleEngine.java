package dev.aiguard.analysis;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.*;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.stmt.*;
import dev.aiguard.analysis.SourceProject.JavaSource;
import dev.aiguard.analysis.rules.AstSupport;
import dev.aiguard.analysis.rules.ConfigurationRules;
import dev.aiguard.model.ScanModel.*;
import java.util.*;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;
import static dev.aiguard.analysis.rules.AstSupport.*;

/** Versioned, offline syntax evidence. OBSERVED never means that a control is effective. */
public final class RuleEngine {
    private static final String ADVISORS = "https://docs.spring.io/spring-ai/reference/api/advisors.html";
    private static final String TOOLS = "https://docs.spring.io/spring-ai/reference/api/tools.html";
    private static final String RAG = "https://docs.spring.io/spring-ai/reference/api/retrieval-augmented-generation.html";
    private static final String SAFEGUARD = "org.springframework.ai.chat.client.advisor.SafeGuardAdvisor";
    private static final List<Rule> RULES = List.of(
        rule("AI-L1-001", Domain.L1, "不可信输入进入 system 指令", "跟踪 Web 方法参数、未被修改的局部别名与字符串拼接进入 ChatClient.system。", "把请求数据放入用户消息，固定系统指令；另外评估间接注入和工具信任边界。", ADVISORS),
        rule("AI-L1-002", Domain.L1, "围栏绑定与异常放行", "识别 SafeGuardAdvisor 请求级绑定。仅对方法内显式原始 builder 构造且无重赋值的客户端，确认 catch 遗漏围栏；默认 Advisor 不明时为 UNKNOWN。", "核实实际 ChatClient 的同步/流式绑定、默认 Advisor、拒绝处理及所有备用路径。", ADVISORS),
        rule("AI-L2-001", Domain.L2, "工具入参与敏感操作", "识别 Spring AI @Tool 参数直接进入 Runtime.exec、ProcessBuilder 或 JdbcTemplate 的 SQL 文本；其他工具仅审查声明证据。", "对工具参数独立鉴权并校验业务约束；使用服务端身份、固定操作与参数化 SQL。", TOOLS),
        rule("AI-L2-002", Domain.L2, "会话记忆隔离", "识别 Web 方法中 ChatMemory.CONVERSATION_ID 使用常量且同请求表达式绑定记忆 Advisor；动态 ID 的归属授权不在证明范围。", "从已认证上下文建立会话归属并在读取/写入时校验，避免共享固定会话 ID。", ADVISORS),
        rule("AI-L3-001", Domain.L3, "原始 AI 数据日志", "跟踪同一方法进入 AI 的 Web 参数及模型返回值进入明确 SLF4J Logger 的日志参数。", "日志中仅保留必要元数据；对请求、模型响应和工具结果执行敏感信息处理及访问控制。", ADVISORS),
        rule("AI-L4-001", Domain.L4, "无界模型重试", "识别 ChatClient.stream 调用链上的 Reactor retry()，并观察字面量有限 retry(n)。", "设置有限重试、超时、并发、Token 预算与用户/租户配额；外部网关配置另行核实。", ADVISORS),
        rule("AI-L5-001", Domain.L5, "流式发送与审核顺序", "在同一直接语句块中识别 SseEmitter.send 模型片段与明确 ModerationModel.call 的先后顺序。", "先完成审核再发送相应内容；审核失败时阻断输出，单独验证同步与流式路径。", ADVISORS),
        rule("AI-L6-001", Domain.L6, "请求审计关联", "观察 AI Web 方法内 MDC requestId/traceId/correlationId 的常量或动态设置；不推断日志落地与全链路传播。", "使用请求级唯一关联标识，记录安全决策及策略版本，验证异步传播、日志保护和保留策略。", ADVISORS),
        rule("AI-L7-001", Domain.L7, "模型输出进入执行边界", "跟踪模型输出和未修改局部别名进入 Runtime.exec、ProcessBuilder 与 JdbcTemplate 的 SQL 文本。", "把模型输出视为不可信数据；使用允许列表、结构和业务校验、参数化查询及执行前授权。", TOOLS),
        rule("AI-L2-003", Domain.L2, "请求级 RAG 过滤条件", "识别 Web 入参直接设置 QuestionAnswerAdvisor.FILTER_EXPRESSION 且同请求表达式绑定该 Advisor；过滤构造器或外部 ACL 未解析。", "由服务端构造不可被请求覆盖的租户约束，组合允许的用户筛选条件并验证检索授权。", RAG)
    );
    private static Rule rule(String id, Domain domain, String title, String description, String recommendation, String ref) {
        return new Rule(id, domain, title, description, recommendation, List.of(ref));
    }
    public List<Rule> catalog() {
        List<Rule> catalog = new ArrayList<>(RULES);
        catalog.add(ConfigurationRules.RULE);
        return List.copyOf(catalog);
    }

    public List<Assessment> assess(SourceProject project, BooleanSupplier cancelled) {
        Map<String, Result> results = new LinkedHashMap<>();
        for (Rule rule : RULES) results.put(rule.id(), new Result(rule));
        boolean streamSeen = false;
        for (JavaSource source : project.sources()) {
            check(cancelled);
            var calls = calls(source);
            for (MethodCallExpr call : calls) {
                check(cancelled);
                String name = call.getNameAsString();
                if (chat(call)) {
                    system(source, call, results.get("AI-L1-001"));
                    if (name.equals("stream")) streamSeen = true;
                    retry(source, call, results.get("AI-L4-001"));
                    if (name.equals("advisors")) {
                        var r = results.get("AI-L1-002");
                        if (containsSafeGuard(call)) r.observe(source, call, "已发现请求级 SafeGuardAdvisor 绑定；仅证明绑定构造存在。");
                        else r.unknown(source, call, "已发现 Advisor 配置；自定义或间接 Advisor 的安全语义未确认。");
                    }
                }
                memory(source, call, results.get("AI-L2-002"));
                rag(source, call, results.get("AI-L2-003"));
                logging(source, call, results.get("AI-L3-001"));
                audit(source, call, results.get("AI-L6-001"));
                if (sink(call) && !call.getArguments().isEmpty()) {
                    checkSink(source, call, call.getArgument(0), results);
                }
            }
            for (ObjectCreationExpr creation : source.unit().findAll(ObjectCreationExpr.class)) {
                if (processBuilder(creation) && !creation.getArguments().isEmpty()) {
                    checkSink(source, creation, creation.getArgument(0), results);
                    // Separate data arguments do not become shell command text.
                    if (creation.getArguments().size() >= 3 && creation.getArgument(1).isStringLiteralExpr() &&
                        Set.of("-c", "/c", "-Command").contains(creation.getArgument(1).asStringLiteralExpr().asString()))
                        checkSink(source, creation, creation.getArgument(2), results);
                }
                if (type(creation, creation.getTypeAsString(), SAFEGUARD) && !isBound(creation))
                    results.get("AI-L1-002").unknown(source, creation, "存在 SafeGuardAdvisor 构造，但未在支持的同表达式范围内确认绑定。");
            }
            for (ClassOrInterfaceDeclaration cls : source.unit().findAll(ClassOrInterfaceDeclaration.class)) {
                if (cls.getImplementedTypes().stream().anyMatch(t -> type(cls, t.asString(), "org.springframework.ai.chat.client.advisor.api.CallAdvisor") ||
                    type(cls, t.asString(), "org.springframework.ai.chat.client.advisor.api.StreamAdvisor")))
                    results.get("AI-L1-002").unknown(source, cls, "存在自定义 Advisor 实现；其业务作用、绑定与同步/流式覆盖需要核实。");
            }
            for (MethodDeclaration method : source.unit().findAll(MethodDeclaration.class)) {
                check(cancelled);
                if (tool(method)) {
                    var r = results.get("AI-L2-001");
                    if (annotation(method, "org.springframework.security.access.prepost.PreAuthorize"))
                        r.observe(source, method, "工具方法声明了 PreAuthorize；未证明方法安全已启用或表达式足够严格。");
                    else r.unknown(source, method, "工具方法已识别；无法从方法局部证明服务端授权，外部授权仍可能存在。");
                }
            }
            guardBypass(source, results.get("AI-L1-002"));
            streamOrder(source, results.get("AI-L5-001"));
        }
        List<Assessment> output = new ArrayList<>();
        for (Result r : results.values()) {
            check(cancelled);
            boolean applicable = project.metadata().aiDetected();
            if (r.rule.id().equals("AI-L5-001") && !streamSeen && r.evidenceCount() == 0) applicable = false;
            output.addAll(r.finish(project, applicable));
        }
        output.addAll(ConfigurationRules.assess(project, cancelled));
        return List.copyOf(output);
    }

    private static void system(JavaSource source, MethodCallExpr call, Result r) {
        if (!call.getNameAsString().equals("system") || call.getArguments().isEmpty()) return;
        Expression input = call.getArgument(0);
        if (origin(input, Origin.WEB_INPUT)) r.violate(source, call, "Web 请求参数经直接表达式或不可变局部别名进入 system 指令。");
        else if (constant(input)) r.observe(source, call, "该 system 参数是字面量常量；其他上下文输入未获安全证明。");
        else r.unknown(source, call, "system 参数经过未解析构造或非 Web 来源，无法证明信任来源。");
    }
    private static void retry(JavaSource source, MethodCallExpr call, Result r) {
        if (!call.getNameAsString().equals("retry") || !aiStream(call)) return;
        if (call.getArguments().isEmpty()) r.violate(source, call, "AI 流式调用链使用无参数 retry，会持续重新订阅错误来源且没有次数上限。");
        else if (call.getArguments().size() == 1 && call.getArgument(0).isIntegerLiteralExpr() ||
                 call.getArguments().size() == 1 && call.getArgument(0).isLongLiteralExpr())
            r.observe(source, call, "发现字面量 retry 次数配置；未证明超时、租户配额或总体预算。");
        else r.unknown(source, call, "重试次数来自未解析表达式，无法确认上限。");
    }
    private static boolean advisorParameter(MethodCallExpr call) {
        if (!call.getNameAsString().equals("param") || call.getArguments().size() < 2) return false;
        var lambda = call.findAncestor(LambdaExpr.class);
        if (lambda.isEmpty()) return false;
        Expression receiver = call;
        while (receiver instanceof MethodCallExpr c && c.getScope().isPresent()) receiver = c.getScope().get();
        if (!(receiver instanceof NameExpr name) || lambda.get().getParameters().stream().noneMatch(p -> declaration(name).map(p::equals).orElse(false))) return false;
        return lambda.flatMap(l -> l.getParentNode()).filter(n -> n instanceof MethodCallExpr)
            .map(n -> (MethodCallExpr) n).filter(c -> c.getNameAsString().equals("advisors") && chat(c)).isPresent();
    }
    private static void memory(JavaSource source, MethodCallExpr call, Result r) {
        if (!advisorParameter(call) || !key(call.getArgument(0), "org.springframework.ai.chat.memory.ChatMemory", "CONVERSATION_ID")) return;
        if (!boundAdvisor(call, Set.of("org.springframework.ai.chat.client.advisor.MessageChatMemoryAdvisor",
            "org.springframework.ai.chat.client.advisor.VectorStoreChatMemoryAdvisor"))) {
            r.unknown(source, call, "已配置记忆会话参数，但同一请求表达式未确认记忆 Advisor 的实际绑定。");
        } else if (stringConstant(call.getArgument(1)) && method(call).map(AstSupport::web).orElse(false))
            r.violate(source, call, "Web 请求方法显式给记忆 Advisor 使用固定会话标识，多个请求将选择相同会话键。");
        else if (stringConstant(call.getArgument(1))) r.unknown(source, call, "固定会话标识已发现；当前入口是否单用户或测试用途未确认。");
        else r.unknown(source, call, "会话标识为动态表达式；本规则无法证明用户/租户归属校验。");
    }
    private static void rag(JavaSource source, MethodCallExpr call, Result r) {
        if (!advisorParameter(call) || !key(call.getArgument(0), "org.springframework.ai.chat.client.advisor.QuestionAnswerAdvisor", "FILTER_EXPRESSION")) return;
        if (!boundAdvisor(call, Set.of("org.springframework.ai.chat.client.advisor.QuestionAnswerAdvisor"))) {
            r.unknown(source, call, "已配置 RAG 过滤参数，但同一请求表达式未确认 QuestionAnswerAdvisor 的实际绑定。");
        } else if (origin(call.getArgument(1), Origin.WEB_INPUT))
            r.violate(source, call, "Web 参数直接成为 QuestionAnswerAdvisor 请求级过滤表达式，调用方可控制检索过滤条件。");
        else if (constant(call.getArgument(1))) r.observe(source, call, "请求级 RAG 过滤表达式为常量；租户范围是否正确仍未确认。");
        else r.unknown(source, call, "RAG 过滤表达式经自定义构造；服务端约束与覆盖语义未获证明。");
    }
    private static void logging(JavaSource source, MethodCallExpr call, Result r) {
        if (!logger(call)) return;
        boolean raw = call.getArguments().stream().anyMatch(a -> origin(a, Origin.MODEL_OUTPUT));
        var method = method(call);
        if (!raw && method.isPresent()) {
            Set<Node> inputs = new HashSet<>();
            for (MethodCallExpr c : method.get().findAll(MethodCallExpr.class))
                if (chat(c) && Set.of("user", "system").contains(c.getNameAsString()))
                    for (Expression a : c.getArguments()) if (origin(a, Origin.WEB_INPUT))
                        for (NameExpr n : a.findAll(NameExpr.class)) declaration(n).ifPresent(inputs::add);
            raw = call.getArguments().stream().anyMatch(a -> origin(a, Origin.WEB_INPUT) && a.findAll(NameExpr.class).stream().anyMatch(n -> declaration(n).map(inputs::contains).orElse(false)));
        }
        if (raw) r.violate(source, call, "已跟踪到原始 AI 输入或输出直接进入 SLF4J 日志参数；具体是否含敏感数据尚未证明。");
        else if (method.map(m -> m.findAll(MethodCallExpr.class).stream().anyMatch(AstSupport::chat)).orElse(false))
            r.unknown(source, call, "AI 方法存在日志调用；自定义脱敏、日志插件与数据语义未解析。");
    }
    private static void audit(JavaSource source, MethodCallExpr call, Result r) {
        if (!call.getNameAsString().equals("put") || !staticScope(call, "org.slf4j.MDC") || call.getArguments().size() != 2 || !call.getArgument(0).isStringLiteralExpr()) return;
        if (!Set.of("requestId", "traceId", "correlationId").contains(call.getArgument(0).asStringLiteralExpr().asString())) return;
        var method = method(call);
        if (method.isEmpty() || method.get().findAll(MethodCallExpr.class).stream().noneMatch(AstSupport::chat)) return;
        if (stringConstant(call.getArgument(1)) && web(method.get())) r.violate(source, call, "AI Web 方法把请求关联字段设为固定值，不能单独区分请求。");
        else if (!constant(call.getArgument(1))) r.observe(source, call, "发现动态 MDC 关联字段设置；未证明唯一性、异步传播、清理或日志持久化。");
        else r.unknown(source, call, "常量 MDC 标识已发现；入口是否多请求以及其他关联机制未确认。");
    }
    private static void checkSink(JavaSource source, Node sink, Expression argument, Map<String, Result> results) {
        if (origin(argument, Origin.MODEL_OUTPUT)) results.get("AI-L7-001").violate(source, sink, "模型原始输出经直接表达式或不可变局部别名进入命令/SQL 执行文本。");
        else if (!constant(argument) && method(sink).map(m -> m.findAll(MethodCallExpr.class).stream().anyMatch(AstSupport::chat)).orElse(false))
            results.get("AI-L7-001").unknown(source, sink, "AI 方法包含动态执行文本；中间转换和跨方法来源未解析。");
        if (origin(argument, Origin.TOOL_INPUT)) results.get("AI-L2-001").violate(source, sink, "Tool 参数直接进入命令/SQL 执行文本；本结论涉及输入执行边界，不推断外围授权不存在。");
    }
    private static boolean containsSafeGuard(Node node) {
        return node.findAll(ObjectCreationExpr.class).stream().anyMatch(c -> type(c, c.getTypeAsString(), SAFEGUARD));
    }
    private static boolean boundAdvisor(MethodCallExpr parameter, Set<String> qualifiedTypes) {
        var request = parameter.findAncestor(LambdaExpr.class).flatMap(Node::getParentNode);
        if (request.orElse(null) instanceof MethodCallExpr requestCall) {
            MethodCallExpr expression = requestCall;
            while (expression.getParentNode().orElse(null) instanceof MethodCallExpr outer && outer.getScope().orElse(null) == expression) expression = outer;
            // Only explicit request-level advisors in this fluent chain are proven bound.
            for (MethodCallExpr binding : chainCalls(expression)) {
                if (!binding.getNameAsString().equals("advisors")) continue;
                for (Expression arg : binding.getArguments()) {
                    if (arg instanceof ObjectCreationExpr creation && qualifiedTypes.stream().anyMatch(q -> type(creation, creation.getTypeAsString(), q))) return true;
                    if (arg instanceof MethodCallExpr build && build.getNameAsString().equals("build") &&
                        chainCalls(build).stream().anyMatch(c -> c.getNameAsString().equals("builder") && qualifiedTypes.stream().anyMatch(q -> staticScope(c, q)))) return true;
                }
            }
        }
        return false;
    }
    private static boolean isBound(Node node) {
        Node current = node;
        while (current.getParentNode().isPresent() && !(current instanceof Statement)) {
            current = current.getParentNode().get();
            if (current instanceof MethodCallExpr call && Set.of("advisors", "defaultAdvisors").contains(call.getNameAsString()) && chat(call)) return true;
        }
        return false;
    }
    private static String rootName(Expression expr) {
        if (expr instanceof MethodCallExpr c) return c.getScope().map(RuleEngine::rootName).orElse("");
        if (expr instanceof NameExpr n) return n.getNameAsString();
        if (expr instanceof FieldAccessExpr f && f.getScope().isThisExpr()) return f.getNameAsString();
        return "";
    }
    private static void guardBypass(JavaSource source, Result r) {
        for (TryStmt block : source.unit().findAll(TryStmt.class)) {
            Set<String> protectedClients = new HashSet<>();
            for (MethodCallExpr c : block.getTryBlock().findAll(MethodCallExpr.class))
                if (chat(c) && c.getNameAsString().equals("advisors") && containsSafeGuard(c)) protectedClients.add(rootName(c));
            if (protectedClients.isEmpty()) continue;
            for (CatchClause catcher : block.getCatchClauses()) for (MethodCallExpr c : catcher.findAll(MethodCallExpr.class))
                if (modelOutput(c) && protectedClients.contains(rootName(c)) && !containsSafeGuard(c) &&
                    c.findAll(MethodCallExpr.class).stream().noneMatch(x -> x.getNameAsString().equals("advisors")))
                    if (rawLocalClient(c)) r.violate(source, c, "catch 分支重试同一局部原始 ChatClient，遗漏 try 中显式添加的 SafeGuardAdvisor；局部构建未配置默认 Advisor。");
                    else r.unknown(source, c, "catch 分支遗漏 try 路径显式添加的 SafeGuardAdvisor；客户端默认 Advisor 或外围阻断无法解析，不能证明围栏失效。");
        }
    }
    private static boolean rawLocalClient(MethodCallExpr call) {
        Expression root = call;
        while (root instanceof MethodCallExpr c && c.getScope().isPresent()) root = c.getScope().get();
        if (!(root instanceof NameExpr name) || !(declaration(name).orElse(null) instanceof VariableDeclarator variable)) return false;
        if (variable.findAncestor(FieldDeclaration.class).isPresent() || variable.getInitializer().isEmpty()) return false;
        Expression initializer = variable.getInitializer().get();
        if (!(initializer instanceof MethodCallExpr build) || !build.getNameAsString().equals("build") ||
            !(build.getScope().orElse(null) instanceof MethodCallExpr builder) || !builder.getNameAsString().equals("builder") ||
            !staticScope(builder, "org.springframework.ai.chat.client.ChatClient")) return false;
        return method(call).map(m -> m.findAll(AssignExpr.class).stream().noneMatch(a ->
            a.getTarget().isNameExpr() && a.getTarget().asNameExpr().getNameAsString().equals(name.getNameAsString()))).orElse(false);
    }
    private static void streamOrder(JavaSource source, Result r) {
        for (BlockStmt block : source.unit().findAll(BlockStmt.class)) {
            List<MethodCallExpr> sends = new ArrayList<>(), checks = new ArrayList<>();
            // Direct expression statements only: no claim about nested branch/control flow.
            for (Statement s : block.getStatements()) if (s instanceof ExpressionStmt e && e.getExpression() instanceof MethodCallExpr c) {
                if (c.getNameAsString().equals("send") && receiverType(c, "org.springframework.web.servlet.mvc.method.annotation.SseEmitter") &&
                    c.getArguments().stream().anyMatch(a -> origin(a, Origin.MODEL_OUTPUT))) sends.add(c);
                if (c.getNameAsString().equals("call") && receiverType(c, "org.springframework.ai.moderation.ModerationModel")) checks.add(c);
            }
            for (var send : sends) {
                Set<Node> sentOrigins = new HashSet<>();
                send.getArguments().forEach(a -> a.findAll(NameExpr.class).stream().filter(n -> origin(n, Origin.MODEL_OUTPUT))
                    .forEach(n -> declaration(n).ifPresent(sentOrigins::add)));
                var samePayloadChecks = checks.stream().filter(c -> c.getArguments().stream().anyMatch(a ->
                    a.findAll(NameExpr.class).stream().anyMatch(n -> origin(n, Origin.MODEL_OUTPUT) &&
                        declaration(n).map(sentOrigins::contains).orElse(false)))).toList();
                if (samePayloadChecks.stream().anyMatch(c -> before(send, c))) r.violate(source, send, "同一直线语句块先发送模型内容，后调用审核模型；该次审核结果无法撤回已发送内容。");
                else if (!samePayloadChecks.isEmpty()) r.observe(source, send, "局部顺序存在发送前审核调用；未证明审核结果被执行、失败阻断或覆盖全部内容。");
                else r.unknown(source, send, "已发送模型内容；当前支持范围无法确认发送前的内容审核。");
            }
        }
    }
    private static boolean stringConstant(Expression e) {
        return e.isStringLiteralExpr() || e.isBinaryExpr() && stringConstant(e.asBinaryExpr().getLeft()) && stringConstant(e.asBinaryExpr().getRight());
    }
    private static void check(BooleanSupplier cancelled) { if (cancelled.getAsBoolean()) throw new CancellationException("scan cancelled"); }
    private static final class Result {
        final Rule rule;
        final List<Evidence> violations = new ArrayList<>(), observations = new ArrayList<>(), unknowns = new ArrayList<>();
        Result(Rule rule) { this.rule = rule; }
        void violate(JavaSource s, Node n, String detail) { add(violations, s, n, detail); }
        void observe(JavaSource s, Node n, String detail) { add(observations, s, n, detail); }
        void unknown(JavaSource s, Node n, String detail) { add(unknowns, s, n, detail); }
        void add(List<Evidence> list, JavaSource s, Node n, String detail) {
            Evidence e = new Evidence(s.path(), line(n), detail);
            if (list.size() < 40 && !list.contains(e)) list.add(e);
        }
        int evidenceCount() { return violations.size() + observations.size() + unknowns.size(); }
        List<Assessment> finish(SourceProject project, boolean applicable) {
            List<String> limitations = new ArrayList<>(List.of(
                "仅分析明确导入/声明类型、局部不可变别名和列明语法；未构建完整控制流或跨方法数据流。",
                "未运行目标程序；不证明动态 Bean/AOP、反射、外部网关、存储 ACL 或生产围栏有效性。",
                "OBSERVED 只表示构造存在；没有违规证据不代表安全通过。每种证据最多记录 40 个位置。"));
            Disposition disposition;
            String explanation;
            List<Evidence> evidence = new ArrayList<>();
            evidence.addAll(violations); evidence.addAll(unknowns); evidence.addAll(observations);
            if (!project.supportedVersion() && (applicable || !evidence.isEmpty())) {
                disposition = Disposition.UNKNOWN;
                explanation = "Spring AI 版本未确认或不在支持范围，相关语法证据保留但不升级为违规结论。";
                limitations.add("版本适配支持显式 Spring AI 1.0.x、1.1.x、2.0.x；未解析的 BOM/版本冲突降级。");
            } else if (!violations.isEmpty()) {
                disposition = Disposition.VIOLATED;
                explanation = "在该规则明确支持的局部语法范围内发现违反证据；风险含义见位置说明。";
            } else if (!unknowns.isEmpty()) {
                disposition = Disposition.UNKNOWN; explanation = "已找到相关构造，但现有证据不足以评估控制覆盖或有效性。";
            } else if (!observations.isEmpty()) {
                disposition = Disposition.OBSERVED; explanation = "观察到相关控制或配置构造；这不是安全通过结论。";
            } else if (!applicable && project.diagnostics().isEmpty()) {
                disposition = Disposition.NOT_APPLICABLE;
                explanation = rule.id().equals("AI-L5-001") && project.metadata().aiDetected() ? "已解析源码中未识别支持的 Spring AI 流式调用。" : "已清点项目未识别 Spring AI 应用证据。";
            } else {
                disposition = Disposition.UNKNOWN; explanation = "未在支持语法范围内获得足够证据；控制可能在外部或未解析路径实现。";
            }
            Severity severity = disposition == Disposition.VIOLATED ?
                (rule.domain() == Domain.L3 || rule.domain() == Domain.L6 ? Severity.MEDIUM : Severity.HIGH) : Severity.INFO;
            List<Assessment> assessments = new ArrayList<>();
            if (project.supportedVersion() && !violations.isEmpty()) {
                assessments.add(assessment(Disposition.VIOLATED, severity, explanation, violations, limitations));
                if (!unknowns.isEmpty()) assessments.add(assessment(Disposition.UNKNOWN, Severity.INFO,
                    "同一规则另有无法解析的相关路径；已发现违规不消除这些覆盖缺口。", unknowns, limitations));
                if (!observations.isEmpty()) assessments.add(assessment(Disposition.OBSERVED, Severity.INFO,
                    "其他位置观察到控制或配置构造；仅证明其存在。", observations, limitations));
            } else if (project.supportedVersion() && !unknowns.isEmpty() && !observations.isEmpty()) {
                assessments.add(assessment(Disposition.UNKNOWN, Severity.INFO, explanation, unknowns, limitations));
                assessments.add(assessment(Disposition.OBSERVED, Severity.INFO,
                    "其他位置观察到控制或配置构造；仅证明其存在。", observations, limitations));
            } else assessments.add(assessment(disposition, severity, explanation, evidence, limitations));
            return List.copyOf(assessments);
        }
        private Assessment assessment(Disposition d, Severity s, String explanation, List<Evidence> evidence, List<String> limitations) {
            return new Assessment(rule.id(), rule.domain(), d, s, rule.title(), explanation, rule.recommendation(), evidence, limitations);
        }
    }
}
