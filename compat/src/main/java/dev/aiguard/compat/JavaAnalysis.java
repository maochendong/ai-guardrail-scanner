package dev.aiguard.compat;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import dev.aiguard.compat.JavaSyntax.Method;
import dev.aiguard.compat.JavaSyntax.Node;
import dev.aiguard.compat.JavaSyntax.Param;
import dev.aiguard.compat.JavaSyntax.Unit;
import java.io.*;
import java.util.*;

/**
 * Versioned source evidence, with bounded local aliases and call edges. Never executes target code.
 */
public final class JavaAnalysis {
  private static final String CHAT = "org.springframework.ai.chat.client.ChatClient";
  private static final String GUARD = "org.springframework.ai.chat.client.advisor.SafeGuardAdvisor";
  private final JavaGraph graph;
  private final LegacyConfiguration configuration;
  private final Cancel cancel;
  private final Map<String, Bucket> buckets = new LinkedHashMap<String, Bucket>();
  private final Set<Method> aiMethods = new HashSet<Method>();
  private final Map<Method, List<Node>> assignments = new IdentityHashMap<Method, List<Node>>();
  private int budget = 300000;
  private boolean streamSeen, exhausted;

  private JavaAnalysis(JavaGraph graph, LegacyConfiguration configuration, Cancel cancel) {
    this.graph = graph;
    this.configuration = configuration;
    this.cancel = cancel;
    for (Map<String, Object> rule : catalog())
      if (!((String) rule.get("id")).startsWith("AI-PY-"))
        buckets.put((String) rule.get("id"), new Bucket(rule));
    for (Method method : graph.methods()) {
      assignments.put(method, JavaSyntax.find(method.rootNode, "ASSIGN"));
      for (Node call : JavaSyntax.find(method.rootNode, "CALL"))
        if (chat(call) || modelOutput(call)) {
          aiMethods.add(method);
          break;
        }
    }
  }

  public static AnalysisResult analyze(List<SourceFile> files, Cancel cancel) {
    cancel.check();
    AnalysisResult result = new AnalysisResult();
    LegacyConfiguration configuration = new LegacyConfiguration(files, cancel);
    List<Unit> units = new ArrayList<Unit>();
    for (SourceFile file : files)
      if (file.path.endsWith(".java")) {
        cancel.check();
        Unit unit = JavaSyntax.parse(file, cancel);
        units.add(unit);
        result.diagnostics.addAll(unit.diagnostics);
      }
    JavaGraph graph = new JavaGraph(units, cancel);
    JavaAnalysis engine = new JavaAnalysis(graph, configuration, cancel);
    engine.spring();
    configuration.assess(files, cancel, engine.buckets.get("AI-L3-002"));
    GatewayFlow flow = GatewayFlow.build(graph, cancel);
    engine.custom(flow);
    engine.functionCalling(flow);
    result.protocols.addAll(flow.protocols());
    result.gatewayMethods = flow.gateways().size();
    result.aiDetected =
        configuration.aiDetected || !engine.aiMethods.isEmpty() || result.gatewayMethods > 0;
    for (Unit unit : units) {
      for (List<String> importedList : unit.imports.values())
        for (String imported : importedList)
          if (imported.startsWith("org.springframework.ai.")) result.aiDetected = true;
      for (String imported : unit.wildcardImports)
        if (imported.startsWith("org.springframework.ai")) result.aiDetected = true;
    }
    result.springAiVersion = configuration.version;
    result.versionStatus = configuration.status;
    for (Unit unit : units) {
      boolean springSource = false;
      for (List<String> imports : unit.imports.values())
        for (String imported : imports)
          if (imported.startsWith("org.springframework.ai.")) springSource = true;
      for (String imported : unit.wildcardImports)
        if (imported.startsWith("org.springframework.ai")) springSource = true;
      if (springSource && !configuration.supported(unit.path)) {
        result.versionStatus = "UNKNOWN";
        result.diagnostics.add(
            Findings.diagnostic(
                "MODULE_VERSION_UNKNOWN",
                unit.path,
                "Nearest module does not establish a supported Spring AI version; unrelated modules"
                    + " do not supply its version."));
      }
    }
    result.diagnostics.addAll(configuration.diagnostics);
    result.diagnostics.addAll(graph.diagnostics());
    result.diagnostics.addAll(flow.diagnostics());
    if (engine.exhausted)
      result.diagnostics.add(
          Findings.diagnostic(
              "ANALYSIS_LIMIT",
              "",
              "Bounded local flow budget exhausted; unresolved paths were not evaluated."));
    boolean uncertainty = !result.diagnostics.isEmpty();
    for (Bucket bucket : engine.buckets.values()) {
      boolean applicable = result.aiDetected;
      if (bucket.id.startsWith("AI-GW-")
          || bucket.id.startsWith("AI-GUARD-")
          || bucket.id.startsWith("AI-FC-")) applicable = result.gatewayMethods > 0;
      if (bucket.id.equals("AI-L5-001") && !engine.streamSeen && !bucket.hasEvidence())
        applicable = false;
      result.assessments.addAll(bucket.finish(applicable, uncertainty || engine.exhausted));
    }
    return result;
  }

  @SuppressWarnings("unchecked")
  private static List<Map<String, Object>> catalog() {
    InputStream stream = JavaAnalysis.class.getResourceAsStream("/rules.json");
    if (stream == null) throw new IllegalStateException("Missing rule catalog");
    try {
      Reader reader = new InputStreamReader(stream, "UTF-8");
      try {
        return new Gson().fromJson(reader, new TypeToken<List<Map<String, Object>>>() {}.getType());
      } finally {
        reader.close();
      }
    } catch (IOException error) {
      throw new IllegalStateException("Rule catalog could not be read", error);
    }
  }

  static final class Bucket {
    final String id, domain, title, recommendation;
    final Map<String, List<Map<String, Object>>> items =
        new LinkedHashMap<String, List<Map<String, Object>>>();

    Bucket(Map<String, Object> rule) {
      id = (String) rule.get("id");
      domain = (String) rule.get("domain");
      title = (String) rule.get("title");
      recommendation = (String) rule.get("recommendation");
    }

    void add(String disposition, Node node, String detail) {
      if (node != null) add(disposition, node.unit.path, node.line, detail);
    }

    void add(String disposition, String path, int line, String detail) {
      List<Map<String, Object>> list = items.get(disposition);
      if (list == null) {
        list = new ArrayList<Map<String, Object>>();
        items.put(disposition, list);
      }
      Map<String, Object> evidence = Findings.evidence(path, line, detail);
      if (list.size() < 40 && !list.contains(evidence)) list.add(evidence);
    }

    boolean hasEvidence() {
      return !items.isEmpty();
    }

    List<Map<String, Object>> finish(boolean applicable, boolean uncertainty) {
      List<Map<String, Object>> results = new ArrayList<Map<String, Object>>();
      if (items.isEmpty())
        items.put(
            applicable || uncertainty ? "UNKNOWN" : "NOT_APPLICABLE",
            new ArrayList<Map<String, Object>>());
      for (String disposition : Arrays.asList("VIOLATED", "UNKNOWN", "OBSERVED", "NOT_APPLICABLE"))
        if (items.containsKey(disposition)) {
          String severity =
              disposition.equals("VIOLATED")
                  ? (domain.equals("L3") || domain.equals("L6") ? "MEDIUM" : "HIGH")
                  : "INFO";
          String explanation =
              disposition.equals("VIOLATED")
                  ? "在明确支持的局部语法范围内发现违反证据；不能据此推断外围控制不存在。"
                  : disposition.equals("OBSERVED")
                      ? "观察到局部构造；不证明控制有效或完整覆盖。"
                      : disposition.equals("NOT_APPLICABLE")
                          ? "已解析范围未识别该规则支持的相关来源。"
                          : "当前证据不足以确定控制语义、来源或全路径覆盖。";
          results.add(
              Findings.assessment(
                  id,
                  domain,
                  disposition,
                  severity,
                  title,
                  explanation,
                  recommendation,
                  items.get(disposition),
                  "仅对显式类型和有界源码结构给出结论；动态分派、外部策略和运行时状态未验证。",
                  "未执行目标程序；OBSERVED 和 UNKNOWN 均不表示安全通过。每种证据最多保留 40 个位置。"));
        }
      return results;
    }
  }

  private void add(String id, String disposition, Node node, String detail) {
    if ((id.startsWith("AI-L")) && !configuration.supported(node.unit.path)) {
      disposition = "UNKNOWN";
      detail = "Spring AI 模块版本未确认或不支持；保留相关语法位置，不能升级结论。";
    }
    buckets.get(id).add(disposition, node, detail);
  }

  private boolean tick() {
    cancel.check();
    if (--budget < 0) {
      exhausted = true;
      return false;
    }
    return true;
  }

  private void spring() {
    for (Unit unit : graph.units)
      for (JavaSyntax.Type cls : unit.types)
        for (String superType : cls.superTypes)
          if (type(
                  cls.node, superType, "org.springframework.ai.chat.client.advisor.api.CallAdvisor")
              || type(
                  cls.node,
                  superType,
                  "org.springframework.ai.chat.client.advisor.api.StreamAdvisor"))
            add("AI-L1-002", "UNKNOWN", cls.node, "存在自定义 Advisor 实现；其业务作用、绑定与同步/流式覆盖未确认。");
    for (Method method : graph.methods()) {
      cancel.check();
      if (exhausted) break;
      if (tool(method))
        add(
            "AI-L2-001",
            annotation(method, "org.springframework.security.access.prepost.PreAuthorize")
                ? "OBSERVED"
                : "UNKNOWN",
            method.node,
            annotation(method, "org.springframework.security.access.prepost.PreAuthorize")
                ? "Tool 方法声明 PreAuthorize；方法安全启用与授权表达式仍未验证。"
                : "已识别 Tool 方法，局部源码不能证明服务端授权。");
      for (Node call : JavaSyntax.find(method.rootNode, "CALL")) {
        if (!tick()) break;
        if (chat(call)) {
          if (call.name.equals("stream")) streamSeen = true;
          if (call.name.equals("system") && !call.args.isEmpty())
            add(
                "AI-L1-001",
                origin(call.args.get(0), "WEB", 0)
                    ? "VIOLATED"
                    : constant(call.args.get(0)) ? "OBSERVED" : "UNKNOWN",
                call,
                "Web 输入、常量或未解析表达式进入 system 指令；仅判断该直接信任边界。");
          if (call.name.equals("retry") && chainNamed(call, "stream"))
            add(
                "AI-L4-001",
                call.args.isEmpty()
                    ? "VIOLATED"
                    : call.args.size() == 1 && numeric(call.args.get(0)) ? "OBSERVED" : "UNKNOWN",
                call,
                call.args.isEmpty() ? "AI 流式调用使用无参数 retry，没有重试次数上限。" : "已发现重试配置；总体预算、超时、配额未验证。");
          if (call.name.equals("advisors"))
            add(
                "AI-L1-002",
                containsType(call, GUARD) ? "OBSERVED" : "UNKNOWN",
                call,
                "发现请求级 Advisor 配置；安全语义、默认 Advisor 与备用路径仍需核实。");
        }
        advisor(call);
        logging(call);
        audit(call);
        Node sink = sinkArgument(call);
        if (sink != null) springSink(call, sink);
      }
      for (Node creation : JavaSyntax.find(method.rootNode, "NEW")) {
        if (!tick()) break;
        if (type(creation, creation.type, "java.lang.ProcessBuilder") && !creation.args.isEmpty()) {
          springSink(creation, creation.args.get(0));
          if (shell(creation)) springSink(creation, creation.args.get(2));
        }
        if (type(creation, creation.type, GUARD) && !boundGuard(creation))
          add("AI-L1-002", "UNKNOWN", creation, "发现围栏 Advisor 构造，但未确认绑定到该模型请求。");
      }
      guardBypass(method);
      streamOrder(method);
    }
  }

  private boolean annotation(Method method, String qualified) {
    for (String name : method.annotations) if (type(method.node, name, qualified)) return true;
    return false;
  }

  private boolean web(Method method) {
    if (method == null) return false;
    for (String name :
        Arrays.asList(
            "RequestMapping",
            "GetMapping",
            "PostMapping",
            "PutMapping",
            "PatchMapping",
            "DeleteMapping"))
      if (annotation(method, "org.springframework.web.bind.annotation." + name)) return true;
    return false;
  }

  private boolean tool(Method method) {
    return method != null && annotation(method, "org.springframework.ai.tool.annotation.Tool");
  }

  private boolean type(Node at, String raw, String expected) {
    return expected.equals(graph.qualifiedType(at, raw));
  }

  private boolean receiver(Node call, String expected) {
    return call.receiver != null && expected.equals(graph.declaredType(call.receiver));
  }

  private boolean staticScope(Node call, String expected) {
    return call.receiver != null
        && graph.declaration(call.receiver) == null
        && type(call.receiver, qualifiedName(call.receiver), expected);
  }

  private String qualifiedName(Node node) {
    if (node == null) return "";
    if (node.kind.equals("NAME")) return node.name;
    if (node.kind.equals("FIELD")) return qualifiedName(node.receiver) + "." + node.name;
    return "";
  }

  private boolean chainType(Node node, String expected) {
    for (int i = 0; node != null && i < 40; i++, node = node.receiver)
      if (expected.equals(graph.declaredType(node))) return true;
    return false;
  }

  private boolean chat(Node call) {
    return chainType(call, CHAT);
  }

  private boolean chainNamed(Node node, String name) {
    for (int i = 0; node != null && i < 40; i++, node = node.receiver)
      if (node.kind.equals("CALL") && node.name.equals(name)) return true;
    return false;
  }

  private boolean modelOutput(Node call) {
    return call != null
        && call.kind.equals("CALL")
        && (receiver(call, "org.springframework.ai.chat.model.ChatModel")
                && call.name.equals("call")
            || chat(call)
                && Arrays.asList("content", "chatResponse", "entity").contains(call.name)
                && (chainNamed(call, "call") || chainNamed(call, "stream")));
  }

  private Node unwrap(Node node) {
    int depth = 0;
    while (node != null && depth++ < 12 && (node.kind.equals("PAREN") || node.kind.equals("CAST")))
      node =
          node.initializer != null
              ? node.initializer
              : node.children.isEmpty() ? null : node.children.get(0);
    return node;
  }

  private boolean origin(Node expr, String wanted, int depth) {
    if (expr == null || depth > 12 || !tick()) return false;
    expr = unwrap(expr);
    if (expr == null) return false;
    if (wanted.equals("MODEL") && modelOutput(expr)) return true;
    if (expr.kind.equals("BINARY")) {
      for (Node child : expr.children) if (origin(child, wanted, depth + 1)) return true;
      return false;
    }
    if (!expr.kind.equals("NAME")) return false;
    Node declaration = graph.declaration(expr);
    if (declaration == null || !unchanged(declaration, expr)) return false;
    if (declaration.kind.equals("PARAM")) {
      Method owner = graph.enclosing(declaration);
      if (declaration.parent != null
          && declaration.parent.kind.equals("METHOD")
          && (wanted.equals("WEB") && owner != null && web(owner)
              || wanted.equals("TOOL") && owner != null && tool(owner))) return true;
      Node lambda = ancestor(declaration, "LAMBDA");
      if (wanted.equals("MODEL")
          && lambda != null
          && lambda.parent != null
          && lambda.parent.kind.equals("CALL")) {
        Node call = lambda.parent;
        if (Arrays.asList("subscribe", "doOnNext", "map", "flatMap").contains(call.name)
            && chat(call)
            && chainNamed(call, "stream")) {
          Node scope = call.receiver;
          while (scope != null) {
            if (scope.kind.equals("CALL")
                && Arrays.asList("map", "flatMap", "transform", "handle", "cast", "ofType")
                    .contains(scope.name)) return false;
            scope = scope.receiver;
          }
          return true;
        }
      }
    }
    return declaration.kind.equals("VAR")
        && declaration.initializer != null
        && origin(declaration.initializer, wanted, depth + 1);
  }

  private boolean unchanged(Node declaration, Node use) {
    Method owner = graph.enclosing(use);
    if (owner == null) return false;
    List<Node> writes = assignments.get(owner);
    if (writes != null)
      for (Node assign : writes) {
        cancel.check();
        Node target = assign.receiver;
        if (target != null
            && graph.declaration(target) == declaration
            && assign.start > declaration.start
            && assign.start < use.start) return false;
      }
    for (Node unary : JavaSyntax.find(owner.rootNode, "UNARY"))
      if ((unary.name.contains("++") || unary.name.contains("--"))
          && unary.start > declaration.start
          && unary.start < use.start)
        for (Node name : JavaSyntax.find(unary, "NAME"))
          if (graph.declaration(name) == declaration) return false;
    return true;
  }

  private boolean constant(Node expr) {
    expr = unwrap(expr);
    if (expr == null) return false;
    if (expr.kind.equals("LITERAL")) return true;
    if (expr.kind.equals("BINARY") && !expr.children.isEmpty()) {
      for (Node child : expr.children) if (!constant(child)) return false;
      return true;
    }
    return false;
  }

  private boolean numeric(Node expr) {
    return expr != null
        && expr.kind.equals("LITERAL")
        && expr.literalValue != null
        && expr.literalValue.matches("[0-9][0-9_]*[lL]?");
  }

  private boolean string(Node expr) {
    return expr != null
        && expr.kind.equals("LITERAL")
        && ("String".equals(expr.type) || "java.lang.String".equals(expr.type));
  }

  private boolean containsType(Node root, String expected) {
    for (Node n : JavaSyntax.find(root, "NEW")) if (type(n, n.type, expected)) return true;
    return false;
  }

  private boolean logger(Node call) {
    if (!Arrays.asList("info", "warn", "error", "trace", "debug").contains(call.name)) return false;
    if (receiver(call, "org.slf4j.Logger")) return true;
    if (call.receiver == null
        || !call.receiver.kind.equals("NAME")
        || !call.receiver.name.equals("log")
        || graph.declaration(call.receiver) != null
        || call.ownerType == null) return false;
    for (String annotation : call.ownerType.annotations)
      if (type(call, annotation, "lombok.extern.slf4j.Slf4j")) return true;
    return false;
  }

  private Node sinkArgument(Node call) {
    if (call.args.isEmpty()) return null;
    if (call.name.equals("exec")
        && (receiver(call, "java.lang.Runtime")
            || call.receiver != null
                && call.receiver.kind.equals("CALL")
                && call.receiver.name.equals("getRuntime")
                && staticScope(call.receiver, "java.lang.Runtime"))) return call.args.get(0);
    if (Arrays.asList("execute", "update", "query", "queryForObject", "queryForList", "batchUpdate")
            .contains(call.name)
        && receiver(call, "org.springframework.jdbc.core.JdbcTemplate")) return call.args.get(0);
    return null;
  }

  private boolean shell(Node creation) {
    if (creation.args.size() < 3 || !string(creation.args.get(0)) || !string(creation.args.get(1)))
      return false;
    String exe = creation.args.get(0).literalValue.replace('\\', '/');
    exe = exe.substring(exe.lastIndexOf('/') + 1).toLowerCase(Locale.ROOT);
    String flag = creation.args.get(1).literalValue;
    return Arrays.asList("sh", "bash", "dash", "zsh", "ksh").contains(exe)
            && Arrays.asList("-c", "-lc").contains(flag)
        || Arrays.asList("cmd", "cmd.exe").contains(exe) && "/c".equalsIgnoreCase(flag)
        || Arrays.asList("powershell", "powershell.exe", "pwsh", "pwsh.exe").contains(exe)
            && "-Command".equalsIgnoreCase(flag);
  }

  private void springSink(Node sink, Node arg) {
    if (origin(arg, "MODEL", 0)) add("AI-L7-001", "VIOLATED", sink, "模型输出经未修改局部别名进入命令或 SQL 执行文本。");
    else if (!constant(arg) && aiMethods.contains(graph.enclosing(sink)))
      add("AI-L7-001", "UNKNOWN", sink, "AI 方法包含动态执行文本；转换与跨方法来源尚未解析。");
    if (origin(arg, "TOOL", 0))
      add("AI-L2-001", "VIOLATED", sink, "Tool 参数直接进入命令或 SQL 执行文本；本结论不推断外围授权不存在。");
  }

  private static Node ancestor(Node node, String kind) {
    for (node = node.parent; node != null; node = node.parent)
      if (node.kind.equals(kind)) return node;
    return null;
  }

  private void advisor(Node call) {
    if (!call.name.equals("param") || call.args.size() < 2) return;
    Node lambda = ancestor(call, "LAMBDA");
    if (lambda == null
        || lambda.parent == null
        || !lambda.parent.kind.equals("CALL")
        || !lambda.parent.name.equals("advisors")
        || !chat(lambda.parent)) return;
    Node root = call;
    while (root.receiver != null) root = root.receiver;
    Node decl = graph.declaration(root);
    boolean parameter = false;
    for (Param p : lambda.params) if (p.node == decl) parameter = true;
    if (!parameter) return;
    Node key = call.args.get(0);
    if (!key.kind.equals("FIELD")) return;
    if (key.name.equals("CONVERSATION_ID")
        && type(
            key, qualifiedName(key.receiver), "org.springframework.ai.chat.memory.ChatMemory")) {
      boolean bound =
          boundAdvisor(
              lambda.parent,
              Arrays.asList(
                  "org.springframework.ai.chat.client.advisor.MessageChatMemoryAdvisor",
                  "org.springframework.ai.chat.client.advisor.VectorStoreChatMemoryAdvisor"));
      add(
          "AI-L2-002",
          bound && string(call.args.get(1)) && web(graph.enclosing(call)) ? "VIOLATED" : "UNKNOWN",
          call,
          bound
              ? "同一请求表达式绑定记忆 Advisor 并配置会话键；固定 Web 会话键会被多个请求共享，动态键归属未证明。"
              : "配置了会话键但未确认同一请求表达式绑定记忆 Advisor。");
    }
    if (key.name.equals("FILTER_EXPRESSION")
        && type(
            key,
            qualifiedName(key.receiver),
            "org.springframework.ai.chat.client.advisor.QuestionAnswerAdvisor")) {
      boolean bound =
          boundAdvisor(
              lambda.parent,
              Arrays.asList("org.springframework.ai.chat.client.advisor.QuestionAnswerAdvisor"));
      add(
          "AI-L2-003",
          !bound
              ? "UNKNOWN"
              : origin(call.args.get(1), "WEB", 0)
                  ? "VIOLATED"
                  : constant(call.args.get(1)) ? "OBSERVED" : "UNKNOWN",
          call,
          bound
              ? "请求级 RAG 过滤表达式绑定到 QuestionAnswerAdvisor；请求来源会让调用方控制检索过滤，常量不证明租户范围正确。"
              : "发现过滤参数但同一请求表达式 Advisor 绑定未确认。");
    }
  }

  private boolean boundAdvisor(Node call, List<String> types) {
    Node outer = call;
    while (outer.parent != null
        && outer.parent.kind.equals("CALL")
        && outer.parent.receiver == outer) outer = outer.parent;
    for (Node c = outer; c != null; c = c.receiver)
      if (c.kind.equals("CALL") && c.name.equals("advisors"))
        for (Node argument : c.args) {
          for (String expected : types)
            if (argument.kind.equals("NEW") && type(argument, argument.type, expected)) return true;
          if (argument.kind.equals("CALL") && argument.name.equals("build"))
            for (Node b = argument; b != null; b = b.receiver)
              if (b.kind.equals("CALL") && b.name.equals("builder"))
                for (String expected : types) if (staticScope(b, expected)) return true;
        }
    return false;
  }

  private boolean boundGuard(Node creation) {
    for (Node n = creation.parent; n != null && !n.kind.equals("BLOCK"); n = n.parent)
      if (n.kind.equals("CALL")
          && Arrays.asList("advisors", "defaultAdvisors").contains(n.name)
          && chat(n)) return true;
    return false;
  }

  private void logging(Node call) {
    if (!logger(call)) return;
    boolean raw = false;
    for (Node arg : call.args) if (origin(arg, "MODEL", 0)) raw = true;
    Method method = graph.enclosing(call);
    if (!raw && method != null) {
      Set<Node> inputs = new HashSet<Node>();
      for (Node c : JavaSyntax.find(method.rootNode, "CALL"))
        if (chat(c) && Arrays.asList("user", "system").contains(c.name))
          for (Node a : c.args)
            if (origin(a, "WEB", 0))
              for (Node n : JavaSyntax.find(a, "NAME"))
                if (graph.declaration(n) != null) inputs.add(graph.declaration(n));
      for (Node a : call.args)
        if (origin(a, "WEB", 0))
          for (Node n : JavaSyntax.find(a, "NAME"))
            if (inputs.contains(graph.declaration(n))) raw = true;
    }
    if (raw) add("AI-L3-001", "VIOLATED", call, "AI 请求参数或模型原始输出直接进入 SLF4J 日志；是否包含敏感内容仍未证明。");
    else if (aiMethods.contains(method))
      add("AI-L3-001", "UNKNOWN", call, "AI 方法存在日志调用；自定义脱敏与数据语义未解析。");
  }

  private void audit(Node call) {
    if (!call.name.equals("put")
        || !staticScope(call, "org.slf4j.MDC")
        || call.args.size() != 2
        || !string(call.args.get(0))
        || !Arrays.asList("requestId", "traceId", "correlationId")
            .contains(call.args.get(0).literalValue)
        || !aiMethods.contains(graph.enclosing(call))) return;
    add(
        "AI-L6-001",
        string(call.args.get(1)) && web(graph.enclosing(call))
            ? "VIOLATED"
            : !constant(call.args.get(1)) ? "OBSERVED" : "UNKNOWN",
        call,
        "AI 方法设置 MDC 关联标识；固定 Web 请求标识不能单独区分请求，动态值的唯一性和传播未验证。");
  }

  private Node chainRoot(Node call) {
    int depth = 0;
    while (call != null && call.receiver != null && depth++ < 40) call = call.receiver;
    return call;
  }

  private boolean rawClient(Node call) {
    Node root = chainRoot(call), decl = root == null ? null : graph.declaration(root);
    if (decl == null || !decl.kind.equals("VAR") || !unchanged(decl, root)) return false;
    Node build = decl.initializer;
    if (build == null || !build.kind.equals("CALL") || !build.name.equals("build")) return false;
    Node builder = build.receiver;
    return builder != null
        && builder.kind.equals("CALL")
        && builder.name.equals("builder")
        && staticScope(builder, CHAT);
  }

  private void guardBypass(Method method) {
    for (Node block : JavaSyntax.find(method.rootNode, "TRY")) {
      Set<Node> clients = new HashSet<Node>();
      for (Node call : JavaSyntax.find(block, "CALL"))
        if (ancestor(call, "CATCH") == null
            && chat(call)
            && call.name.equals("advisors")
            && containsType(call, GUARD)) {
          Node root = chainRoot(call);
          Node decl = graph.declaration(root);
          if (decl != null) clients.add(decl);
        }
      for (Node catcher : JavaSyntax.find(block, "CATCH"))
        for (Node call : JavaSyntax.find(catcher, "CALL"))
          if (modelOutput(call)
              && clients.contains(graph.declaration(chainRoot(call)))
              && !chainNamed(call, "advisors"))
            add(
                "AI-L1-002",
                rawClient(call) ? "VIOLATED" : "UNKNOWN",
                call,
                rawClient(call)
                    ? "catch 对同一局部原始 ChatClient 重试时遗漏 try 中的围栏；局部构建未配置默认 Advisor。"
                    : "catch 未重复 try 的显式围栏绑定；默认 Advisor 或外围阻断未确认。");
    }
  }

  private Node directStatement(Node node) {
    Node previous = node;
    for (Node p = node.parent; p != null; p = p.parent) {
      if (p.kind.equals("BLOCK")) return previous;
      if (Arrays.asList(
              "IF", "FOR", "WHILE", "DO", "LOOP", "TRY", "CATCH", "SWITCH", "CASE", "LAMBDA")
          .contains(p.kind)) return null;
      previous = p;
    }
    return null;
  }

  private Node directBlock(Node node) {
    Node statement = directStatement(node);
    return statement == null ? null : statement.parent;
  }

  private Set<Node> modelDeclarations(Node root) {
    Set<Node> set = new HashSet<Node>();
    for (Node name : JavaSyntax.find(root, "NAME"))
      if (origin(name, "MODEL", 0) && graph.declaration(name) != null)
        set.add(graph.declaration(name));
    return set;
  }

  private void streamOrder(Method method) {
    List<Node> calls = JavaSyntax.find(method.rootNode, "CALL");
    for (Node send : calls)
      if (send.name.equals("send")
          && receiver(send, "org.springframework.web.servlet.mvc.method.annotation.SseEmitter")) {
        boolean model = false;
        for (Node arg : send.args) if (origin(arg, "MODEL", 0)) model = true;
        if (!model) continue;
        streamSeen = true;
        Node statement = directStatement(send);
        if (statement != send
            && !(statement != null
                && statement.kind.equals("EXPR_STMT")
                && statement.children.size() == 1
                && statement.children.get(0) == send)) {
          add("AI-L5-001", "UNKNOWN", send, "流式发送位于未解析控制结构中；审核顺序未确认。");
          continue;
        }
        Set<Node> payload = modelDeclarations(send);
        boolean before = false, after = false;
        for (Node check : calls)
          if (check.name.equals("call")
              && receiver(check, "org.springframework.ai.moderation.ModerationModel")
              && directBlock(check) == directBlock(send)
              && directBlock(send) != null) {
            Set<Node> checked = modelDeclarations(check);
            checked.retainAll(payload);
            if (checked.isEmpty()) continue;
            if (check.start < send.start) before = true;
            else after = true;
          }
        add(
            "AI-L5-001",
            before ? "OBSERVED" : after ? "VIOLATED" : "UNKNOWN",
            send,
            before
                ? "同一直线块在发送前调用内容审核；审核结果消费和失败阻断未证明。"
                : after ? "同一直线块先发送模型内容后审核相同值；后续审核无法撤回已发送内容。" : "发送模型内容前的审核未在支持结构中确认。");
      }
  }

  private static final class Decision {
    final Node call, payload, branch;

    Decision(Node call, Node payload, Node branch) {
      this.call = call;
      this.payload = payload;
      this.branch = branch;
    }
  }

  private void custom(GatewayFlow flow) {
    Bucket gateway = buckets.get("AI-GW-001"),
        logs = buckets.get("AI-GW-002"),
        input = buckets.get("AI-GUARD-001"),
        output = buckets.get("AI-GUARD-002"),
        release = buckets.get("AI-GUARD-003");
    for (Method method : flow.gateways()) {
      gateway.add("OBSERVED", method.node, "HTTP 传输与模型协议结构关联，已识别自定义模型边界。");
      gateway.add("UNKNOWN", method.node, "部署配置、接口实际实现及外部服务安全语义未运行验证。");
    }
    for (Method method : graph.methods()) {
      cancel.check();
      if (exhausted) break;
      List<Node> calls = JavaSyntax.find(method.rootNode, "CALL");
      List<Decision> decisions = new ArrayList<Decision>();
      for (Node call : calls) {
        if (!tick()) break;
        if (graph.enclosing(call) != method) continue;
        if (flow.isInvocation(call)) gateway.add("OBSERVED", call, "发现可解析到模型网关的源码调用；接口与工厂选择仅为候选。");
        if (logger(call))
          for (Node arg : call.args) {
            GatewayFlow.Origin source = flow.origin(arg);
            if (source != null) {
              logs.add(
                  source.candidate ? "UNKNOWN" : "VIOLATED",
                  call,
                  source.candidate
                      ? "候选模型响应进入日志；动态分派或转换使来源不确定。"
                      : "明确模型响应直接进入 SLF4J 日志参数；真实敏感数据及外围脱敏未验证。");
              break;
            }
          }
        Set<String> accessors = decisionAccessors(call);
        if (accessors.isEmpty()) continue;
        Node branch = consumingBranch(method, call, accessors), payload = null;
        for (Node arg : call.args)
          if (flow.origin(arg) != null) {
            payload = arg;
            break;
          }
        if (payload != null) {
          output.add(
              branch == null ? "UNKNOWN" : "OBSERVED",
              call,
              branch == null ? "模型值进入局部判定，但未确认该次结果控制提前退出。" : "模型值进入源码内判定，该次结果用于局部提前退出；业务安全含义未证明。");
          output.add("UNKNOWN", call, "判定算法、拒绝极性和完整路径覆盖需业务验证。");
          if (branch != null) decisions.add(new Decision(call, payload, branch));
        } else if (branch != null && flow.participatingMethods().contains(method))
          for (Node invocation : calls)
            if (flow.isInvocation(invocation) && ordered(branch, invocation)) {
              // A shared declaration is evidence of local input correlation, never an identity or
              // policy claim.
              if (sharedInput(call, invocation))
                input.add("OBSERVED", call, "判定与后续模型调用共享局部输入声明，并由该次判定结果控制提前退出。");
              input.add("UNKNOWN", call, "模型调用前存在局部退出结构；输入转换、安全语义及其他路径未证明。");
              break;
            }
      }
      for (Node send : calls)
        if (send.name.equals("send")
            && receiver(send, "org.springframework.web.servlet.mvc.method.annotation.SseEmitter"))
          for (Node payload : sentPayloads(send)) {
            if (flow.origin(payload) == null) continue;
            boolean early = false, late = false;
            for (Decision decision : decisions)
              if (sameValue(payload, decision.payload)) {
                early |= ordered(decision.branch, send);
                late |= ordered(send, decision.branch);
              }
            if (early || late)
              release.add(
                  "OBSERVED",
                  send,
                  early ? "发送同一模型值之前存在消费该次判定结果的提前退出；安全语义未证明。" : "同一模型值先发送后进入判定退出；自定义判定是否安全控制仍未知。");
            release.add("UNKNOWN", send, "局部顺序不能证明判定语义、异步输出及完整流覆盖；自定义后置检查不直接升级为违反。");
          }
    }
  }

  private Set<String> decisionAccessors(Node call) {
    JavaGraph.Edge edge = graph.resolve(call);
    Set<String> common = null;
    for (Method target : edge.targets) {
      if (target.rootNode == null) continue;
      boolean used = false;
      for (Node n : JavaSyntax.find(target.rootNode, "NAME"))
        for (Param param : target.params) if (graph.declaration(n) == param.node) used = true;
      if (!used) return Collections.emptySet();
      Set<String> accessors = new HashSet<String>();
      String returned = graph.qualifiedType(target.node, target.returnType);
      if (returned.equals("boolean") || returned.equals("java.lang.Boolean")) accessors.add("");
      for (Unit unit : graph.units)
        for (JavaSyntax.Type type : unit.types)
          if (type.qualifiedName.equals(returned))
            for (Param component : type.recordComponents)
              if (component.type.equals("boolean")) accessors.add(component.name);
      for (Method getter : graph.methods())
        if (getter.owner.qualifiedName.equals(returned)
            && getter.params.isEmpty()
            && getter.returnType.equals("boolean")
            && getter.rootNode != null
            && getter.rootNode.children.size() == 1) {
          Node statement = getter.rootNode.children.get(0);
          if (!statement.kind.equals("RETURN") || statement.args.size() != 1) continue;
          Node field = graph.declaration(statement.args.get(0));
          if (field != null && field.kind.equals("FIELD") && field.type.equals("boolean"))
            accessors.add(getter.name);
        }
      if (common == null) common = accessors;
      else common.retainAll(accessors);
    }
    return common == null ? Collections.<String>emptySet() : common;
  }

  private Node consumingBranch(Method method, Node call, Set<String> accessors) {
    Node variable =
        call.parent != null && call.parent.kind.equals("VAR") && call.parent.initializer == call
            ? call.parent
            : null;
    for (Node branch : JavaSyntax.find(method.rootNode, "IF")) {
      cancel.check();
      if (!terminal(branch.thenBranch) && !terminal(branch.elseBranch)
          || !JavaSyntax.find(branch.condition, "ASSIGN").isEmpty()) continue;
      if (accessors.contains("") && directDecisionUse(branch.condition, call)) return branch;
      if (variable == null || call.start >= branch.start) continue;
      boolean changed = false;
      for (Node assignment : assignments.get(method))
        if (referencesDeclaration(assignment.receiver, variable)
            && assignment.start > call.start
            && assignment.start < branch.start) changed = true;
      for (Node other : JavaSyntax.find(method.rootNode, "CALL"))
        if (other.start > call.start
            && other.start < branch.start
            && (referencesDeclaration(other.receiver, variable)
                || anyReferences(other.args, variable))) changed = true;
      for (Node other : JavaSyntax.find(branch.condition, "CALL"))
        if (anyReferences(other.args, variable)
            || referencesDeclaration(other.receiver, variable)
                && (!accessors.contains(other.name) || !other.args.isEmpty())) changed = true;
      if (changed) continue;
      for (Node use : JavaSyntax.find(branch.condition, "NAME"))
        if (graph.declaration(use) == variable
            && (accessors.contains("")
                || use.parent != null
                    && use.parent.kind.equals("CALL")
                    && use.parent.receiver == use
                    && use.parent.args.isEmpty()
                    && accessors.contains(use.parent.name))) return branch;
    }
    return null;
  }

  private boolean directDecisionUse(Node condition, Node call) {
    if (condition == null) return false;
    if (condition == call) return true;
    if (condition.kind.equals("PAREN")
        || condition.kind.equals("UNARY") && condition.name.equals("!")
        || condition.kind.equals("BINARY")
            && Arrays.asList("&&", "||", "==", "!=", "&", "|", "^").contains(condition.name))
      for (Node child : condition.args) if (directDecisionUse(child, call)) return true;
    return false;
  }

  private boolean terminal(Node branch) {
    if (branch == null) return false;
    if (branch.kind.equals("RETURN") || branch.kind.equals("THROW")) return true;
    if (branch.kind.equals("BLOCK") && !branch.children.isEmpty())
      return terminal(branch.children.get(branch.children.size() - 1));
    return branch.kind.equals("IF") && terminal(branch.thenBranch) && terminal(branch.elseBranch);
  }

  private boolean referencesDeclaration(Node expression, Node declaration) {
    if (expression == null) return false;
    for (Node name : JavaSyntax.find(expression, "NAME"))
      if (graph.declaration(name) == declaration) return true;
    return false;
  }

  private boolean anyReferences(List<Node> expressions, Node declaration) {
    for (Node expression : expressions)
      if (referencesDeclaration(expression, declaration)) return true;
    return false;
  }

  private boolean sharedInput(Node first, Node second) {
    Set<Node> declarations = new HashSet<Node>();
    for (Node arg : first.args)
      for (Node name : JavaSyntax.find(arg, "NAME")) {
        Node decl = graph.declaration(name);
        if (decl != null && unchanged(decl, name)) declarations.add(decl);
      }
    for (Node arg : second.args)
      for (Node name : JavaSyntax.find(arg, "NAME")) {
        Node decl = graph.declaration(name);
        if (declarations.contains(decl) && unchanged(decl, name)) return true;
      }
    return false;
  }

  private boolean sameValue(Node first, Node second) {
    if (first == second) return true;
    first = unwrap(first);
    second = unwrap(second);
    if (first == null
        || second == null
        || !first.kind.equals("NAME")
        || !second.kind.equals("NAME")) return false;
    Node decl = graph.declaration(first);
    return decl != null
        && decl == graph.declaration(second)
        && unchanged(decl, first)
        && unchanged(decl, second);
  }

  private boolean ordered(Node first, Node second) {
    Node a = directStatement(first), b = directStatement(second);
    return a != null && b != null && a != b && a.parent == b.parent && a.start < b.start;
  }

  private List<Node> sentPayloads(Node send) {
    List<Node> result = new ArrayList<Node>(send.args);
    for (Node arg : send.args)
      for (Node nested : JavaSyntax.find(arg, "CALL"))
        if (nested.name.equals("data") && nested.args.size() == 1) {
          for (Node call = nested; call != null; call = call.receiver)
            if (call.kind.equals("CALL")
                && call.name.equals("event")
                && staticScope(
                    call, "org.springframework.web.servlet.mvc.method.annotation.SseEmitter")) {
              result.add(nested.args.get(0));
              break;
            }
        }
    return result;
  }

  private static final class FcValue {
    final String role;
    final boolean candidate;
    final GatewayFlow.Origin source;

    FcValue(String role, boolean candidate, GatewayFlow.Origin source) {
      this.role = role;
      this.candidate = candidate;
      this.source = source;
    }

    FcValue candidate(boolean extra) {
      return new FcValue(role, candidate || extra, source);
    }
  }

  private static final class Bindings {
    final Map<Node, FcValue> fields = new IdentityHashMap<Node, FcValue>();
    final Map<Node, GatewayFlow.Origin> models = new IdentityHashMap<Node, GatewayFlow.Origin>();
  }

  private final Map<Method, Map<String, Set<String>>> protocolPairs =
      new IdentityHashMap<Method, Map<String, Set<String>>>();

  private void functionCalling(GatewayFlow gateways) {
    Bindings empty = new Bindings();
    for (Method method : graph.methods()) {
      cancel.check();
      if (exhausted) break;
      for (Node call : JavaSyntax.find(method.rootNode, "CALL")) {
        if (!tick()) break;
        Map<Integer, FcValue> values = argumentFields(call, empty, gateways);
        int danger = dangerous(call);
        if (values.containsKey(Integer.valueOf(danger)))
          fcDanger(call, values.get(Integer.valueOf(danger)));
        boolean name = false, args = false;
        for (FcValue value : values.values()) {
          name |= value.role.equals("NAME");
          args |= value.role.equals("ARGS");
        }
        if (!name || !args) continue;
        JavaGraph.Edge edge = graph.resolve(call);
        if (edge.targets.isEmpty()) continue;
        fcDispatch(call, values.size() < call.args.size());
        for (Method target : edge.targets)
          inspectFunction(
              target,
              bindings(target, call, values, empty, gateways, edge.candidate || edge.unknown),
              gateways,
              0,
              new HashSet<Method>());
      }
      for (Node creation : JavaSyntax.find(method.rootNode, "NEW"))
        if (type(creation, creation.type, "java.lang.ProcessBuilder") && !creation.args.isEmpty()) {
          FcValue first = fc(creation.args.get(0), empty, gateways, 0);
          if (first != null) fcDanger(creation, first);
          if (shell(creation)) {
            FcValue command = fc(creation.args.get(2), empty, gateways, 0);
            if (command != null) fcDanger(creation, command);
          }
        }
    }
  }

  private void fcDispatch(Node call, boolean separate) {
    buckets.get("AI-FC-001").add("OBSERVED", call, "模型工具名称与参数字段进入本地分派方法；字段协议与执行边界已关联。");
    buckets.get("AI-FC-001").add("UNKNOWN", call, "局部分派结构不证明允许列表完整、未知名称拒绝或运行时工具授权。");
    buckets.get("AI-FC-002").add("OBSERVED", call, "已关联模型工具参数与分派实参；字段提取和解析不等于参数验证。");
    buckets.get("AI-FC-002").add("UNKNOWN", call, "执行前 schema、取值范围和业务约束验证及拒绝结果消费尚未证明。");
    if (separate)
      buckets.get("AI-FC-003").add("OBSERVED", call, "分派另有独立实参，局部来源未归为模型字段；不根据名称推断身份或可信度。");
    buckets.get("AI-FC-003").add("UNKNOWN", call, "认证主体、租户来源、操作权限及资源归属不能由实参分离证明。");
  }

  private void fcDanger(Node sink, FcValue value) {
    buckets
        .get("AI-FC-001")
        .add(
            value.candidate ? "UNKNOWN" : "VIOLATED",
            sink,
            value.candidate ? "模型工具字段候选进入执行或反射选择；来源与分派未唯一确认。" : "明确模型工具字段进入命令文本、可执行目标或反射选择边界。");
    buckets.get("AI-FC-002").add("UNKNOWN", sink, "该执行边界的参数验证和拒绝路径未确认。");
    buckets.get("AI-FC-003").add("UNKNOWN", sink, "该执行边界的服务端认证、授权和资源归属未确认。");
  }

  private Map<Integer, FcValue> argumentFields(Node call, Bindings bindings, GatewayFlow gateways) {
    Map<Integer, FcValue> fields = new LinkedHashMap<Integer, FcValue>();
    for (int i = 0; i < call.args.size(); i++) {
      FcValue value = fc(call.args.get(i), bindings, gateways, 0);
      if (value != null) fields.put(Integer.valueOf(i), value);
    }
    return fields;
  }

  private Bindings bindings(
      Method target,
      Node call,
      Map<Integer, FcValue> fields,
      Bindings previous,
      GatewayFlow gateways,
      boolean candidate) {
    Bindings next = new Bindings();
    for (int i = 0; i < target.params.size() && i < call.args.size(); i++) {
      Node param = target.params.get(i).node;
      FcValue value = fields.get(Integer.valueOf(i));
      if (value != null) next.fields.put(param, value.candidate(candidate));
      GatewayFlow.Origin model = modelSource(call.args.get(i), previous, gateways, 0);
      if (model != null) next.models.put(param, model);
    }
    return next;
  }

  private void inspectFunction(
      Method method, Bindings bound, GatewayFlow gateways, int depth, Set<Method> seen) {
    if (depth > 3 || !seen.add(method) || !tick()) return;
    for (Node selection : JavaSyntax.find(method.rootNode, "SWITCH")) {
      FcValue name = fc(selection.condition, bound, gateways, 0);
      if (name == null || !name.role.equals("NAME")) continue;
      boolean literals = true;
      for (Node branch : selection.children)
        if (branch.kind.equals("CASE"))
          for (Node label : branch.args) if (!string(label)) literals = false;
      if (literals) {
        buckets.get("AI-FC-001").add("OBSERVED", selection, "模型工具名称进入固定字符串 switch 分派；列举分支不证明权限。");
        for (Node branch : selection.children)
          if (branch.kind.equals("CASE")
              && branch.name.equals("default")
              && JavaSyntax.find(branch, "CALL").isEmpty()
              && JavaSyntax.find(branch, "NEW").isEmpty())
            buckets.get("AI-FC-001").add("OBSERVED", branch, "默认分支没有直接方法调用或对象构造；仅证明这一局部默认路径。");
      }
    }
    for (Node call : JavaSyntax.find(method.rootNode, "CALL")) {
      if (!tick()) return;
      Map<Integer, FcValue> fields = argumentFields(call, bound, gateways);
      if (!fields.isEmpty()
          && mapReceiver(call)
          && Arrays.asList("get", "containsKey").contains(call.name))
        buckets.get("AI-FC-001").add("OBSERVED", call, "工具名称进入 Map 查找或成员检查；注册来源和检查支配关系未证明。");
      if (!fields.isEmpty()
          && Arrays.asList("readTree", "readValue", "convertValue").contains(call.name)
          && receiver(call, "com.fasterxml.jackson.databind.ObjectMapper"))
        buckets.get("AI-FC-002").add("OBSERVED", call, "工具字段经过 Jackson 解码；解码成功不等于 schema 或业务验证。");
      if (!fields.isEmpty()
          && call.name.equals("validate")
          && (receiver(call, "jakarta.validation.Validator")
              || receiver(call, "javax.validation.Validator")
              || receiver(call, "com.networknt.schema.JsonSchema")
              || receiver(call, "org.everit.json.schema.Schema")))
        buckets
            .get("AI-FC-002")
            .add("OBSERVED", call, "参数传入显式 Validator 或 Schema.validate；校验结果阻断与约束强度未证明。");
      int danger = dangerous(call);
      if (fields.containsKey(Integer.valueOf(danger)))
        fcDanger(call, fields.get(Integer.valueOf(danger)));
      if (fields.isEmpty()) continue;
      JavaGraph.Edge edge = graph.resolve(call);
      for (Method target : edge.targets)
        inspectFunction(
            target,
            bindings(target, call, fields, bound, gateways, edge.candidate || edge.unknown),
            gateways,
            depth + 1,
            new HashSet<Method>(seen));
    }
    for (Node creation : JavaSyntax.find(method.rootNode, "NEW"))
      if (type(creation, creation.type, "java.lang.ProcessBuilder") && !creation.args.isEmpty()) {
        FcValue first = fc(creation.args.get(0), bound, gateways, 0);
        if (first != null) fcDanger(creation, first);
        if (shell(creation)) {
          FcValue command = fc(creation.args.get(2), bound, gateways, 0);
          if (command != null) fcDanger(creation, command);
        }
      }
  }

  private boolean mapReceiver(Node call) {
    String type = call.receiver == null ? "" : graph.declaredType(call.receiver);
    return Arrays.asList(
            "java.util.Map",
            "java.util.HashMap",
            "java.util.LinkedHashMap",
            "java.util.TreeMap",
            "java.util.concurrent.ConcurrentMap",
            "java.util.concurrent.ConcurrentHashMap")
        .contains(type);
  }

  private int dangerous(Node call) {
    if (call.args.isEmpty()) return -1;
    if (sinkArgument(call) != null && call.name.equals("exec")) return 0;
    if (call.name.equals("forName") && staticScope(call, "java.lang.Class")) return 0;
    if (Arrays.asList("getMethod", "getDeclaredMethod").contains(call.name)
        && receiver(call, "java.lang.Class")) return 0;
    return -1;
  }

  private FcValue fc(Node expression, Bindings bound, GatewayFlow gateways, int depth) {
    if (expression == null || depth > 14 || !tick()) return null;
    expression = unwrap(expression);
    if (expression == null) return null;
    if (expression.kind.equals("NAME")) {
      Node decl = graph.declaration(expression);
      if (decl == null || !unchanged(decl, expression)) return null;
      FcValue binding = bound.fields.get(decl);
      if (binding != null) return binding;
      return decl.kind.equals("VAR") ? fc(decl.initializer, bound, gateways, depth + 1) : null;
    }
    if (expression.kind.equals("CALL")) {
      if (Arrays.asList(
                  "asText", "asInt", "asLong", "asDouble", "asBoolean", "textValue", "toString")
              .contains(expression.name)
          && expression.args.isEmpty()) return fc(expression.receiver, bound, gateways, depth + 1);
      if (Arrays.asList("readTree", "readValue", "convertValue").contains(expression.name)
          && !expression.args.isEmpty()
          && receiver(expression, "com.fasterxml.jackson.databind.ObjectMapper"))
        return fc(expression.args.get(0), bound, gateways, depth + 1);
      if (Arrays.asList("get", "path").contains(expression.name)
          && expression.args.size() == 1
          && string(expression.args.get(0))) {
        String key = expression.args.get(0).literalValue;
        String role =
            key.equals("name") || key.equals("tool")
                ? "NAME"
                : key.equals("arguments") || key.equals("args") ? "ARGS" : null;
        GatewayFlow.Origin source = modelSource(expression.receiver, bound, gateways, depth + 1);
        if (role != null && source != null && protocolPair(expression, key))
          return new FcValue(role, source.candidate, source);
      }
      if (expression.args.isEmpty() && expression.receiver != null) {
        FcValue value = recordComponent(expression, bound, gateways, depth + 1);
        if (value != null) return value;
      }
    }
    return null;
  }

  private GatewayFlow.Origin modelSource(
      Node expression, Bindings bindings, GatewayFlow gateways, int depth) {
    if (expression == null || depth > 14 || !tick()) return null;
    GatewayFlow.Origin source = gateways.origin(expression);
    if (source != null) return source;
    if (bindings.models.isEmpty() && bindings.fields.isEmpty()) return null;
    expression = unwrap(expression);
    if (expression == null) return null;
    if (expression.kind.equals("NAME")) {
      Node decl = graph.declaration(expression);
      if (decl == null || !unchanged(decl, expression)) return null;
      source = bindings.models.get(decl);
      if (source != null) return source;
      return decl.kind.equals("VAR")
          ? modelSource(decl.initializer, bindings, gateways, depth + 1)
          : null;
    }
    if (expression.kind.equals("CALL")) {
      if (Arrays.asList("get", "path").contains(expression.name)
          && expression.args.size() == 1
          && string(expression.args.get(0))
          && Arrays.asList(
                  "usage",
                  "prompt_tokens",
                  "completion_tokens",
                  "total_tokens",
                  "model",
                  "id",
                  "created",
                  "finish_reason",
                  "object",
                  "system_fingerprint")
              .contains(expression.args.get(0).literalValue)) return null;
      if (Arrays.asList(
              "get",
              "path",
              "asText",
              "asInt",
              "asLong",
              "asDouble",
              "asBoolean",
              "trim",
              "strip",
              "substring")
          .contains(expression.name))
        return modelSource(expression.receiver, bindings, gateways, depth + 1);
      if (Arrays.asList("readTree", "readValue").contains(expression.name)
          && receiver(expression, "com.fasterxml.jackson.databind.ObjectMapper")
          && !expression.args.isEmpty())
        return modelSource(expression.args.get(0), bindings, gateways, depth + 1);
    }
    return null;
  }

  private boolean protocolPair(Node access, String key) {
    Method owner = graph.enclosing(access);
    if (owner == null) return false;
    Map<String, Set<String>> groups = protocolPairs.get(owner);
    if (groups == null) {
      groups = new HashMap<String, Set<String>>();
      protocolPairs.put(owner, groups);
      for (Node call : JavaSyntax.find(owner.rootNode, "CALL"))
        if (Arrays.asList("get", "path").contains(call.name)
            && call.args.size() == 1
            && string(call.args.get(0))) {
          String group = scopeKey(call.receiver, 0);
          if (group.length() == 0) continue;
          Set<String> keys = groups.get(group);
          if (keys == null) {
            keys = new HashSet<String>();
            groups.put(group, keys);
          }
          keys.add(call.args.get(0).literalValue);
        }
    }
    Set<String> keys = groups.get(scopeKey(access.receiver, 0));
    return keys != null
        && (key.equals("name") || key.equals("arguments")
            ? keys.contains("name") && keys.contains("arguments")
            : keys.contains("tool") && keys.contains("args"));
  }

  private String scopeKey(Node node, int depth) {
    if (node == null || depth > 6) return "";
    node = unwrap(node);
    if (node == null) return "";
    if (node.kind.equals("NAME")) {
      Node decl = graph.declaration(node);
      return decl == null ? "" : decl.unit.path + ":" + decl.start;
    }
    if (node.kind.equals("CALL")
        && Arrays.asList("get", "path").contains(node.name)
        && node.args.size() == 1
        && string(node.args.get(0))) {
      String before = scopeKey(node.receiver, depth + 1);
      return before.length() == 0 ? "" : before + "/" + node.args.get(0).literalValue;
    }
    return "";
  }

  private FcValue recordComponent(
      Node accessor, Bindings bindings, GatewayFlow gateways, int depth) {
    if (depth > 14) return null;
    Node scope = unwrap(accessor.receiver);
    int alias = 0;
    while (scope != null && scope.kind.equals("NAME") && alias++ < 8) {
      Node decl = graph.declaration(scope);
      if (decl == null || !decl.kind.equals("VAR") || !unchanged(decl, scope)) return null;
      scope = unwrap(decl.initializer);
    }
    if (scope == null || !scope.kind.equals("CALL")) return null;
    JavaGraph.Edge edge = graph.resolve(scope);
    for (Method target : edge.targets) {
      Bindings child =
          bindings(
              target,
              scope,
              argumentFields(scope, bindings, gateways),
              bindings,
              gateways,
              edge.candidate || edge.unknown);
      if (child.models.isEmpty() && child.fields.isEmpty()) continue;
      for (Node returned : JavaSyntax.find(target.rootNode, "RETURN"))
        for (Node creation : returned.args)
          if (creation.kind.equals("NEW")) {
            String qualified = graph.qualifiedType(creation, creation.type);
            for (JavaSyntax.Type type : creation.unit.types)
              if (type.qualifiedName.equals(qualified) && type.kind.equals("RECORD"))
                for (int i = 0; i < type.recordComponents.size() && i < creation.args.size(); i++)
                  if (type.recordComponents.get(i).name.equals(accessor.name)) {
                    FcValue value = fc(creation.args.get(i), child, gateways, depth + 1);
                    if (value != null)
                      return value.candidate(
                          edge.candidate
                              || edge.unknown
                              || JavaSyntax.find(target.rootNode, "RETURN").size() > 1);
                  }
          }
    }
    return null;
  }
}
