package dev.aiguard.compat;

import dev.aiguard.compat.JavaSyntax.*;
import java.util.*;

/** Source-only, bounded declaration graph. Candidate dispatch never proves execution. */
public final class JavaGraph {
  public static final class Edge {
    public final Node call;
    public final List<Method> targets;
    public final boolean candidate, unknown;
    public final Set<String> reasons;

    Edge(Node call, List<Method> targets, boolean candidate, boolean unknown, String reason) {
      this.call = call;
      this.targets = Collections.unmodifiableList(new ArrayList<Method>(targets));
      this.candidate = candidate;
      this.unknown = unknown;
      this.reasons = Collections.singleton(reason);
    }
  }

  public final List<Method> methods = new ArrayList<Method>();
  public final List<Unit> units;
  public final List<Map<String, Object>> diagnostics = new ArrayList<Map<String, Object>>();
  private final Cancel cancel;
  private final Map<String, List<Type>> types = new LinkedHashMap<String, List<Type>>();
  private final Map<String, List<String>> parents = new HashMap<String, List<String>>(),
      children = new HashMap<String, List<String>>();
  private final Map<Node, Edge> edges = new IdentityHashMap<Node, Edge>();
  private final Map<Method, List<Node>> incoming = new IdentityHashMap<Method, List<Node>>();
  private final Set<Node> resolving =
      Collections.newSetFromMap(new IdentityHashMap<Node, Boolean>());
  private final Map<Type, Map<String, List<Method>>> methodsBySignature =
      new IdentityHashMap<Type, Map<String, List<Method>>>();
  private final Set<String> diagnosticKeys = new HashSet<String>();
  private int operations = 2000000;
  private static final Set<String> PRIMITIVES =
      set("boolean byte short int long float double char void null");
  private static final Set<String> JAVA_LANG =
      set(
          "String Object Boolean Byte Short Integer Long Float Double Character Void Number Class"
              + " Enum Record Throwable Exception RuntimeException StringBuilder StringBuffer"
              + " Iterable Comparable Runnable Runtime ProcessBuilder");
  private static final Map<String, Set<String>> WILDCARDS = new HashMap<String, Set<String>>();

  static {
    WILDCARDS.put(
        "java.util",
        set(
            "List Map Set Collection ArrayList HashMap LinkedHashMap HashSet LinkedHashSet Optional"
                + " Iterator Collections Arrays Objects UUID"));
    WILDCARDS.put(
        "java.util.function",
        set(
            "Consumer BiConsumer Function BiFunction Supplier Predicate UnaryOperator"
                + " BinaryOperator"));
    WILDCARDS.put(
        "java.util.concurrent",
        set("CompletableFuture Future Executor ExecutorService ConcurrentHashMap ConcurrentMap"));
    WILDCARDS.put(
        "okhttp3", set("OkHttpClient Request Response RequestBody MediaType ResponseBody Call"));
    WILDCARDS.put("okhttp3.sse", set("EventSource EventSources EventSourceListener"));
    WILDCARDS.put("com.fasterxml.jackson.databind", set("ObjectMapper JsonNode"));
    WILDCARDS.put(
        "org.springframework.web.bind.annotation",
        set(
            "RequestMapping GetMapping PostMapping PutMapping DeleteMapping PatchMapping"
                + " RestController RequestBody RequestParam PathVariable"));
    WILDCARDS.put("org.springframework.ai.chat.client", set("ChatClient"));
    WILDCARDS.put(
        "org.springframework.ai.chat.client.advisor",
        set(
            "SafeGuardAdvisor MessageChatMemoryAdvisor VectorStoreChatMemoryAdvisor"
                + " QuestionAnswerAdvisor"));
    WILDCARDS.put(
        "org.springframework.ai.chat.client.advisor.api", set("CallAdvisor StreamAdvisor"));
    WILDCARDS.put("org.springframework.ai.chat.model", set("ChatModel"));
    WILDCARDS.put("org.springframework.ai.tool.annotation", set("Tool"));
    WILDCARDS.put("org.springframework.ai.moderation", set("ModerationModel ModerationPrompt"));
    WILDCARDS.put("org.slf4j", set("Logger MDC"));
  }

  private static Set<String> set(String text) {
    return new HashSet<String>(Arrays.asList(text.split(" ")));
  }

  public JavaGraph(List<Unit> input, Cancel cancel) {
    this.units = Collections.unmodifiableList(new ArrayList<Unit>(input));
    this.cancel = cancel;
    for (Unit unit : units)
      for (Type type : unit.types) {
        cancel.check();
        list(types, type.qualifiedName).add(type);
      }
    for (Map.Entry<String, List<Type>> entry : types.entrySet())
      if (entry.getValue().size() > 1)
        diagnostic(
            "CALL_GRAPH_DUPLICATE_TYPE",
            entry.getValue().get(0).node,
            "Duplicate source types prevent unique binding.");
    for (Unit unit : units)
      for (Type type : unit.types) {
        cancel.check();
        for (String raw : type.superTypes) {
          String parent = qualifiedType(type.node, raw);
          if (parent.length() > 0) {
            list(parents, type.qualifiedName).add(parent);
            list(children, parent).add(type.qualifiedName);
          }
        }
      }
    for (Unit unit : units)
      for (Method method : unit.methods) {
        cancel.check();
        if (methods.size() >= 30000) {
          diagnostic(
              "CALL_GRAPH_METHOD_LIMIT",
              method.node,
              "Method budget reached; coverage is incomplete.");
          break;
        }
        methods.add(method);
      }
    for (Method method : methods) {
      cancel.check();
      Map<String, List<Method>> signatures = methodsBySignature.get(method.owner);
      if (signatures == null) {
        signatures = new HashMap<String, List<Method>>();
        methodsBySignature.put(method.owner, signatures);
      }
      list(signatures, method.name + "/" + method.params.size()).add(method);
    }
    int calls = 0;
    outer:
    for (Method method : methods)
      for (Node call : JavaSyntax.find(method.rootNode, "CALL")) {
        cancel.check();
        if (call.method != method) continue;
        if (++calls > 100000) {
          diagnostic("CALL_GRAPH_CALL_LIMIT", call, "Call budget reached; coverage is incomplete.");
          break outer;
        }
        Edge edge = resolve(call);
        for (Method target : edge.targets) {
          List<Node> uses = incoming.get(target);
          if (uses == null) {
            uses = new ArrayList<Node>();
            incoming.put(target, uses);
          }
          uses.add(call);
        }
      }
  }

  private static <T> List<T> list(Map<String, List<T>> map, String key) {
    List<T> value = map.get(key);
    if (value == null) {
      value = new ArrayList<T>();
      map.put(key, value);
    }
    return value;
  }

  public List<Method> methods() {
    return Collections.unmodifiableList(methods);
  }

  public List<Map<String, Object>> diagnostics() {
    return Collections.unmodifiableList(diagnostics);
  }

  public List<Node> incoming(Method method) {
    List<Node> found = incoming.get(method);
    return found == null ? Collections.<Node>emptyList() : Collections.unmodifiableList(found);
  }

  public Method enclosing(Node node) {
    return node == null ? null : node.method;
  }

  private boolean tick(Node node) {
    cancel.check();
    if (--operations >= 0) return true;
    diagnostic(
        "CALL_GRAPH_OPERATION_LIMIT",
        node,
        "Call graph operation budget reached; unresolved paths remain unknown.");
    return false;
  }

  public String qualifiedType(Node context, String raw) {
    return qualified(context, raw, 0);
  }

  private String qualified(Node context, String raw, int depth) {
    if (context == null || raw == null || depth > 16 || !tick(context)) return "";
    String name = erase(raw.trim());
    if (name.length() == 0 || name.equals("var") || name.equals("?")) return "";
    if (name.endsWith("[]")) {
      String component = qualified(context, name.substring(0, name.length() - 2), depth + 1);
      return component.length() == 0 ? "" : component + "[]";
    }
    if (PRIMITIVES.contains(name)) return name;
    String first = name.indexOf('.') < 0 ? name : name.substring(0, name.indexOf('.')),
        suffix = name.substring(first.length());
    for (Type owner = context.ownerType; owner != null; owner = owner.owner) {
      if (owner.name.equals(first)) return owner.qualifiedName + suffix;
      String nested = owner.qualifiedName + "." + first;
      if (types.containsKey(nested)) return nested + suffix;
    }
    Unit unit = context.unit;
    String same = unit.packageName.length() == 0 ? first : unit.packageName + "." + first;
    if (types.containsKey(same)) return same + suffix;
    List<String> imports = unit.imports.get(first);
    if (imports != null) {
      Set<String> unique = new LinkedHashSet<String>(imports);
      return unique.size() == 1 ? unique.iterator().next() + suffix : "";
    }
    if (name.indexOf('.') >= 0 && Character.isLowerCase(first.charAt(0))) return name;
    Set<String> choices = new LinkedHashSet<String>();
    for (String wildcard : unit.wildcardImports) {
      cancel.check();
      String target = wildcard + "." + first;
      Set<String> known = WILDCARDS.get(wildcard);
      if (types.containsKey(target) || known != null && known.contains(first))
        choices.add(target + suffix);
    }
    if (choices.size() > 1) return "";
    if (choices.size() == 1) return choices.iterator().next();
    if (JAVA_LANG.contains(first)) return "java.lang." + first + suffix;
    return "";
  }

  public static String erase(String raw) {
    StringBuilder out = new StringBuilder();
    int depth = 0;
    for (int i = 0; i < raw.length(); i++) {
      char c = raw.charAt(i);
      if (c == '<') {
        depth++;
        continue;
      }
      if (c == '>') {
        depth--;
        continue;
      }
      if (depth == 0 && !Character.isWhitespace(c)) out.append(c);
    }
    return out.toString().replace("...", "[]");
  }

  public Node declaration(Node expr) {
    return declaration(expr, 0);
  }

  private Node declaration(Node expr, int depth) {
    if (expr == null || depth > 24 || !tick(expr)) return null;
    if (expr.decl == expr) return expr;
    if (expr.kind.equals("PAREN") || expr.kind.equals("CAST"))
      return expr.args.isEmpty() ? null : declaration(expr.args.get(0), depth + 1);
    if (expr.kind.equals("NAME")) {
      if (expr.name.equals("this") || expr.name.equals("super")) return null;
      for (Node scope = expr.parent; scope != null; scope = scope.parent) {
        cancel.check();
        Node found = null;
        for (Node child : scope.children)
          if (child.decl == child
              && child.receiver == null
              && child.name.equals(expr.name)
              && !child.kind.equals("FIELD")
              && (child.kind.equals("PARAM") || child.start < expr.start)) {
            if (found != null && found.start == child.start) return null;
            if (found == null || child.start > found.start) found = child;
          }
        if (found != null) return found;
        if (scope.kind.equals("TYPE")) {
          Node member = field(scope.ownerType, expr.name, new HashSet<String>(), 0);
          if (member != null) return member;
          if (scope.ownerType == null || !scope.ownerType.kind.equals("ANONYMOUS")) break;
        }
      }
      return field(expr.ownerType, expr.name, new HashSet<String>(), 0);
    }
    if (expr.kind.equals("FIELD") && expr.receiver != null) {
      String owner = type(expr.receiver, depth + 1);
      List<Type> matches = types.get(owner);
      if (matches == null || matches.size() != 1) return null;
      return field(matches.get(0), expr.name, new HashSet<String>(), 0);
    }
    return null;
  }

  private Node field(Type owner, String name, Set<String> seen, int depth) {
    if (owner == null || depth > 8 || !seen.add(owner.qualifiedName) || !tick(owner.node))
      return null;
    Node match = null;
    for (Node field : owner.fields)
      if (field.name.equals(name)) {
        if (match != null) return null;
        match = field;
      }
    if (match != null) return match;
    List<String> supers = parents.get(owner.qualifiedName);
    if (supers != null)
      for (String parent : supers) {
        List<Type> candidates = types.get(parent);
        if (candidates == null || candidates.size() != 1) continue;
        Node inherited = field(candidates.get(0), name, seen, depth + 1);
        if (inherited != null) {
          if (match != null && match != inherited) return null;
          match = inherited;
        }
      }
    if (match == null && owner.owner != null) match = field(owner.owner, name, seen, depth + 1);
    return match;
  }

  public String declaredType(Node expr) {
    return type(expr, 0);
  }

  public String expressionType(Node expr) {
    return type(expr, 0);
  }

  private String type(Node expr, int depth) {
    if (expr == null || depth > 24 || !tick(expr)) return "";
    if (expr.kind.equals("NEW")
        || expr.kind.equals("CAST")
        || expr.kind.equals("PARAM")
        || expr.kind.equals("VAR")
        || expr.kind.equals("FIELD") && expr.decl == expr) {
      String declared = qualifiedType(expr, expr.type);
      return declared.length() > 0
          ? declared
          : expr.type.equals("var") ? type(expr.initializer, depth + 1) : "";
    }
    if (expr.kind.equals("LITERAL")) return expr.type;
    if (expr.kind.equals("PAREN"))
      return expr.args.isEmpty() ? "" : type(expr.args.get(0), depth + 1);
    if (expr.kind.equals("NAME") && expr.name.equals("this"))
      return expr.ownerType == null ? "" : expr.ownerType.qualifiedName;
    if (expr.kind.equals("NAME") && expr.name.equals("super")) {
      List<String> p = expr.ownerType == null ? null : parents.get(expr.ownerType.qualifiedName);
      return p != null && p.size() == 1 ? p.get(0) : "";
    }
    if (expr.kind.equals("NAME") || expr.kind.equals("FIELD")) {
      Node decl = declaration(expr, depth + 1);
      if (decl != null) return type(decl, depth + 1);
      if (expr.kind.equals("NAME") && expr.name.equals("log"))
        for (Type owner = expr.ownerType; owner != null; owner = owner.owner)
          for (String annotation : owner.annotations)
            if (qualifiedType(owner.node, annotation).equals("lombok.extern.slf4j.Slf4j"))
              return "org.slf4j.Logger";
      return qualifiedType(expr, JavaSyntax.name(expr));
    }
    if (expr.kind.equals("CLASS")) return "java.lang.Class";
    if (expr.kind.equals("ARRAY_ACCESS")) {
      String array = type(expr.receiver, depth + 1);
      return array.endsWith("[]") ? array.substring(0, array.length() - 2) : "";
    }
    if (expr.kind.equals("BINARY") && expr.name.equals("+")) {
      for (Node child : expr.args)
        if (type(child, depth + 1).equals("java.lang.String")) return "java.lang.String";
      return "";
    }
    if (!expr.kind.equals("CALL")) return "";
    Edge edge = resolve(expr, depth + 1);
    String returnType = "";
    for (Method target : edge.targets) {
      String next = qualifiedType(target.node, target.returnType);
      if (next.length() == 0 || returnType.length() > 0 && !returnType.equals(next)) return "";
      returnType = next;
    }
    if (returnType.length() > 0) return returnType;
    String receiver = type(expr.receiver, depth + 1);
    List<Type> owners = types.get(receiver);
    if (expr.args.isEmpty() && owners != null && owners.size() == 1)
      for (Param component : owners.get(0).recordComponents)
        if (component.name.equals(expr.name)) return qualifiedType(component.node, component.type);
    if (expr.name.equals("get") && expr.args.size() == 1 && expr.receiver != null) {
      Node declaration = declaration(expr.receiver, depth + 1);
      String raw = declaration == null ? "" : declaration.type;
      int open = raw.indexOf('<'), close = raw.lastIndexOf('>');
      if (open >= 0 && close > open) {
        String arguments = raw.substring(open + 1, close);
        if (receiver.equals("java.util.List") && !arguments.contains(","))
          return qualifiedType(declaration, arguments);
      }
    }
    // External return contracts here are exact types, never source-value propagation.
    if (receiver.equals("java.lang.Runtime") && expr.name.equals("getRuntime")) return receiver;
    if (receiver.equals("okhttp3.OkHttpClient") && expr.name.equals("newCall"))
      return "okhttp3.Call";
    if (receiver.equals("okhttp3.Call") && expr.name.equals("execute")) return "okhttp3.Response";
    if (receiver.equals("okhttp3.Response") && expr.name.equals("body"))
      return "okhttp3.ResponseBody";
    if (receiver.equals("okhttp3.ResponseBody") && expr.name.equals("string"))
      return "java.lang.String";
    if (receiver.equals("okhttp3.Request.Builder"))
      return expr.name.equals("build") ? "okhttp3.Request" : receiver;
    if (receiver.equals("com.fasterxml.jackson.databind.ObjectMapper")
        && expr.name.equals("readTree")) return "com.fasterxml.jackson.databind.JsonNode";
    if (receiver.equals("com.fasterxml.jackson.databind.JsonNode")
        && Arrays.asList("get", "path", "at").contains(expr.name)) return receiver;
    return "";
  }

  public Edge resolve(Node call) {
    return resolve(call, 0);
  }

  private Edge resolve(Node call, int depth) {
    if (call == null || !call.kind.equals("CALL") || depth > 24 || !tick(call))
      return unknown(call, "UNSUPPORTED_OR_LIMIT");
    Edge cached = edges.get(call);
    if (cached != null) return cached;
    if (!resolving.add(call)) return unknown(call, "RECURSIVE_TYPE");
    try {
      String owner =
          call.receiver == null
              ? (call.ownerType == null ? "" : call.ownerType.qualifiedName)
              : type(call.receiver, depth + 1);
      if (owner.length() == 0) return remember(call, unknown(call, "UNKNOWN_RECEIVER"));
      List<Type> known = types.get(owner);
      if (known == null) return remember(call, unknown(call, "EXTERNAL_TYPE"));
      if (known.size() != 1) return remember(call, unknown(call, "DUPLICATE_TYPE"));
      Type direct = known.get(0);
      List<Method> base = select(direct, call, new HashSet<String>(), 0);
      if (operations < 0) return remember(call, unknown(call, "UNSUPPORTED_OR_LIMIT"));
      if (base.size() > 16) {
        diagnostic(
            "CALL_GRAPH_TARGET_LIMIT",
            call,
            "Dispatch target budget reached; no partial target set is treated as complete.");
        return remember(call, unknown(call, "TARGET_LIMIT"));
      }
      boolean concrete =
          call.receiver != null && call.receiver.kind.equals("NEW")
              || direct.modifiers.contains("final")
              || direct.kind.equals("RECORD")
              || direct.kind.equals("ENUM");
      boolean fixed =
          base.size() == 1
              && (base.get(0).modifiers.contains("private")
                  || base.get(0).modifiers.contains("static")
                  || base.get(0).modifiers.contains("final"));
      LinkedHashSet<Method> targets = new LinkedHashSet<Method>(base);
      boolean candidate = !concrete && !fixed;
      if (candidate) {
        ArrayDeque<String> queue = new ArrayDeque<String>();
        Set<String> seen = new HashSet<String>();
        queue.add(owner);
        int levels = 0;
        while (!queue.isEmpty() && levels++ < 30000) {
          String name = queue.remove();
          if (!seen.add(name)) continue;
          List<String> subs = children.get(name);
          if (subs == null) continue;
          for (String subtype : subs) {
            cancel.check();
            queue.add(subtype);
            List<Type> defs = types.get(subtype);
            if (defs != null && defs.size() == 1)
              targets.addAll(select(defs.get(0), call, new HashSet<String>(), 0));
            if (operations < 0) return remember(call, unknown(call, "UNSUPPORTED_OR_LIMIT"));
            if (targets.size() > 16) {
              diagnostic(
                  "CALL_GRAPH_TARGET_LIMIT",
                  call,
                  "Dispatch target budget reached; no partial target set is treated as complete.");
              return remember(call, unknown(call, "TARGET_LIMIT"));
            }
          }
        }
      }
      // Body-less declarations establish return types but do not represent an executable
      // implementation.
      boolean ambiguity = base.size() > 1 || targets.size() > 1;
      candidate = candidate || ambiguity;
      if (targets.isEmpty()) return remember(call, unknown(call, "NO_SOURCE_METHOD"));
      return remember(
          call,
          new Edge(
              call,
              new ArrayList<Method>(targets),
              candidate,
              false,
              ambiguity
                  ? "AMBIGUOUS_DISPATCH"
                  : candidate ? "VIRTUAL_DISPATCH" : "EXPLICIT_SOURCE_TARGET"));
    } finally {
      resolving.remove(call);
    }
  }

  private List<Method> select(Type owner, Node call, Set<String> seen, int depth) {
    List<Method> result = new ArrayList<Method>();
    if (depth > 8 || !seen.add(owner.qualifiedName) || !tick(call)) return result;
    int best = -1;
    Map<String, List<Method>> signatures = methodsBySignature.get(owner);
    List<Method> candidates =
        signatures == null ? null : signatures.get(call.name + "/" + call.args.size());
    if (candidates == null) candidates = Collections.emptyList();
    for (Method method : candidates) {
      if (!tick(call)) return Collections.emptyList();
      int score = 0;
      boolean incompatible = false;
      for (int i = 0; i < method.params.size(); i++) {
        String expected = qualifiedType(method.node, method.params.get(i).type),
            actual = type(call.args.get(i), 1);
        if (operations < 0) return Collections.emptyList();
        if (expected.length() == 0 || actual.length() == 0 || actual.equals("null")) continue;
        if (expected.equals(actual)) score += 2;
        else if (expected.equals("java.lang.Object")
            || isSubtype(actual, expected, new HashSet<String>(), 0)) score++;
        else {
          incompatible = true;
          break;
        }
      }
      if (!incompatible) {
        if (score > best) {
          result.clear();
          best = score;
        }
        if (score == best) result.add(method);
      }
    }
    if (!result.isEmpty()) return result;
    List<String> supers = parents.get(owner.qualifiedName);
    if (supers != null)
      for (String parent : supers) {
        List<Type> defs = types.get(parent);
        if (defs != null && defs.size() == 1)
          result.addAll(select(defs.get(0), call, seen, depth + 1));
      }
    return result;
  }

  private boolean isSubtype(String child, String parent, Set<String> seen, int depth) {
    if (child.equals(parent)) return true;
    if (depth > 8 || !seen.add(child)) return false;
    List<String> supers = parents.get(child);
    if (supers != null)
      for (String next : supers) if (isSubtype(next, parent, seen, depth + 1)) return true;
    return false;
  }

  private Edge unknown(Node call, String reason) {
    return new Edge(call, Collections.<Method>emptyList(), false, true, reason);
  }

  private Edge remember(Node call, Edge edge) {
    if (edges.size() < 100000) edges.put(call, edge);
    return edge;
  }

  private void diagnostic(String code, Node node, String message) {
    String path = node == null ? "" : node.unit.path;
    if (diagnosticKeys.add(code + ":" + path))
      diagnostics.add(Findings.diagnostic(code, path, message));
  }
}
