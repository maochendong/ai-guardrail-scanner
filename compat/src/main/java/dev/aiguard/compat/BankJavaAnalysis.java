package dev.aiguard.compat;

import dev.aiguard.compat.JavaSyntax.Method;
import dev.aiguard.compat.JavaSyntax.Node;
import dev.aiguard.compat.JavaSyntax.Param;
import dev.aiguard.compat.JavaSyntax.Unit;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Adapts the existing Java syntax graph; it never executes or loads target classes. */
public final class BankJavaAnalysis {
  private final JavaGraph graph;
  private final Cancel cancel;
  private final BankFlow.Program program = new BankFlow.Program();
  private final Set<String> diagnostics = new HashSet<String>();
  private final Set<String> duplicateTypes = new HashSet<String>();
  private int remaining = 150000;

  private BankJavaAnalysis(JavaGraph graph, Cancel cancel) {
    this.graph = graph;
    this.cancel = cancel;
    Set<String> types = new HashSet<String>();
    for (Unit unit : graph.units)
      for (JavaSyntax.Type type : unit.types) {
        cancel.check();
        if (!types.add(type.qualifiedName)) duplicateTypes.add(type.qualifiedName);
      }
  }

  public static BankFlow.Program adapt(List<SourceFile> files, Cancel cancel) {
    return adapt(files, cancel, BankPolicy.generic());
  }

  public static BankFlow.Program adapt(List<SourceFile> files, Cancel cancel, BankPolicy policy) {
    return adapt(files, cancel, policy, new JavaSyntax.Cache());
  }

  public static BankFlow.Program adapt(
      List<SourceFile> files, Cancel cancel, BankPolicy policy, JavaSyntax.Cache syntax) {
    List<Unit> units = new ArrayList<Unit>();
    for (SourceFile file : files) {
      cancel.check();
      if (file.path.endsWith(".java")) units.add(syntax.parse(file, cancel));
    }
    return adapt(new JavaGraph(units, cancel), cancel);
  }

  public static BankFlow.Program adapt(JavaGraph graph, Cancel cancel) {
    return new BankJavaAnalysis(graph, cancel).run();
  }

  private BankFlow.Program run() {
    for (Unit unit : graph.units) {
      cancel.check();
      if (unit.syntaxErrors > 0 || unit.root == null) {
        program.incompletePaths.add(unit.path);
        diagnostic(
            "BANK_JAVA_PARSE_INCOMPLETE",
            unit.path,
            "Java syntax is unavailable; banking controls in this file remain unknown.");
      }
    }
    for (Method method : graph.methods()) {
      cancel.check();
      BankFlow.Function function = new BankFlow.Function();
      function.path = method.node.unit.path;
      function.line = method.line;
      function.symbol = method.owner.qualifiedName + "#" + method.name;
      for (Param param : method.params) {
        function.params.add(key(param.node));
        function.parameterNames.add(param.name);
      }
      program.functions.add(function);
      try {
        if (method.rootNode == null) function.body.add(statement("UNKNOWN", method.node));
        else statements(method.rootNode, function.body, method, 0);
      } catch (Limit exhausted) {
        incompleteFrom(method);
        function.body.clear();
        function.body.add(statement("UNKNOWN", method.node));
        diagnostic(
            "BANK_JAVA_ADAPTER_LIMIT",
            function.path,
            "Java banking adaptation reached its node or depth budget; remaining flow is unknown.");
        break;
      } catch (StackOverflowError exhausted) {
        incompleteFrom(method);
        function.body.clear();
        function.body.add(statement("UNKNOWN", method.node));
        diagnostic(
            "BANK_JAVA_ADAPTER_DEPTH",
            function.path,
            "Java banking adaptation exceeded its supported nesting depth; remaining flow is"
                + " unknown.");
        break;
      }
    }
    retainUnmodeledInitializationCalls();
    for (Map<String, Object> item : graph.diagnostics())
      diagnostic(
          "BANK_JAVA_BINDING_INCOMPLETE",
          String.valueOf(item.get("path")),
          "Java declaration binding is incomplete; ambiguous banking API symbols remain unknown.");
    return program;
  }

  private void incompleteFrom(Method first) {
    boolean remainingMethods = false;
    for (Method method : graph.methods()) {
      if (method == first) remainingMethods = true;
      if (remainingMethods) program.incompletePaths.add(method.node.unit.path);
    }
  }

  /**
   * Keep unsupported/deferred initialization calls visible without treating them as eager
   * execution.
   */
  private void retainUnmodeledInitializationCalls() {
    for (Unit unit : graph.units) {
      try {
        for (Node call : JavaSyntax.find(unit.root, null)) {
          if (!call.kind.equals("CALL") && !call.kind.equals("NEW")) continue;
          tick(0);
          if (!unmodeledInitialization(call)) continue;
          boolean nested = false;
          for (Node parent = call.parent;
              parent != null && parent.method == call.method;
              parent = parent.parent)
            if ((parent.kind.equals("CALL") || parent.kind.equals("NEW"))
                && unmodeledInitialization(parent)) {
              nested = true;
              break;
            }
          if (nested) continue;
          BankFlow.Function function = new BankFlow.Function();
          function.path = unit.path;
          function.line = call.line;
          function.symbol =
              (call.ownerType == null ? "" : call.ownerType.qualifiedName)
                  + "#<unmodeled-init-"
                  + call.start
                  + ">";
          BankFlow.Stmt unknown = statement("UNKNOWN", call);
          unknown.expr = expression(call, 0);
          function.body.add(unknown);
          program.functions.add(function);
        }
      } catch (Limit exhausted) {
        program.incompletePaths.add(unit.path);
        diagnostic(
            "BANK_JAVA_ADAPTER_LIMIT",
            unit.path,
            "Unmodeled initialization calls exceeded the adaptation budget; coverage is"
                + " incomplete.");
      } catch (StackOverflowError exhausted) {
        program.incompletePaths.add(unit.path);
        diagnostic(
            "BANK_JAVA_ADAPTER_DEPTH",
            unit.path,
            "Unmodeled initialization calls exceeded supported nesting; coverage is incomplete.");
      }
    }
  }

  private boolean unmodeledInitialization(Node call) {
    if (call.method == null) return true;
    Method method = call.method;
    if (method != method.owner.staticInitializer && method != method.owner.instanceInitializer)
      return false;
    for (Node parent = call.parent;
        parent != null && parent.method == method;
        parent = parent.parent) if (parent.kind.equals("LAMBDA")) return true;
    return false;
  }

  private void tick(int depth) {
    cancel.check();
    if (--remaining < 0 || depth > 128) throw new Limit();
  }

  private void diagnostic(String code, String path, String message) {
    if (diagnostics.size() < 128 && diagnostics.add(code + ":" + path))
      program.diagnostics.add(Findings.diagnostic(code, path, message));
  }

  private void statements(Node node, List<BankFlow.Stmt> out, Method method, int depth) {
    if (node == null || node.method != method) return;
    tick(depth);
    if (node.kind.equals("BLOCK")) {
      for (Node child : node.children) statements(child, out, method, depth + 1);
      return;
    }
    if (node.kind.equals("VAR") || node.kind.equals("FIELD") && node.decl == node) {
      BankFlow.Stmt result = statement("ASSIGN", node);
      result.target = key(node);
      result.expr = expression(node.initializer, depth + 1);
      out.add(result);
      return;
    }
    if (node.kind.equals("IF")) {
      BankFlow.Stmt result = statement("IF", node);
      result.expr = expression(node.condition, depth + 1);
      statements(node.thenBranch, result.body, method, depth + 1);
      statements(node.elseBranch, result.otherwise, method, depth + 1);
      out.add(result);
      return;
    }
    if (node.kind.equals("RETURN") || node.kind.equals("THROW")) {
      BankFlow.Stmt result = statement(node.kind, node);
      if (!node.args.isEmpty()) result.expr = expression(node.args.get(0), depth + 1);
      out.add(result);
      return;
    }
    if (node.kind.equals("TRY")) {
      BankFlow.Stmt result = statement("TRY", node);
      for (Node child : node.children) {
        if (child.kind.equals("CATCH")) {
          List<BankFlow.Stmt> handler = new ArrayList<BankFlow.Stmt>();
          for (Node body : child.children)
            if (!body.kind.equals("PARAM")) statements(body, handler, method, depth + 1);
          result.handlers.add(handler);
        } else if (child.kind.equals("FINALLY")) {
          for (Node body : child.children) statements(body, result.finalizer, method, depth + 1);
        } else statements(child, result.body, method, depth + 1);
      }
      out.add(result);
      return;
    }
    if (node.kind.equals("ASSIGN")) {
      Node declaration = graph.declaration(node.receiver);
      if (tracked(declaration, node.receiver) && node.args.size() == 2) {
        BankFlow.Stmt result = statement("ASSIGN", node);
        result.target = key(declaration);
        result.expr = expression(node.initializer, depth + 1);
        if (!node.name.equals("=")) {
          BankFlow.Expr combination = expr("UNKNOWN", node);
          combination.args.add(expression(node.receiver, depth + 1));
          combination.args.add(result.expr);
          result.expr = combination;
        }
        out.add(result);
        return;
      }
    }
    if (node.kind.equals("EXPR_STMT")
        && node.children.size() == 1
        && isExpression(node.children.get(0))) {
      statements(node.children.get(0), out, method, depth + 1);
      return;
    }
    if (isExpression(node) && !node.kind.equals("ASSIGN")) {
      BankFlow.Stmt result = statement("EXPR", node);
      result.expr = expression(node, depth + 1);
      out.add(result);
      return;
    }
    // Loops, switches, field writes and unsupported statements preserve candidate calls,
    // but their children must not establish a definite control-flow barrier.
    BankFlow.Stmt result = statement("UNKNOWN", node);
    if (node.kind.equals("ASSIGN")) result.expr = expression(node, depth + 1);
    else for (Node child : node.children) statements(child, result.body, method, depth + 1);
    out.add(result);
  }

  private boolean isExpression(Node node) {
    String kind = node.kind;
    return kind.equals("CALL")
        || kind.equals("NAME")
        || kind.equals("FIELD")
        || kind.equals("LITERAL")
        || kind.equals("PAREN")
        || kind.equals("CAST")
        || kind.equals("UNARY")
        || kind.equals("BINARY")
        || kind.equals("NEW")
        || kind.equals("ARRAY_ACCESS")
        || kind.equals("CONDITIONAL")
        || kind.equals("LAMBDA")
        || kind.equals("METHOD_REF")
        || kind.equals("ASSIGN")
        || kind.equals("UNKNOWN");
  }

  private BankFlow.Expr expression(Node node, int depth) {
    if (node == null) return new BankFlow.Expr("UNKNOWN");
    tick(depth);
    String kind = node.kind;
    if ((kind.equals("PAREN") || kind.equals("CAST")) && node.args.size() == 1)
      return expression(node.args.get(0), depth + 1);
    if (kind.equals("NAME")) {
      Node declaration = graph.declaration(node);
      BankFlow.Expr result = expr(tracked(declaration, node) ? "NAME" : "UNKNOWN", node);
      if (tracked(declaration, node)) result.name = key(declaration);
      return result;
    }
    if (kind.equals("CALL")) {
      BankFlow.Expr result = expr("CALL", node);
      result.symbol = symbol(node);
      JavaGraph.Edge edge = graph.resolve(node);
      result.bindingUncertain =
          result.symbol.length() == 0
              || edge.reasons.contains("AMBIGUOUS_DISPATCH")
              || edge.reasons.contains("TARGET_LIMIT")
              || edge.reasons.contains("UNSUPPORTED_OR_LIMIT");
      if (node.receiver != null && !typeReceiver(node.receiver))
        result.receiver = expression(node.receiver, depth + 1);
      for (Node arg : node.args) {
        result.args.add(expression(arg, depth + 1));
        result.argNames.add("");
      }
      if (result.symbol.equals("java.util.Map#of")
          && !result.bindingUncertain
          && edge.reasons.contains("EXTERNAL_TYPE")
          && node.args.size() % 2 == 0
          && node.args.size() <= 20) {
        Set<String> names = new HashSet<String>();
        boolean constantKeys = true;
        for (int i = 0; i < node.args.size(); i += 2) {
          String name = stringKey(node.args.get(i));
          if (name == null || !names.add(name)) {
            constantKeys = false;
            break;
          }
        }
        if (constantKeys) {
          result.kind = "MAP";
          for (int i = 0; i < node.args.size(); i += 2)
            result.members.put(stringKey(node.args.get(i)), result.args.get(i + 1));
          result.args.clear();
          result.argNames.clear();
        }
      } else if (result.symbol.equals("java.util.Map#get")
          && !result.bindingUncertain
          && edge.reasons.contains("EXTERNAL_TYPE")
          && result.receiver != null
          && node.args.size() == 1
          && stringKey(node.args.get(0)) != null) {
        result.kind = "MEMBER";
        result.name = stringKey(node.args.get(0));
        result.args.clear();
        result.argNames.clear();
      }
      return result;
    }
    if (kind.equals("FIELD") && node.receiver != null && !node.name.equals("<unsupported>")) {
      Node declaration = graph.declaration(node);
      if (tracked(declaration, node)) {
        BankFlow.Expr result = expr("NAME", node);
        result.name = key(declaration);
        return result;
      }
      BankFlow.Expr result = expr("MEMBER", node);
      result.receiver = expression(node.receiver, depth + 1);
      result.name = node.name;
      return result;
    }
    if (kind.equals("ARRAY_ACCESS")
        && node.args.size() == 2
        && stringKey(node.args.get(1)) != null) {
      BankFlow.Expr result = expr("MEMBER", node);
      result.receiver = expression(node.receiver, depth + 1);
      result.name = stringKey(node.args.get(1));
      return result;
    }
    if (kind.equals("NEW")
        && !node.modifiers.contains("array")
        && !node.modifiers.contains("anonymous")) {
      String type = graph.declaredType(node);
      boolean constructor = type.length() > 0 && !type.endsWith("[]");
      for (Node child : node.children) if (!node.args.contains(child)) constructor = false;
      if (constructor) {
        BankFlow.Expr result = expr("NEW", node);
        result.symbol = type + "#<init>";
        result.bindingUncertain = duplicateTypes.contains(type);
        for (Node arg : node.args) {
          result.args.add(expression(arg, depth + 1));
          result.argNames.add("");
        }
        return result;
      }
    }
    if (kind.equals("LITERAL")) {
      BankFlow.Expr result = expr("LITERAL", node);
      if (node.type.equals("boolean")) result.literal = Boolean.valueOf(node.literalValue);
      else if (node.type.equals("null")) result.literal = null;
      else if (node.type.equals("java.lang.String") || node.type.equals("char"))
        result.literal = node.literalValue;
      else {
        String number = node.literalValue == null ? "" : node.literalValue.replace("_", "");
        if (number.endsWith("l") || number.endsWith("L"))
          number = number.substring(0, number.length() - 1);
        try {
          result.literal =
              number.startsWith("0b") || number.startsWith("0B")
                  ? Long.valueOf(number.substring(2), 2)
                  : Long.decode(number);
        } catch (NumberFormatException notInteger) {
          try {
            Double value = Double.valueOf(number);
            if (value.isInfinite() || value.isNaN()) result.kind = "UNKNOWN";
            else result.literal = value;
          } catch (NumberFormatException unsupported) {
            result.kind = "UNKNOWN";
          }
        }
      }
      return result;
    }
    if ((kind.equals("UNARY")
            && (node.name.equals("!") || node.name.equals("+") || node.name.equals("-")))
        || kind.equals("BINARY")) {
      BankFlow.Expr result = expr(kind, node);
      result.operator = node.name;
      for (Node arg : node.args) result.args.add(expression(arg, depth + 1));
      return result;
    }
    BankFlow.Expr result = expr("UNKNOWN", node);
    if (kind.equals("LAMBDA") || kind.equals("METHOD_REF")) return result;
    if (node.receiver != null && !node.args.contains(node.receiver))
      result.receiver = expression(node.receiver, depth + 1);
    for (Node arg : node.args) result.args.add(expression(arg, depth + 1));
    if (node.args.isEmpty() && node.receiver == null)
      for (Node child : node.children)
        if (isExpression(child)) result.args.add(expression(child, depth + 1));
    return result;
  }

  private static String stringKey(Node node) {
    while (node != null && node.kind.equals("PAREN") && node.args.size() == 1)
      node = node.args.get(0);
    return node != null && node.kind.equals("LITERAL") && node.type.equals("java.lang.String")
        ? node.literalValue
        : null;
  }

  private String symbol(Node call) {
    if (call.receiver != null) {
      if (graph.resolve(call).reasons.contains("DUPLICATE_TYPE")) return "";
      // A dotted identifier may be either a package-qualified type or a value access.
      // Never reinterpret an unresolved field on a local value as a qualified type.
      Node base = call.receiver;
      while (base.kind.equals("FIELD") && base.receiver != null) base = base.receiver;
      if (base != call.receiver
          && graph.declaration(base) != null
          && graph.declaration(call.receiver) == null
          && !base.name.equals("this")) return "";
      String type = graph.declaredType(call.receiver);
      return type.length() == 0 ? "" : type + "#" + call.name;
    }
    JavaGraph.Edge edge = graph.resolve(call);
    if (!edge.unknown && !edge.candidate && edge.targets.size() == 1)
      return edge.targets.get(0).owner.qualifiedName + "#" + call.name;
    // Explicit static imports are useful for external APIs, but only when a local
    // declaration of the same name cannot shadow them. Wildcards stay unresolved.
    for (JavaSyntax.Type owner = call.ownerType; owner != null; owner = owner.owner)
      for (Method method : owner.methods) if (method.name.equals(call.name)) return "";
    Set<String> imports = new HashSet<String>();
    for (String imported : call.unit.staticImports) {
      if (imported.endsWith(".*")) return "";
      if (imported.endsWith("." + call.name))
        imports.add(imported.substring(0, imported.length() - call.name.length() - 1));
    }
    return imports.size() == 1 ? imports.iterator().next() + "#" + call.name : "";
  }

  private boolean typeReceiver(Node receiver) {
    if (!(receiver.kind.equals("NAME") || receiver.kind.equals("FIELD"))) return false;
    Node base = receiver;
    while (base.kind.equals("FIELD") && base.receiver != null) base = base.receiver;
    return base.kind.equals("NAME")
        && !base.name.equals("this")
        && !base.name.equals("super")
        && graph.declaration(base) == null
        && graph.declaration(receiver) == null
        && graph.declaredType(receiver).length() > 0;
  }

  private static boolean local(Node node) {
    return node != null && (node.kind.equals("VAR") || node.kind.equals("PARAM"));
  }

  /**
   * Only the current initialization sequence owns a field value; no object-wide proof is inferred.
   */
  private boolean tracked(Node declaration, Node use) {
    if (local(declaration)) return true;
    if (declaration == null
        || !declaration.kind.equals("FIELD")
        || use.method == null
        || declaration.ownerType != use.method.owner) return false;
    Method method = use.method;
    boolean isStatic = declaration.modifiers.contains("static");
    if (method != (isStatic ? method.owner.staticInitializer : method.owner.instanceInitializer))
      return false;
    if (use.kind.equals("NAME")) return true;
    if (!use.kind.equals("FIELD") || use.receiver == null) return false;
    return isStatic
        ? typeReceiver(use.receiver)
        : use.receiver.kind.equals("NAME") && use.receiver.name.equals("this");
  }

  private static String key(Node declaration) {
    return declaration.unit.path + ":" + declaration.start + ":" + declaration.name;
  }

  private static BankFlow.Stmt statement(String kind, Node node) {
    BankFlow.Stmt statement = new BankFlow.Stmt(kind);
    statement.path = node.unit.path;
    statement.line = node.line;
    return statement;
  }

  private static BankFlow.Expr expr(String kind, Node node) {
    BankFlow.Expr expression = new BankFlow.Expr(kind);
    expression.path = node.unit.path;
    expression.line = node.line;
    return expression;
  }

  private static final class Limit extends RuntimeException {
    private static final long serialVersionUID = 1L;
  }
}
