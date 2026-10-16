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
public final class BusinessJavaAnalysis {
  private final JavaGraph graph;
  private final Cancel cancel;
  private final BusinessPolicy policy;
  private final LombokSourceDefaults lombok;
  private final BusinessFlow.Program program = new BusinessFlow.Program();
  private final Set<String> diagnostics = new HashSet<String>();
  private final Set<String> duplicateTypes = new HashSet<String>();
  private final Map<String, JavaSyntax.Type> sourceTypes =
      new java.util.HashMap<String, JavaSyntax.Type>();
  private final Map<Node, Boolean> defaultMappers = new java.util.IdentityHashMap<Node, Boolean>();
  private int remaining = 150000;

  private BusinessJavaAnalysis(
      JavaGraph graph, Cancel cancel, BusinessPolicy policy, List<SourceFile> files) {
    this.graph = graph;
    this.cancel = cancel;
    this.policy = policy;
    this.lombok = new LombokSourceDefaults(files, cancel);
    Set<String> types = new HashSet<String>();
    for (Unit unit : graph.units)
      for (JavaSyntax.Type type : unit.types) {
        cancel.check();
        if (!types.add(type.qualifiedName)) duplicateTypes.add(type.qualifiedName);
        sourceTypes.put(type.qualifiedName, type);
      }
  }

  public static BusinessFlow.Program adapt(List<SourceFile> files, Cancel cancel) {
    return adapt(files, cancel, BusinessPolicy.generic());
  }

  public static BusinessFlow.Program adapt(
      List<SourceFile> files, Cancel cancel, BusinessPolicy policy) {
    return adapt(files, cancel, policy, new JavaSyntax.Cache());
  }

  public static BusinessFlow.Program adapt(
      List<SourceFile> files, Cancel cancel, BusinessPolicy policy, JavaSyntax.Cache syntax) {
    List<Unit> units = new ArrayList<Unit>();
    for (SourceFile file : files) {
      cancel.check();
      if (file.path.endsWith(".java")) units.add(syntax.parse(file, cancel));
    }
    return new BusinessJavaAnalysis(new JavaGraph(units, cancel), cancel, policy, files).run();
  }

  public static BusinessFlow.Program adapt(JavaGraph graph, Cancel cancel) {
    return new BusinessJavaAnalysis(
            graph, cancel, BusinessPolicy.generic(), java.util.Collections.<SourceFile>emptyList())
        .run();
  }

  private BusinessFlow.Program run() {
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
      BusinessFlow.Function function = new BusinessFlow.Function();
      function.id = key(method.node);
      function.path = method.node.unit.path;
      function.line = method.line;
      function.symbol = method.owner.qualifiedName + "#" + method.name;
      for (Param param : method.params) {
        function.params.add(key(param.node));
        function.parameterNames.add(param.name);
      }
      program.functions.add(function);
      try {
        BusinessFlow.Expr constructed = constructorValue(method);
        if (constructed != null) {
          BusinessFlow.Stmt returned = statement("RETURN", method.node);
          returned.expr = constructed;
          function.body.add(returned);
        } else if (method.rootNode == null) function.body.add(statement("UNKNOWN", method.node));
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
          BusinessFlow.Function function = new BusinessFlow.Function();
          function.path = unit.path;
          function.line = call.line;
          function.symbol =
              (call.ownerType == null ? "" : call.ownerType.qualifiedName)
                  + "#<unmodeled-init-"
                  + call.start
                  + ">";
          BusinessFlow.Stmt unknown = statement("UNKNOWN", call);
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

  private void statements(Node node, List<BusinessFlow.Stmt> out, Method method, int depth) {
    if (node == null || node.method != method) return;
    tick(depth);
    if (node.kind.equals("BLOCK")) {
      for (Node child : node.children) statements(child, out, method, depth + 1);
      return;
    }
    if (node.kind.equals("VAR") || node.kind.equals("FIELD") && node.decl == node) {
      valueStatement("ASSIGN", key(node), node.initializer, node, out, depth + 1);
      return;
    }
    if (node.kind.equals("IF")) {
      BusinessFlow.Stmt result = statement("IF", node);
      result.expr = expression(node.condition, depth + 1);
      statements(node.thenBranch, result.body, method, depth + 1);
      statements(node.elseBranch, result.otherwise, method, depth + 1);
      out.add(result);
      return;
    }
    if (node.kind.equals("FOR")) {
      Node variable = null, body = null;
      boolean enhanced = true;
      for (Node child : node.children) {
        if (child.kind.equals("VAR") && child.collection != null && variable == null)
          variable = child;
        else if (body == null) body = child;
        else enhanced = false;
      }
      if (enhanced && variable != null && body != null) {
        BusinessFlow.Stmt iteration = statement("ITERATE", node);
        iteration.target = key(variable);
        iteration.expr = expression(variable.collection, depth + 1);
        statements(body, iteration.body, method, depth + 1);
        out.add(iteration);
        return;
      }
    }
    if (node.kind.equals("EXPR_STMT") && node.children.isEmpty()) {
      String exit = lombok.simpleLoopExit(node);
      if (!exit.isEmpty()) {
        out.add(statement(exit, node));
        return;
      }
    }
    if (node.kind.equals("RETURN") || node.kind.equals("THROW")) {
      valueStatement(
          node.kind, "", node.args.isEmpty() ? null : node.args.get(0), node, out, depth + 1);
      return;
    }
    if (node.kind.equals("TRY")) {
      BusinessFlow.Stmt result = statement("TRY", node);
      for (Node child : node.children) {
        if (child.kind.equals("CATCH")) {
          List<BusinessFlow.Stmt> handler = new ArrayList<BusinessFlow.Stmt>();
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
        if (node.name.equals("=")) {
          valueStatement("ASSIGN", key(declaration), node.initializer, node, out, depth + 1);
          return;
        }
        BusinessFlow.Stmt result = statement("ASSIGN", node);
        result.target = key(declaration);
        result.expr = expression(node.initializer, depth + 1);
        if (!node.name.equals("=")) {
          BusinessFlow.Expr combination = expr("UNKNOWN", node);
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
      BusinessFlow.Stmt result = statement("EXPR", node);
      result.expr = expression(node, depth + 1);
      out.add(result);
      return;
    }
    // Loops, switches, field writes and unsupported statements preserve candidate calls,
    // but their children must not establish a definite control-flow barrier.
    BusinessFlow.Stmt result = statement("UNKNOWN", node);
    if (node.kind.equals("ASSIGN")) result.expr = expression(node, depth + 1);
    else for (Node child : node.children) statements(child, result.body, method, depth + 1);
    out.add(result);
  }

  /**
   * A conditional which is the entire value can be lowered without moving calls across sibling
   * arguments or receivers. Nested conditionals in either arm retain their own branch order.
   */
  private void valueStatement(
      String kind,
      String target,
      Node value,
      Node location,
      List<BusinessFlow.Stmt> out,
      int depth) {
    tick(depth);
    Node conditional = value;
    while (conditional != null && conditional.kind.equals("PAREN") && conditional.args.size() == 1)
      conditional = conditional.args.get(0);
    if (conditional != null
        && conditional.kind.equals("CONDITIONAL")
        && conditional.args.size() == 3) {
      BusinessFlow.Stmt branch = statement("IF", conditional);
      branch.expr = expression(conditional.args.get(0), depth + 1);
      valueStatement(kind, target, conditional.args.get(1), location, branch.body, depth + 1);
      valueStatement(kind, target, conditional.args.get(2), location, branch.otherwise, depth + 1);
      out.add(branch);
      return;
    }
    BusinessFlow.Stmt result = statement(kind, location);
    result.target = target;
    if (value != null) result.expr = expression(value, depth + 1);
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

  private BusinessFlow.Expr expression(Node node, int depth) {
    if (node == null) return new BusinessFlow.Expr("UNKNOWN");
    tick(depth);
    String kind = node.kind;
    if (kind.equals("CAST") && node.args.size() == 1 && jacksonNode(node.args.get(0), 0)) {
      // Tree shape is not Java type compatibility. In particular, ObjectNode is not a Map;
      // dropping this cast would turn a ClassCastException path into an ordinary field read.
      BusinessFlow.Expr cast = expr("UNKNOWN", node);
      cast.args.add(expression(node.args.get(0), depth + 1));
      return cast;
    }
    if ((kind.equals("PAREN") || kind.equals("CAST")) && node.args.size() == 1)
      return expression(node.args.get(0), depth + 1);
    if (kind.equals("NAME")) {
      Node declaration = graph.declaration(node);
      BusinessFlow.Expr result = expr(tracked(declaration, node) ? "NAME" : "UNKNOWN", node);
      if (tracked(declaration, node)) result.name = key(declaration);
      return result;
    }
    if (kind.equals("CALL")) {
      BusinessFlow.Expr result = expr("CALL", node);
      result.symbol = symbol(node);
      JavaGraph.Edge edge = graph.resolve(node);
      if (!edge.unknown && edge.targets.size() == 1) {
        result.localTargetId = key(edge.targets.get(0).node);
        result.localTargetCandidate = edge.candidate;
      }
      result.bindingUncertain =
          result.symbol.length() == 0
              || node.receiver == null && edge.candidate
              || edge.reasons.contains("AMBIGUOUS_DISPATCH")
              || edge.reasons.contains("TARGET_LIMIT")
              || edge.reasons.contains("UNSUPPORTED_OR_LIMIT");
      if (node.receiver != null && !typeReceiver(node.receiver))
        result.receiver = expression(node.receiver, depth + 1);
      for (Node arg : node.args) {
        result.args.add(expression(arg, depth + 1));
        result.argNames.add("");
      }
      // A chained external method has no source declaration. Only a proven tree-producing
      // expression supplies Jackson's exact member namespace for policy precedence.
      if (result.symbol.isEmpty() && jacksonNode(node.receiver, 0)) {
        result.symbol = "com.fasterxml.jackson.databind.JsonNode#" + node.name;
        result.bindingUncertain = false;
      }
      // Explicit operator semantics take precedence over structural convenience summaries.
      if (!policy.contractsForSymbol(result.symbol).isEmpty()) return result;
      jacksonCall(node, result);
      generatedAccessor(node, result, edge);
      if (!result.bindingUncertain
          && edge.reasons.contains("EXTERNAL_TYPE")
          && result.receiver != null
          && listType(exactConstructionType(node.receiver))) {
        if (node.name.equals("add") && node.args.size() == 1) {
          result.kind = "COLLECTION_APPEND";
          result.operator = "boolean";
        } else if (node.name.equals("size") && node.args.isEmpty()) {
          result.kind = "COLLECTION_SIZE";
        }
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
      } else if (mapType(result.symbol.substring(0, Math.max(0, result.symbol.indexOf('#'))))
          && node.name.equals("get")
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
      if (!result.bindingUncertain
          && edge.reasons.contains("EXTERNAL_TYPE")
          && mapType(result.symbol.substring(0, Math.max(0, result.symbol.indexOf('#'))))
          && result.receiver != null
          && node.args.size() == 2
          && node.name.equals("put")
          && stringKey(node.args.get(0)) != null) {
        result.kind = "PUT_MEMBER";
        result.name = stringKey(node.args.get(0));
        result.args.remove(0);
        result.argNames.clear();
      }
      if (!edge.unknown && !edge.candidate && edge.targets.size() == 1 && result.receiver != null) {
        Method target = edge.targets.get(0);
        Node body = soleStatement(target.rootNode);
        if (body != null
            && body.kind.equals("RETURN")
            && target.params.isEmpty()
            && body.args.size() == 1) {
          Node field = ownField(body.args.get(0), target);
          if (field != null) {
            result.kind = "MEMBER";
            result.name = field.name;
            result.localTargetId = "";
          }
        } else if (body != null
            && body.kind.equals("ASSIGN")
            && body.name.equals("=")
            && target.params.size() == 1
            && target.returnType.equals("void")
            && graph.declaration(body.initializer) == target.params.get(0).node) {
          Node field = ownField(body.receiver, target);
          if (field != null) {
            result.kind = "PUT_MEMBER";
            result.name = field.name;
            result.operator = "void";
            result.localTargetId = "";
          }
        }
      }
      return result;
    }
    if (kind.equals("FIELD") && node.receiver != null && !node.name.equals("<unsupported>")) {
      Node declaration = graph.declaration(node);
      if (tracked(declaration, node)) {
        BusinessFlow.Expr result = expr("NAME", node);
        result.name = key(declaration);
        return result;
      }
      BusinessFlow.Expr result = expr("MEMBER", node);
      result.receiver = expression(node.receiver, depth + 1);
      result.name = node.name;
      return result;
    }
    if (kind.equals("ARRAY_ACCESS")
        && node.args.size() == 2
        && stringKey(node.args.get(1)) != null) {
      BusinessFlow.Expr result = expr("MEMBER", node);
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
        BusinessFlow.Expr result = expr("NEW", node);
        result.symbol = type + "#<init>";
        result.bindingUncertain = duplicateTypes.contains(type);
        for (Node arg : node.args) {
          result.args.add(expression(arg, depth + 1));
          result.argNames.add("");
        }
        if (!policy.contractsForSymbol(result.symbol).isEmpty()) return result;
        if ((type.equals("java.util.HashMap") || type.equals("java.util.LinkedHashMap"))
            && node.args.isEmpty()
            && sourceType(type) == null) result.kind = "MAP";
        else if ((type.equals("java.util.HashMap") || type.equals("java.util.LinkedHashMap"))
            && node.args.size() == 1
            && sourceType(type) == null
            && mapType(graph.declaredType(node.args.get(0)))) result.kind = "MAP_COPY";
        else if (listType(type) && node.args.isEmpty()) result.kind = "COLLECTION_NEW";
        JavaSyntax.Type owner = sourceType(type);
        Method matched = null;
        int matches = 0;
        if (owner != null && !duplicateTypes.contains(type))
          for (Method method : owner.methods)
            if (method.name.equals(owner.name)
                && method.returnType.isEmpty()
                && method.params.size() == node.args.size()) {
              matched = method;
              matches++;
            }
        if (matches == 1 && constructorValue(matched) != null)
          result.localTargetId = key(matched.node);
        else if (matches == 0
            && owner != null
            && node.args.isEmpty()
            && defaultGeneratedConstructor(owner)) {
          result = defaultFields(owner, node);
          result.generatedMethodUncertain =
              lombok.qualification(owner, graph) != LombokSourceDefaults.DEFAULTS;
          result.bindingUncertain = result.generatedMethodUncertain;
        }
        return result;
      }
    }
    if (kind.equals("LITERAL")) {
      BusinessFlow.Expr result = expr("LITERAL", node);
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
      BusinessFlow.Expr result = expr(kind, node);
      result.operator = node.name;
      for (Node arg : node.args) result.args.add(expression(arg, depth + 1));
      return result;
    }
    BusinessFlow.Expr result = expr("UNKNOWN", node);
    if (kind.equals("LAMBDA") || kind.equals("METHOD_REF")) return result;
    if (node.receiver != null && !node.args.contains(node.receiver))
      result.receiver = expression(node.receiver, depth + 1);
    for (Node arg : node.args) result.args.add(expression(arg, depth + 1));
    if (node.args.isEmpty() && node.receiver == null)
      for (Node child : node.children)
        if (isExpression(child)) result.args.add(expression(child, depth + 1));
    return result;
  }

  private boolean mapType(String type) {
    return (type.equals("java.util.Map")
            || type.equals("java.util.HashMap")
            || type.equals("java.util.LinkedHashMap"))
        && sourceType(type) == null;
  }

  private boolean listType(String type) {
    return (type.equals("java.util.ArrayList") || type.equals("java.util.LinkedList"))
        && sourceType(type) == null;
  }

  private JavaSyntax.Type sourceType(String name) {
    return sourceTypes.get(name);
  }

  private Node soleStatement(Node body) {
    while (body != null
        && (body.kind.equals("BLOCK") || body.kind.equals("EXPR_STMT"))
        && body.children.size() == 1) body = body.children.get(0);
    return body;
  }

  private Node ownField(Node access, Method method) {
    if (access == null) return null;
    Node field = graph.declaration(access);
    if (field == null
        || !field.kind.equals("FIELD")
        || field.ownerType != method.owner
        || field.modifiers.contains("static")) return null;
    if (access.kind.equals("NAME")) return field;
    return access.kind.equals("FIELD")
            && access.receiver != null
            && access.receiver.kind.equals("NAME")
            && access.receiver.name.equals("this")
        ? field
        : null;
  }

  private boolean markerOnly(JavaSyntax.Type owner) {
    for (String raw : owner.superTypes) {
      String name = graph.qualifiedType(owner.node, raw);
      if (!name.equals("java.io.Serializable") || sourceType(name) != null) return false;
    }
    return true;
  }

  private void jacksonCall(Node call, BusinessFlow.Expr result) {
    if (defaultJsonParse(call)) {
      result.kind = "JACKSON_PARSE";
      result.operator = "default-mapper";
      result.bindingUncertain = false;
      result.localTargetId = "";
      return;
    }
    if (!jacksonNode(call.receiver, 0)) return;
    String name = call.name;
    if ((name.equals("path") || name.equals("get") || name.equals("has"))
        && call.args.size() == 1
        && stringKey(call.args.get(0)) != null) {
      result.kind = "JACKSON_" + name.toUpperCase(java.util.Locale.ROOT);
    } else if (name.equals("asText")
        && (call.args.isEmpty() || call.args.size() == 1 && stringKey(call.args.get(0)) != null)) {
      result.kind = "JACKSON_TEXT";
    } else return;
    result.bindingUncertain = false;
    result.localTargetId = "";
  }

  private boolean defaultJsonParse(Node call) {
    return call != null
        && call.kind.equals("CALL")
        && call.name.equals("readTree")
        && call.args.size() == 1
        && graph.declaredType(call.args.get(0)).equals("java.lang.String")
        && sourceType("com.fasterxml.jackson.databind.JsonNode") == null
        && sourceType("com.fasterxml.jackson.databind.ObjectMapper") == null
        && policy
            .contractsForSymbol("com.fasterxml.jackson.databind.ObjectMapper#readTree")
            .isEmpty()
        && defaultMapper(call.receiver);
  }

  private boolean defaultMapper(Node receiver) {
    if (receiver == null
        || !graph.declaredType(receiver).equals("com.fasterxml.jackson.databind.ObjectMapper"))
      return false;
    if (receiver.kind.equals("NEW")) return plainMapperConstruction(receiver);
    Node declaration = graph.declaration(receiver);
    if (declaration == null) return false;
    Boolean cached = defaultMappers.get(declaration);
    if (cached != null) return cached.booleanValue();
    defaultMappers.put(declaration, Boolean.FALSE);
    if (!plainMapperConstruction(declaration.initializer)) return false;
    if (declaration.kind.equals("FIELD")) {
      if (!declaration.modifiers.contains("private") || !declaration.modifiers.contains("final"))
        return false;
    } else if (!declaration.kind.equals("VAR")) return false;
    // A final reference does not make ObjectMapper configuration immutable. Every source use
    // must be a String readTree call; configuration calls, aliases and escapes reject the summary.
    for (Node use : JavaSyntax.find(declaration.unit.root, null)) {
      tick(0);
      if (use == declaration
          || !(use.kind.equals("NAME") || use.kind.equals("FIELD"))
          || graph.declaration(use) != declaration) continue;
      Node call = use.parent;
      if (call == null
          || !call.kind.equals("CALL")
          || call.receiver != use
          || !call.name.equals("readTree")
          || call.args.size() != 1
          || !graph.declaredType(call.args.get(0)).equals("java.lang.String")) return false;
    }
    defaultMappers.put(declaration, Boolean.TRUE);
    return true;
  }

  private boolean plainMapperConstruction(Node created) {
    return created != null
        && created.kind.equals("NEW")
        && created.args.isEmpty()
        && !created.modifiers.contains("anonymous")
        && !created.modifiers.contains("array")
        && graph.declaredType(created).equals("com.fasterxml.jackson.databind.ObjectMapper")
        && sourceType("com.fasterxml.jackson.databind.ObjectMapper") == null
        && policy
            .contractsForSymbol("com.fasterxml.jackson.databind.ObjectMapper#<init>")
            .isEmpty();
  }

  private boolean jacksonNode(Node node, int depth) {
    if (node == null || depth > 16) return false;
    tick(depth);
    while (node.kind.equals("PAREN") && node.args.size() == 1) node = node.args.get(0);
    if (defaultJsonParse(node)) return true;
    if (node.kind.equals("CALL")
        && (node.name.equals("path") || node.name.equals("get"))
        && node.args.size() == 1
        && stringKey(node.args.get(0)) != null
        && policy
            .contractsForSymbol("com.fasterxml.jackson.databind.JsonNode#" + node.name)
            .isEmpty()) return jacksonNode(node.receiver, depth + 1);
    if (node.kind.equals("NAME")) {
      Node declaration = graph.declaration(node);
      if (declaration == null || !declaration.kind.equals("VAR") || declaration.method == null)
        return false;
      for (Node assignment : JavaSyntax.find(declaration.method.rootNode, "ASSIGN")) {
        tick(depth);
        if (graph.declaration(assignment.receiver) == declaration) return false;
      }
      return jacksonNode(declaration.initializer, depth + 1);
    }
    return false;
  }

  private boolean lombokAnnotation(Node context, Set<String> annotations, String expected) {
    if (sourceType(expected) != null || lombok.shadowsAnnotation(context, expected)) return false;
    for (String annotation : annotations)
      if (graph.qualifiedType(context, annotation).equals(expected)) return true;
    return false;
  }

  private boolean nullChecked(Node field) {
    for (String annotation : field.annotations) {
      String simple = annotation.substring(annotation.lastIndexOf('.') + 1);
      if (simple.toLowerCase(java.util.Locale.ROOT).endsWith("nonnull")
          || simple.equalsIgnoreCase("NotNull")
          || simple.equalsIgnoreCase("NonNullDecl")
          || simple.equalsIgnoreCase("NonNullType")) return true;
    }
    return false;
  }

  private boolean generatedType(JavaSyntax.Type owner) {
    return owner != null
        && owner.kind.equals("CLASS")
        && !duplicateTypes.contains(owner.qualifiedName)
        && markerOnly(owner)
        && owner.staticInitializer == null
        && owner.instanceInitializer == null
        && lombok.qualification(owner, graph) != LombokSourceDefaults.BLOCKED;
  }

  private void generatedAccessor(Node call, BusinessFlow.Expr result, JavaGraph.Edge edge) {
    if (!result.kind.equals("CALL")
        || result.receiver == null
        || !edge.targets.isEmpty()
        || !edge.reasons.contains("NO_SOURCE_METHOD")
        || result.bindingUncertain) return;
    JavaSyntax.Type owner = sourceType(graph.declaredType(call.receiver));
    if (!generatedType(owner) || !exactReceiver(call.receiver, owner)) return;
    boolean setter = call.args.size() == 1, getter = call.args.isEmpty();
    if (!setter && !getter) return;
    Node matched = null;
    for (Node field : owner.fields) {
      tick(0);
      if (field.modifiers.contains("static")
          || setter && field.modifiers.contains("final")
          || field.name.startsWith("$")
          || nullChecked(field)) continue;
      String annotation = setter ? "lombok.Setter" : "lombok.Getter";
      if (!lombokAnnotation(field, field.annotations, annotation)
          && !lombokAnnotation(owner.node, owner.annotations, annotation)
          && !lombokAnnotation(owner.node, owner.annotations, "lombok.Data")) continue;
      String suffix = field.name;
      if (suffix.isEmpty() || !suffix.matches("[a-zA-Z_][a-zA-Z_0-9]*")) continue;
      boolean primitiveBoolean = field.type.equals("boolean");
      if (primitiveBoolean
          && suffix.startsWith("is")
          && suffix.length() > 2
          && !Character.isLowerCase(suffix.charAt(2))
          && !Character.isUpperCase(suffix.charAt(2))) continue;
      boolean isPrefixed =
          primitiveBoolean
              && suffix.startsWith("is")
              && suffix.length() > 2
              && Character.isUpperCase(suffix.charAt(2));
      if (isPrefixed) suffix = suffix.substring(2);
      suffix = Character.toUpperCase(suffix.charAt(0)) + suffix.substring(1);
      String name = (setter ? "set" : primitiveBoolean ? "is" : "get") + suffix;
      if (!call.name.equals(name)) continue;
      Set<String> alternatives = new HashSet<String>();
      alternatives.add(name.toLowerCase(java.util.Locale.ROOT));
      if (primitiveBoolean) {
        String original = Character.toUpperCase(field.name.charAt(0)) + field.name.substring(1);
        alternatives.add(((setter ? "set" : "is") + original).toLowerCase(java.util.Locale.ROOT));
        if (!setter) {
          alternatives.add(("get" + suffix).toLowerCase(java.util.Locale.ROOT));
          alternatives.add(("get" + original).toLowerCase(java.util.Locale.ROOT));
        }
      }
      for (Method method : owner.methods)
        if (alternatives.contains(method.name.toLowerCase(java.util.Locale.ROOT))
            && (method.params.size() == call.args.size() || varargs(method))) return;
      if (matched != null) return;
      matched = field;
    }
    if (matched == null) return;
    result.kind = setter ? "PUT_MEMBER" : "MEMBER";
    result.name = matched.name;
    if (setter) result.operator = "void";
    result.localTargetId = "";
    result.generatedMethodUncertain =
        lombok.qualification(owner, graph) != LombokSourceDefaults.DEFAULTS;
    result.bindingUncertain = result.generatedMethodUncertain;
    if (result.generatedMethodUncertain)
      diagnostic(
          "GENERATED_METHOD_CONFIGURATION_UNVERIFIED",
          call.unit.path,
          "Lombok default accessors are candidate field paths: inherited or external configuration"
              + " and annotation processing were not verified.");
  }

  private boolean varargs(Method method) {
    // Syntax normalizes varargs to arrays. Suppress on either form instead of inventing a getter.
    return !method.params.isEmpty()
        && method.params.get(method.params.size() - 1).type.endsWith("[]");
  }

  private boolean exactReceiver(Node receiver, JavaSyntax.Type owner) {
    while (receiver != null && receiver.kind.equals("PAREN") && receiver.args.size() == 1)
      receiver = receiver.args.get(0);
    if (receiver == null) return false;
    if (owner.modifiers.contains("final")) return true;
    return exactConstructionType(receiver).equals(owner.qualifiedName);
  }

  private String exactConstructionType(Node receiver) {
    while (receiver != null && receiver.kind.equals("PAREN") && receiver.args.size() == 1)
      receiver = receiver.args.get(0);
    if (receiver == null) return "";
    Node created = receiver;
    if (receiver.kind.equals("NAME")) {
      Node declaration = graph.declaration(receiver);
      if (declaration == null || !declaration.kind.equals("VAR") || declaration.method == null)
        return "";
      created = declaration.initializer;
      for (Node assignment : JavaSyntax.find(declaration.method.rootNode, "ASSIGN")) {
        tick(0);
        if (graph.declaration(assignment.receiver) == declaration) return "";
      }
    }
    return created != null
            && created.kind.equals("NEW")
            && !created.modifiers.contains("anonymous")
            && !created.modifiers.contains("array")
        ? graph.declaredType(created)
        : "";
  }

  private boolean defaultGeneratedConstructor(JavaSyntax.Type owner) {
    if (!generatedType(owner) || !lombokAnnotation(owner.node, owner.annotations, "lombok.Data"))
      return false;
    for (Method method : owner.methods)
      if (method.name.equals(owner.name) && method.returnType.isEmpty()) return false;
    for (Node field : owner.fields)
      if (!field.modifiers.contains("static")
          && (field.initializer != null || field.modifiers.contains("final") || nullChecked(field)))
        return false;
    return true;
  }

  private BusinessFlow.Expr defaultFields(JavaSyntax.Type owner, Node location) {
    BusinessFlow.Expr result = expr("MAP", location);
    result.name = "object";
    for (Node field : owner.fields) {
      if (field.modifiers.contains("static")) continue;
      BusinessFlow.Expr zero = expr("LITERAL", field);
      zero.literal =
          field.type.equals("boolean")
              ? Boolean.FALSE
              : java.util.Arrays.asList("byte", "short", "int", "long", "float", "double", "char")
                      .contains(field.type)
                  ? Long.valueOf(0)
                  : null;
      result.members.put(field.name, zero);
    }
    return result;
  }

  private boolean clockValue(Node value) {
    if (value == null
        || !value.kind.equals("CALL")
        || !value.name.equals("currentTimeMillis")
        || !value.args.isEmpty()
        || value.receiver == null
        || !policy.contractsForSymbol("java.lang.System#currentTimeMillis").isEmpty()
        || sourceType("java.lang.System") != null) return false;
    String resolved = symbol(value);
    if (resolved.equals("java.lang.System#currentTimeMillis") && typeReceiver(value.receiver))
      return true;
    // JavaGraph deliberately has a small java.lang allowlist. Resolve this one harmless clock
    // only when no lexical declaration, explicit import or wildcard can supply another System.
    if (!value.receiver.kind.equals("NAME")
        || !value.receiver.name.equals("System")
        || graph.declaration(value.receiver) != null
        || !value.unit.wildcardImports.isEmpty()
        || value.unit.imports.containsKey("System")) return false;
    String samePackage =
        value.unit.packageName.isEmpty() ? "System" : value.unit.packageName + ".System";
    if (sourceType(samePackage) != null) return false;
    for (JavaSyntax.Type scope = value.ownerType; scope != null; scope = scope.owner)
      if (scope.name.equals("System") || sourceType(scope.qualifiedName + ".System") != null)
        return false;
    return true;
  }

  /** Only a complete, side-effect-free source constructor supplies object field identities. */
  private BusinessFlow.Expr constructorValue(Method method) {
    if (!method.name.equals(method.owner.name)
        || !method.returnType.isEmpty()
        || method.rootNode == null
        || !markerOnly(method.owner)
        || method.owner.instanceInitializer != null
        || method.owner.staticInitializer != null) return null;
    BusinessFlow.Expr result = defaultFields(method.owner, method.node);
    for (Node field : method.owner.fields) {
      if (field.modifiers.contains("static")) continue;
      if (field.initializer != null) return null;
    }
    for (Node child : method.rootNode.children) {
      Node assignment = soleStatement(child);
      if (assignment == null || !assignment.kind.equals("ASSIGN") || !assignment.name.equals("="))
        return null;
      Node field = ownField(assignment.receiver, method);
      if (field == null) return null;
      BusinessFlow.Expr value = expression(assignment.initializer, 0);
      if (clockValue(assignment.initializer)) value = expr("UNKNOWN", assignment.initializer);
      else if (!value.kind.equals("NAME") && !value.kind.equals("LITERAL")) return null;
      if (value.kind.equals("NAME")) {
        boolean parameter = false;
        for (Param param : method.params) parameter |= key(param.node).equals(value.name);
        if (!parameter) return null;
      }
      result.members.put(field.name, value);
    }
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
    // Preserve a unique lexical target even when virtual dispatch remains a candidate. The caller
    // marks that binding uncertain; naming the candidate must not establish a trusted source/check.
    if (!edge.unknown && edge.targets.size() == 1)
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

  private static BusinessFlow.Stmt statement(String kind, Node node) {
    BusinessFlow.Stmt statement = new BusinessFlow.Stmt(kind);
    statement.path = node.unit.path;
    statement.line = node.line;
    return statement;
  }

  private static BusinessFlow.Expr expr(String kind, Node node) {
    BusinessFlow.Expr expression = new BusinessFlow.Expr(kind);
    expression.path = node.unit.path;
    expression.line = node.line;
    return expression;
  }

  private static final class Limit extends RuntimeException {
    private static final long serialVersionUID = 1L;
  }
}
