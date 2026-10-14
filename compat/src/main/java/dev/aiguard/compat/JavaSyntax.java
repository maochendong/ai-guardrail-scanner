package dev.aiguard.compat;

import dev.aiguard.compat.grammar.JavaLexer;
import dev.aiguard.compat.grammar.JavaParser;
import java.util.*;
import org.antlr.v4.runtime.*;
import org.antlr.v4.runtime.tree.ParseTree;

/** Bounded syntax IR; none of the source-valued fields belong in exported evidence. */
public final class JavaSyntax {
  private JavaSyntax() {}

  public static final class Unit {
    public final String path, packageName;
    public Node root;
    public final List<Type> types = new ArrayList<Type>();
    public final List<Method> methods = new ArrayList<Method>();
    public final Map<String, List<String>> imports = new LinkedHashMap<String, List<String>>();
    public final List<String> wildcardImports = new ArrayList<String>(),
        staticImports = new ArrayList<String>();
    public final List<Map<String, Object>> diagnostics = new ArrayList<Map<String, Object>>();
    public int syntaxErrors;

    Unit(String path, String packageName) {
      this.path = path;
      this.packageName = packageName;
    }
  }

  public static final class Node {
    public final String kind;
    public String name = "", type = "", literalValue;
    public final int line, start, end;
    public final Unit unit;
    public Node parent, receiver, decl, initializer, condition, thenBranch, elseBranch, collection;
    public Method method;
    public Type ownerType;
    public final List<Node> args = new ArrayList<Node>(), children = new ArrayList<Node>();
    public final List<Param> params = new ArrayList<Param>();
    public final Set<String> modifiers = new LinkedHashSet<String>(),
        annotations = new LinkedHashSet<String>();

    Node(String kind, ParserRuleContext context, Unit unit) {
      this.kind = kind;
      this.unit = unit;
      this.line = context.getStart().getLine();
      this.start = context.getStart().getStartIndex();
      this.end = context.getStop() == null ? start : context.getStop().getStopIndex() + 1;
    }

    public List<Node> find(String kind) {
      return JavaSyntax.find(this, kind);
    }
  }

  public static final class Param {
    public final String name, type;
    public final Node node;

    Param(String name, String type, Node node) {
      this.name = name;
      this.type = type;
      this.node = node;
    }
  }

  public static final class Method {
    public final Type owner;
    public final String name, returnType;
    public final int line;
    public final Node node;
    public Node rootNode;
    public final List<Param> params = new ArrayList<Param>();
    public final Set<String> annotations = new LinkedHashSet<String>(),
        modifiers = new LinkedHashSet<String>();

    Method(Type owner, String name, String returnType, Node node) {
      this.owner = owner;
      this.name = name;
      this.returnType = returnType;
      this.node = node;
      this.line = node.line;
    }

    public String id() {
      return node.unit.path + ":" + node.start + ":" + owner.qualifiedName + "." + name;
    }
  }

  public static final class Type {
    public final String name, qualifiedName, kind;
    public final Type owner;
    public final Node node;
    public final List<String> superTypes = new ArrayList<String>();
    public final List<Node> fields = new ArrayList<Node>();
    public final List<Param> recordComponents = new ArrayList<Param>();
    public final List<Method> methods = new ArrayList<Method>();
    public final Set<String> modifiers = new LinkedHashSet<String>(),
        annotations = new LinkedHashSet<String>();

    Type(String name, String qualifiedName, String kind, Type owner, Node node) {
      this.name = name;
      this.qualifiedName = qualifiedName;
      this.kind = kind;
      this.owner = owner;
      this.node = node;
    }
  }

  public static Unit parse(SourceFile file, Cancel cancel) {
    cancel.check();
    final ErrorCounter errors = new ErrorCounter();
    final Cancel stop = cancel;
    JavaLexer lexer =
        new JavaLexer(new ANTLRInputStream(file.content)) {
          int tokens;

          @Override
          public Token nextToken() {
            stop.check();
            if (++tokens > 200000) throw new Budget();
            return super.nextToken();
          }
        };
    lexer.removeErrorListeners();
    lexer.addErrorListener(errors);
    CommonTokenStream tokens =
        new CommonTokenStream(lexer) {
          int operations;

          @Override
          public Token LT(int k) {
            if ((++operations & 1023) == 0) stop.check();
            if (operations > 20000000) throw new Budget();
            return super.LT(k);
          }
        };
    JavaParser parser = new JavaParser(tokens);
    parser.removeErrorListeners();
    parser.addErrorListener(errors);
    Unit unit = null;
    try {
      ParserRuleContext tree = parser.compilationunit();
      String pkg = "";
      ParserRuleContext declaration = child(tree, "packageDeclaration");
      if (declaration != null) {
        ParserRuleContext q = child(declaration, "qualifiedName");
        if (q != null) pkg = q.getText();
      }
      unit = new Unit(file.path, pkg);
      unit.syntaxErrors = errors.count;
      if (errors.count > 0) {
        diagnostic(
            unit,
            "JAVA_PARSE_ERROR",
            "Java syntax could not be parsed; no partial syntax is assessed.");
        return unit;
      }
      for (ParserRuleContext imp : children(tree, "importDeclaration")) {
        String qualified = child(imp, "qualifiedName").getText();
        if (direct(imp, "static"))
          unit.staticImports.add(qualified + (direct(imp, "*") ? ".*" : ""));
        else if (direct(imp, "*")) unit.wildcardImports.add(qualified);
        else {
          String simple = qualified.substring(qualified.lastIndexOf('.') + 1);
          List<String> existing = unit.imports.get(simple);
          if (existing == null) {
            existing = new ArrayList<String>();
            unit.imports.put(simple, existing);
          }
          existing.add(qualified);
        }
      }
      Builder builder = new Builder(unit, cancel);
      unit.root = builder.node("UNIT", tree, null, null);
      builder.populate(tree, unit.root, null, null, 0);
      return unit;
    } catch (Budget exhausted) {
      if (unit == null) unit = new Unit(file.path, "");
      unit.types.clear();
      unit.methods.clear();
      unit.root = null;
      unit.syntaxErrors++;
      diagnostic(
          unit,
          "JAVA_SYNTAX_BUDGET",
          "Java syntax analysis reached its token, operation or tree budget; no partial syntax is"
              + " assessed.");
      return unit;
    } catch (StackOverflowError exhausted) {
      if (unit == null) unit = new Unit(file.path, "");
      unit.types.clear();
      unit.methods.clear();
      unit.root = null;
      unit.syntaxErrors++;
      diagnostic(
          unit,
          "JAVA_SYNTAX_DEPTH",
          "Java syntax exceeded the supported nesting depth; no partial syntax is assessed.");
      return unit;
    }
  }

  public static List<Node> find(Node root, String kind) {
    List<Node> result = new ArrayList<Node>();
    if (root == null) return result;
    ArrayDeque<Node> stack = new ArrayDeque<Node>();
    stack.push(root);
    while (!stack.isEmpty()) {
      Node n = stack.pop();
      if (kind == null || kind.equals(n.kind)) result.add(n);
      for (int i = n.children.size() - 1; i >= 0; i--) stack.push(n.children.get(i));
    }
    return result;
  }

  public static String name(Node node) {
    if (node == null) return "";
    if ("NAME".equals(node.kind)) return node.name;
    if ("FIELD".equals(node.kind) && node.receiver != null) {
      String before = name(node.receiver);
      return before.length() == 0 ? "" : before + "." + node.name;
    }
    return "";
  }

  public static boolean contains(Node parent, Node child) {
    while (child != null) {
      if (child == parent) return true;
      child = child.parent;
    }
    return false;
  }

  private static final class ErrorCounter extends BaseErrorListener {
    int count;

    @Override
    public void syntaxError(
        Recognizer<?, ?> recognizer,
        Object symbol,
        int line,
        int column,
        String message,
        RecognitionException exception) {
      count++;
    }
  }

  private static final class Budget extends RuntimeException {
    private static final long serialVersionUID = 1L;
  }

  private static void diagnostic(Unit unit, String code, String message) {
    Map<String, Object> d = new LinkedHashMap<String, Object>();
    d.put("code", code);
    d.put("path", unit.path);
    d.put("message", message);
    unit.diagnostics.add(d);
  }

  private static String rule(ParseTree tree) {
    return tree instanceof ParserRuleContext
        ? JavaParser.ruleNames[((ParserRuleContext) tree).getRuleIndex()]
        : "";
  }

  private static ParserRuleContext child(ParseTree tree, String name) {
    for (int i = 0; i < tree.getChildCount(); i++) {
      ParseTree c = tree.getChild(i);
      if (rule(c).equals(name)) return (ParserRuleContext) c;
    }
    return null;
  }

  private static List<ParserRuleContext> children(ParseTree tree, String name) {
    List<ParserRuleContext> out = new ArrayList<ParserRuleContext>();
    for (int i = 0; i < tree.getChildCount(); i++) {
      ParseTree c = tree.getChild(i);
      if (rule(c).equals(name)) out.add((ParserRuleContext) c);
    }
    return out;
  }

  private static boolean direct(ParseTree tree, String text) {
    for (int i = 0; i < tree.getChildCount(); i++)
      if (!(tree.getChild(i) instanceof ParserRuleContext)
          && tree.getChild(i).getText().equals(text)) return true;
    return false;
  }

  private static String text(ParseTree tree, String child) {
    ParserRuleContext c = child(tree, child);
    return c == null ? "" : c.getText();
  }

  private static List<ParserRuleContext> descendants(ParseTree root, String name) {
    List<ParserRuleContext> result = new ArrayList<ParserRuleContext>();
    ArrayDeque<ParseTree> queue = new ArrayDeque<ParseTree>();
    queue.push(root);
    while (!queue.isEmpty()) {
      ParseTree next = queue.pop();
      if (rule(next).equals(name)) result.add((ParserRuleContext) next);
      for (int i = next.getChildCount() - 1; i >= 0; i--) queue.push(next.getChild(i));
    }
    return result;
  }

  private static final class Builder {
    final Unit unit;
    final Cancel cancel;
    int nodes;

    Builder(Unit unit, Cancel cancel) {
      this.unit = unit;
      this.cancel = cancel;
    }

    Node node(String kind, ParserRuleContext context, Type owner, Method method) {
      cancel.check();
      if (++nodes > 100000) throw new Budget();
      Node n = new Node(kind, context, unit);
      n.ownerType = owner;
      n.method = method;
      return n;
    }

    void attach(Node parent, Node child) {
      if (parent != null && child != null) {
        parent.children.add(child);
        child.parent = parent;
      }
    }

    void populate(ParserRuleContext context, Node parent, Type owner, Method method, int depth) {
      cancel.check();
      if (depth > 256) throw new Budget();
      for (int i = 0; i < context.getChildCount(); i++)
        if (context.getChild(i) instanceof ParserRuleContext)
          build((ParserRuleContext) context.getChild(i), parent, owner, method, depth + 1);
    }

    Node build(ParserRuleContext context, Node parent, Type owner, Method method, int depth) {
      cancel.check();
      if (depth > 256) throw new Budget();
      String r = rule(context);
      if (r.equals("classDeclaration")
          || r.equals("interfaceDeclaration")
          || r.equals("enumDeclaration")
          || r.equals("recordDeclaration")) return type(context, parent, owner, method, depth);
      if (r.equals("methodDeclaration")
          || r.equals("interfaceCommonBodyDeclaration")
          || r.equals("constructorDeclaration")
          || r.equals("compactConstructorDeclaration"))
        return method(context, parent, owner, depth);
      if (r.equals("fieldDeclaration")
          || r.equals("localVariableDeclaration")
          || r.equals("resource")
          || r.equals("enhancedForControl")) {
        variables(context, parent, owner, method, depth);
        return null;
      }
      if (r.equals("block")) {
        Node n = node("BLOCK", context, owner, method);
        attach(parent, n);
        populate(context, n, owner, method, depth + 1);
        return n;
      }
      if (r.equals("statement")) return statement(context, parent, owner, method, depth);
      if (r.equals("expression")) {
        Node n = expr(context, owner, method, depth);
        attach(parent, n);
        return n;
      }
      if (r.equals("switchExpression")) {
        Node n = switchNode(context, owner, method, depth);
        attach(parent, n);
        return n;
      }
      if (r.equals("catchClause") || r.equals("finallyBlock")) {
        Node n = node(r.equals("catchClause") ? "CATCH" : "FINALLY", context, owner, method);
        attach(parent, n);
        if (r.equals("catchClause")) {
          Node p = node("PARAM", context, owner, method);
          p.name = text(context, "identifier");
          p.type = text(context, "catchType");
          p.decl = p;
          attach(n, p);
          n.params.add(new Param(p.name, p.type, p));
        }
        populate(context, n, owner, method, depth + 1);
        return n;
      }
      if (r.equals("annotation")
          || r.equals("formalParameters")
          || r.equals("recordHeader")
          || r.equals("packageDeclaration")
          || r.equals("importDeclaration")) return null;
      populate(context, parent, owner, method, depth + 1);
      return null;
    }

    Node type(ParserRuleContext context, Node parent, Type outer, Method enclosing, int depth) {
      String name = text(context, "identifier");
      String kind = rule(context).replace("Declaration", "").toUpperCase(Locale.ROOT);
      Node n = node("TYPE", context, outer, enclosing);
      n.name = name;
      String qualified =
          outer == null
              ? (unit.packageName.length() == 0 ? name : unit.packageName + "." + name)
              : outer.qualifiedName + "." + name;
      Type type = new Type(name, qualified, kind, outer, n);
      n.ownerType = type;
      unit.types.add(type);
      attach(parent, n);
      modifiers(context, type.modifiers, type.annotations);
      n.modifiers.addAll(type.modifiers);
      n.annotations.addAll(type.annotations);
      for (ParserRuleContext superType : children(context, "typeType"))
        type.superTypes.add(superType.getText());
      for (ParserRuleContext list : children(context, "typeList"))
        for (ParserRuleContext superType : children(list, "typeType"))
          type.superTypes.add(superType.getText());
      ParserRuleContext recordHeader = child(context, "recordHeader");
      if (recordHeader != null)
        for (ParserRuleContext component : descendants(recordHeader, "recordComponent")) {
          Node p = node("FIELD", component, type, null);
          p.name = text(component, "identifier");
          p.type = text(component, "typeType") + (direct(component, "...") ? "[]" : "");
          p.decl = p;
          attach(n, p);
          type.fields.add(p);
          type.recordComponents.add(new Param(p.name, p.type, p));
        }
      populate(context, n, type, null, depth + 1);
      return n;
    }

    Node method(ParserRuleContext context, Node parent, Type owner, int depth) {
      if (owner == null) {
        populate(context, parent, owner, null, depth + 1);
        return null;
      }
      Node n = node("METHOD", context, owner, null);
      n.name = text(context, "identifier");
      n.type = text(context, "typeTypeOrVoid");
      if (rule(context).contains("Constructor") || rule(context).equals("constructorDeclaration"))
        n.type = "";
      Method method = new Method(owner, n.name, n.type, n);
      n.method = method;
      unit.methods.add(method);
      owner.methods.add(method);
      attach(parent, n);
      modifiers(context, method.modifiers, method.annotations);
      n.modifiers.addAll(method.modifiers);
      n.annotations.addAll(method.annotations);
      ParserRuleContext formal = child(context, "formalParameters");
      if (formal != null)
        for (ParserRuleContext p : descendants(formal, "formalParameter")) {
          Node pn = parameter(p, owner, method);
          attach(n, pn);
          method.params.add(new Param(pn.name, pn.type, pn));
        }
      if (formal != null)
        for (ParserRuleContext p : descendants(formal, "lastFormalParameter")) {
          if (child(p, "formalParameter") != null) continue;
          Node pn = parameter(p, owner, method);
          pn.type += "[]";
          attach(n, pn);
          method.params.add(new Param(pn.name, pn.type, pn));
        }
      ParserRuleContext body = child(context, "methodBody");
      if (body == null) body = child(context, "block");
      if (body != null) {
        Node before = null;
        if (rule(body).equals("block")) before = build(body, n, owner, method, depth + 1);
        else {
          ParserRuleContext block = child(body, "block");
          if (block != null) before = build(block, n, owner, method, depth + 1);
        }
        method.rootNode = before;
      }
      return n;
    }

    Node parameter(ParserRuleContext context, Type owner, Method method) {
      Node n = node("PARAM", context, owner, method);
      n.type = text(context, "typeType");
      ParserRuleContext id = child(context, "variableDeclaratorId");
      n.name = id == null ? text(context, "identifier") : text(id, "identifier");
      if (direct(context, "...")) n.type += "[]";
      n.decl = n;
      return n;
    }

    void variables(ParserRuleContext context, Node parent, Type owner, Method method, int depth) {
      String type = text(context, "typeType");
      if (type.length() == 0) type = text(context, "classOrInterfaceType");
      if (type.length() == 0 && direct(context, "var")) type = "var";
      String kind = rule(context).equals("fieldDeclaration") ? "FIELD" : "VAR";
      List<ParserRuleContext> declarations = new ArrayList<ParserRuleContext>();
      ParserRuleContext all = child(context, "variableDeclarators");
      if (all != null) declarations.addAll(children(all, "variableDeclarator"));
      else declarations.add(context);
      for (ParserRuleContext declaration : declarations) {
        ParserRuleContext id = child(declaration, "variableDeclaratorId");
        String name = id == null ? text(declaration, "identifier") : text(id, "identifier");
        if (name.length() == 0) continue;
        Node n = node(kind, declaration, owner, method);
        n.name = name;
        n.type = type;
        n.decl = n;
        attach(parent, n);
        if (id != null && id.getText().endsWith("[]")) n.type += "[]";
        ParserRuleContext init = child(declaration, "variableInitializer");
        ParserRuleContext value =
            init == null ? child(declaration, "expression") : child(init, "expression");
        if (value != null && rule(context).equals("enhancedForControl")) {
          n.collection = expr(value, owner, method, depth + 1);
          attach(n, n.collection);
        } else if (value != null) {
          n.initializer = expr(value, owner, method, depth + 1);
          attach(n, n.initializer);
        } else if (init != null) {
          Node unknown = node("UNKNOWN", init, owner, method);
          attach(n, unknown);
          populate(init, unknown, owner, method, depth + 1);
          n.initializer = unknown;
        }
        if (kind.equals("FIELD") && owner != null) {
          owner.fields.add(n);
          modifiers(context, n.modifiers, n.annotations);
        }
      }
    }

    Node statement(ParserRuleContext context, Node parent, Type owner, Method method, int depth) {
      ParserRuleContext block = child(context, "block");
      if (block != null && context.getChildCount() == 1)
        return build(block, parent, owner, method, depth + 1);
      String kind =
          direct(context, "if")
              ? "IF"
              : direct(context, "return")
                  ? "RETURN"
                  : direct(context, "throw")
                      ? "THROW"
                      : direct(context, "try")
                          ? "TRY"
                          : direct(context, "switch")
                              ? "SWITCH"
                              : direct(context, "for")
                                  ? "FOR"
                                  : direct(context, "while") || direct(context, "do")
                                      ? "LOOP"
                                      : "EXPR_STMT";
      Node n = node(kind, context, owner, method);
      attach(parent, n);
      List<ParserRuleContext> expressions = children(context, "expression");
      for (ParserRuleContext e : expressions) {
        Node expression = expr(e, owner, method, depth + 1);
        attach(n, expression);
        n.args.add(expression);
        if (n.condition == null
            && (kind.equals("IF")
                || kind.equals("FOR")
                || kind.equals("LOOP")
                || kind.equals("SWITCH"))) n.condition = expression;
      }
      List<ParserRuleContext> statements = children(context, "statement");
      for (int i = 0; i < statements.size(); i++) {
        Node branch = statement(statements.get(i), n, owner, method, depth + 1);
        if (kind.equals("IF")) {
          if (i == 0) n.thenBranch = branch;
          else n.elseBranch = branch;
        }
      }
      for (int i = 0; i < context.getChildCount(); i++)
        if (context.getChild(i) instanceof ParserRuleContext) {
          ParserRuleContext c = (ParserRuleContext) context.getChild(i);
          String r = rule(c);
          if (r.equals("expression") || r.equals("statement")) continue;
          if (r.equals("switchBlockStatementGroup") || r.equals("switchLabel"))
            switchCase(c, n, owner, method, depth + 1);
          else build(c, n, owner, method, depth + 1);
        }
      return n;
    }

    Node expr(ParserRuleContext context, Type owner, Method method, int depth) {
      cancel.check();
      if (depth > 256) throw new Budget();
      String label = context.getClass().getSimpleName();
      List<ParserRuleContext> expressions = children(context, "expression");
      if (label.equals("PrimaryExpressionContext")) {
        ParserRuleContext p = child(context, "primary");
        ParserRuleContext enclosed = child(p, "expression");
        if (enclosed != null) {
          Node n = node("PAREN", context, owner, method);
          addArg(n, expr(enclosed, owner, method, depth + 1));
          return n;
        }
        ParserRuleContext literal = child(p, "literal");
        if (literal != null) {
          Node n = node("LITERAL", context, owner, method);
          String raw = literal.getText();
          n.literalValue = literal(raw);
          n.type =
              raw.startsWith("\"")
                  ? "java.lang.String"
                  : raw.startsWith("'")
                      ? "char"
                      : raw.equals("true") || raw.equals("false")
                          ? "boolean"
                          : raw.equals("null")
                              ? "null"
                              : raw.endsWith("L") || raw.endsWith("l")
                                  ? "long"
                                  : raw.indexOf('.') >= 0 ? "double" : "int";
          return n;
        }
        if (direct(p, "class")) {
          Node n = node("CLASS", context, owner, method);
          n.type = text(p, "typeTypeOrVoid");
          return n;
        }
        Node n = node("NAME", context, owner, method);
        n.name = text(p, "identifier");
        if (n.name.length() == 0)
          n.name = direct(p, "this") ? "this" : direct(p, "super") ? "super" : "";
        if (n.name.length() == 0) {
          n = node("UNKNOWN", context, owner, method);
          populate(p, n, owner, method, depth + 1);
        }
        return n;
      }
      if (label.equals("MethodCallExpressionContext"))
        return call(child(context, "methodCall"), context, null, owner, method, depth);
      if (label.equals("MemberReferenceExpressionContext")) {
        Node receiver = expr(expressions.get(0), owner, method, depth + 1);
        ParserRuleContext c = child(context, "methodCall");
        if (c != null) return call(c, context, receiver, owner, method, depth);
        Node n = node("FIELD", context, owner, method);
        n.name = text(context, "identifier");
        n.receiver = receiver;
        attach(n, receiver);
        if (n.name.length() == 0) {
          n.name = direct(context, "this") ? "this" : "";
          if (n.name.length() == 0) {
            n.name = "<unsupported>";
            for (ParserRuleContext generic : children(context, "explicitGenericInvocation"))
              populate(generic, n, owner, method, depth + 1);
          }
        }
        return n;
      }
      if (label.equals("ObjectCreationExpressionContext")) {
        ParserRuleContext creator = child(context, "creator");
        Node n = node("NEW", context, owner, method);
        n.type = text(creator, "createdName");
        ParserRuleContext rest = child(creator, "classCreatorRest");
        if (rest != null) {
          arguments(child(rest, "arguments"), n, owner, method, depth + 1);
          ParserRuleContext body = child(rest, "classBody");
          if (body != null) {
            Node typeNode = node("TYPE", body, owner, method);
            String name = "$anonymous" + n.start;
            Type anonymous =
                new Type(
                    name,
                    owner == null ? name : owner.qualifiedName + "." + name,
                    "ANONYMOUS",
                    owner,
                    typeNode);
            typeNode.ownerType = anonymous;
            anonymous.superTypes.add(n.type);
            unit.types.add(anonymous);
            attach(n, typeNode);
            populate(body, typeNode, anonymous, null, depth + 1);
            n.modifiers.add("anonymous");
          }
        } else {
          ParserRuleContext array = child(creator, "arrayCreatorRest");
          if (array != null) populate(array, n, owner, method, depth + 1);
        }
        return n;
      }
      if (label.equals("ExpressionLambdaContext")) {
        ParserRuleContext lambda = child(context, "lambdaExpression");
        Node n = node("LAMBDA", context, owner, method);
        ParserRuleContext params = child(lambda, "lambdaParameters");
        for (ParserRuleContext p : descendants(params, "formalParameter")) {
          Node parameter = parameter(p, owner, method);
          attach(n, parameter);
          n.params.add(new Param(parameter.name, parameter.type, parameter));
        }
        if (n.params.isEmpty())
          for (ParserRuleContext p : children(params, "identifier")) {
            Node parameter = node("PARAM", p, owner, method);
            parameter.name = p.getText();
            parameter.decl = parameter;
            attach(n, parameter);
            n.params.add(new Param(parameter.name, "", parameter));
          }
        ParserRuleContext body = child(lambda, "lambdaBody");
        populate(body, n, owner, method, depth + 1);
        return n;
      }
      if (label.equals("ExpressionSwitchContext"))
        return switchNode(child(context, "switchExpression"), owner, method, depth + 1);
      String kind =
          label.equals("CastExpressionContext")
              ? "CAST"
              : label.equals("TernaryExpressionContext")
                  ? "CONDITIONAL"
                  : label.equals("SquareBracketExpressionContext")
                      ? "ARRAY_ACCESS"
                      : label.equals("MethodReferenceExpressionContext")
                          ? "METHOD_REF"
                          : label.equals("UnaryOperatorExpressionContext")
                                  || label.equals("PostIncrementDecrementOperatorExpressionContext")
                              ? "UNARY"
                              : label.equals("BinaryOperatorExpressionContext")
                                  ? "BINARY"
                                  : "UNKNOWN";
      Node n = node(kind, context, owner, method);
      if (kind.equals("CAST")) n.type = text(context, "typeType");
      for (int i = 0; i < context.getChildCount(); i++)
        if (!(context.getChild(i) instanceof ParserRuleContext)) {
          String token = context.getChild(i).getText();
          if (!token.equals("(") && !token.equals(")") && !token.equals("[") && !token.equals("]"))
            n.name += token;
        }
      if (kind.equals("BINARY")
          && Arrays.asList(
                  "=", "+=", "-=", "*=", "/=", "&=", "|=", "^=", ">>=", ">>>=", "<<=", "%=")
              .contains(n.name)) {
        Node assignment = node("ASSIGN", context, owner, method);
        assignment.name = n.name;
        n = assignment;
      }
      for (ParserRuleContext e : expressions) addArg(n, expr(e, owner, method, depth + 1));
      if (kind.equals("METHOD_REF")) {
        n.name = text(context, "identifier");
        if (!n.args.isEmpty()) n.receiver = n.args.get(0);
      }
      if (kind.equals("ARRAY_ACCESS") && !n.args.isEmpty()) n.receiver = n.args.get(0);
      if (n.kind.equals("ASSIGN") && !n.args.isEmpty()) {
        n.receiver = n.args.get(0);
        if (n.args.size() > 1) n.initializer = n.args.get(1);
      }
      return n;
    }

    Node call(
        ParserRuleContext context,
        ParserRuleContext span,
        Node receiver,
        Type owner,
        Method method,
        int depth) {
      Node n = node("CALL", span, owner, method);
      n.name = text(context, "identifier");
      if (n.name.length() == 0) n.name = direct(context, "this") ? "this" : "super";
      n.receiver = receiver;
      attach(n, receiver);
      arguments(child(context, "arguments"), n, owner, method, depth + 1);
      return n;
    }

    void arguments(ParserRuleContext context, Node n, Type owner, Method method, int depth) {
      if (context == null) return;
      ParserRuleContext list = child(context, "expressionList");
      if (list != null)
        for (ParserRuleContext argument : children(list, "expression"))
          addArg(n, expr(argument, owner, method, depth + 1));
    }

    void addArg(Node n, Node argument) {
      n.args.add(argument);
      attach(n, argument);
    }

    Node switchNode(ParserRuleContext context, Type owner, Method method, int depth) {
      Node n = node("SWITCH", context, owner, method);
      ParserRuleContext selector = child(context, "expression");
      if (selector != null) {
        n.condition = expr(selector, owner, method, depth + 1);
        attach(n, n.condition);
      }
      for (ParserRuleContext c : children(context, "switchLabeledRule"))
        switchCase(c, n, owner, method, depth + 1);
      return n;
    }

    void switchCase(ParserRuleContext context, Node parent, Type owner, Method method, int depth) {
      Node n = node("CASE", context, owner, method);
      n.name = direct(context, "default") ? "default" : "case";
      attach(parent, n);
      for (ParserRuleContext label : children(context, "switchLabel")) {
        if (direct(label, "default")) n.name = "default";
        ParserRuleContext value = child(label, "expression");
        if (value != null) addArg(n, expr(value, owner, method, depth + 1));
      }
      ParserRuleContext list = child(context, "expressionList");
      if (list != null)
        for (ParserRuleContext value : children(list, "expression"))
          addArg(n, expr(value, owner, method, depth + 1));
      for (int i = 0; i < context.getChildCount(); i++)
        if (context.getChild(i) instanceof ParserRuleContext) {
          ParserRuleContext child = (ParserRuleContext) context.getChild(i);
          if (!rule(child).equals("switchLabel") && !rule(child).equals("expressionList"))
            build(child, n, owner, method, depth + 1);
        }
    }

    void modifiers(ParserRuleContext context, Set<String> modifiers, Set<String> annotations) {
      ParserRuleContext current = context;
      for (int level = 0; current != null && level < 4; level++, current = current.getParent()) {
        String r = rule(current);
        if (level > 0
            && (r.equals("classBody")
                || r.equals("interfaceBody")
                || r.equals("recordBody")
                || r.equals("compilationunit"))) break;
        for (int i = 0; i < current.getChildCount(); i++) {
          ParseTree child = current.getChild(i);
          String cr = rule(child);
          if (cr.equals("modifier")
              || cr.equals("classOrInterfaceModifier")
              || cr.equals("interfaceMethodModifier")
              || cr.equals("annotation")) {
            for (ParserRuleContext annotation : descendants(child, "annotation")) {
              ParserRuleContext name = child(annotation, "qualifiedName");
              if (name != null) annotations.add(name.getText());
            }
            String raw = child.getText();
            if (!raw.startsWith("@")) modifiers.add(raw);
          }
        }
      }
    }
  }

  private static String literal(String raw) {
    if (!(raw.startsWith("\"") || raw.startsWith("'"))) return raw;
    int border = raw.startsWith("\"\"\"") ? 3 : 1;
    if (raw.length() < border * 2) return "";
    String value = raw.substring(border, raw.length() - border);
    StringBuilder out = new StringBuilder();
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      if (c != '\\' || i + 1 >= value.length()) {
        out.append(c);
        continue;
      }
      char next = value.charAt(++i);
      switch (next) {
        case 'n':
          out.append('\n');
          break;
        case 'r':
          out.append('\r');
          break;
        case 't':
          out.append('\t');
          break;
        case 'b':
          out.append('\b');
          break;
        case 'f':
          out.append('\f');
          break;
        case 'u':
          while (i + 1 < value.length() && value.charAt(i + 1) == 'u') i++;
          if (i + 4 < value.length()) {
            try {
              out.append((char) Integer.parseInt(value.substring(i + 1, i + 5), 16));
              i += 4;
            } catch (NumberFormatException bad) {
              out.append('u');
            }
          }
          break;
        default:
          out.append(next);
      }
    }
    return out.toString();
  }
}
