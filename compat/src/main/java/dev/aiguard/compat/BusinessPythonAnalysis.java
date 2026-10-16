package dev.aiguard.compat;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.antlr.v4.runtime.ParserRuleContext;
import org.antlr.v4.runtime.tree.ParseTree;

/** Conservative Python syntax adapter; it never imports or executes the inspected application. */
public final class BusinessPythonAnalysis {
  private BusinessPythonAnalysis() {}

  public static BusinessFlow.Program adapt(List<SourceFile> files, Cancel cancel) {
    return adapt(files, cancel, BusinessPolicy.generic());
  }

  public static BusinessFlow.Program adapt(
      List<SourceFile> files, Cancel cancel, BusinessPolicy policy) {
    return adapt(files, cancel, policy, new PythonSyntax.Cache());
  }

  public static BusinessFlow.Program adapt(
      List<SourceFile> files, Cancel cancel, BusinessPolicy policy, PythonSyntax.Cache syntax) {
    BusinessFlow.Program program = new BusinessFlow.Program();
    boolean standardJsonUnambiguous = true;
    for (SourceFile file : files) {
      cancel.check();
      String path = file.path.replace('\\', '/');
      // Source roots and PYTHONPATH are operator-controlled. Any scanned namesake may
      // shadow the standard library, so do not guess which root wins import resolution.
      if (path.equals("json.py")
          || path.endsWith("/json.py")
          || path.equals("json/__init__.py")
          || path.endsWith("/json/__init__.py")) standardJsonUnambiguous = false;
    }
    for (SourceFile file : files) {
      cancel.check();
      new Adapter(file, cancel, program, policy, standardJsonUnambiguous)
          .parse(syntax.parse(file, cancel));
    }
    return program;
  }

  private static final class Limit extends RuntimeException {
    private static final long serialVersionUID = 1L;
  }

  private static final class Scope {
    final Map<String, String> imports = new LinkedHashMap<String, String>();
    final Map<String, Integer> importAt = new HashMap<String, Integer>();
    final Map<String, String> instances = new LinkedHashMap<String, String>();
    final Map<String, Integer> assignments = new HashMap<String, Integer>();
    final Set<String> blocked = new HashSet<String>();
    final Set<String> mutated = new HashSet<String>();
    final Set<String> rebound = new HashSet<String>();
    final Map<String, LocalFunction> localFunctions = new LinkedHashMap<String, LocalFunction>();
    String owner = "", receiverName = "";
    boolean opaque;
  }

  private static final class LocalFunction {
    String id;
    int at;
    final List<String> parameters = new ArrayList<String>();
  }

  private static final class Adapter {
    final SourceFile file;
    final Cancel cancel;
    final BusinessFlow.Program program;
    final BusinessPolicy policy;
    final boolean standardJsonUnambiguous;
    final List<BusinessFlow.Function> functions = new ArrayList<BusinessFlow.Function>();
    int visits;
    boolean unsupported;

    Adapter(
        SourceFile file,
        Cancel cancel,
        BusinessFlow.Program program,
        BusinessPolicy policy,
        boolean standardJsonUnambiguous) {
      this.file = file;
      this.cancel = cancel;
      this.program = program;
      this.policy = policy;
      this.standardJsonUnambiguous = standardJsonUnambiguous;
    }

    void check(int depth) {
      cancel.check();
      if (depth > 160 || ++visits > 300000) throw new Limit();
    }

    void parse(PythonSyntax.Unit syntax) {
      if (syntax.tree == null) {
        parseFailure(syntax.failureReason);
        return;
      }
      try {
        ParserRuleContext tree = syntax.tree;
        Scope module = scope(tree, null, null);
        indexLocalFunctions(tree, module);
        BusinessFlow.Function top = function(moduleName(file.path) + ".<module>", tree);
        top.executionUncertain = module.opaque;
        statements(tree, module, top.body, 0);
        functions.add(top);
        definitions(tree, module, moduleName(file.path), 0, false, "");
        program.functions.addAll(functions);
        if (unsupported)
          diagnostic(
              "BANK_PYTHON_UNSUPPORTED_FLOW",
              "Unsupported Python flow or dynamic binding remains unknown in the bank adapter.");
      } catch (Limit limit) {
        parseFailure("LIMIT");
      } catch (StackOverflowError error) {
        parseFailure("DEPTH");
      }
    }

    void parseFailure(String reason) {
      program.incompletePaths.add(file.path);
      if ("SYNTAX".equals(reason))
        diagnostic(
            "BANK_PYTHON_PARSE_FAILED",
            "Python syntax failed; bank flow for this file was discarded.");
      else if ("LIMIT".equals(reason))
        diagnostic(
            "BANK_PYTHON_ANALYSIS_LIMIT",
            "Python bank flow exceeded its bounded analysis budget; this file was discarded.");
      else
        diagnostic(
            "BANK_PYTHON_ANALYSIS_DEPTH",
            "Python bank flow exceeded supported nesting; this file was discarded.");
    }

    void diagnostic(String code, String message) {
      Map<String, Object> diagnostic = Findings.diagnostic(code, file.path, message);
      // Unknown statements, expressions and calls already carry uncertainty in the IR.
      // Their summary must not invalidate independent functions in this source file.
      if ("BANK_PYTHON_UNSUPPORTED_FLOW".equals(code)) diagnostic.put("flowScope", "local");
      program.diagnostics.add(diagnostic);
    }

    BusinessFlow.Function function(String symbol, ParserRuleContext node) {
      BusinessFlow.Function f = new BusinessFlow.Function();
      f.path = file.path;
      f.line = node.getStart().getLine();
      f.symbol = symbol;
      f.id = file.path + ":" + kind(node) + ":" + node.getStart().getTokenIndex();
      return f;
    }

    Scope scope(ParserRuleContext body, Scope outer, ParserRuleContext params) {
      Scope scope = new Scope();
      if (outer != null) {
        scope.imports.putAll(outer.imports);
        for (String name : outer.blocked) scope.imports.remove(name);
        for (String name : outer.mutated) scope.imports.remove(name);
        scope.opaque = outer.opaque;
        scope.localFunctions.putAll(outer.localFunctions);
      }
      bindings(body, scope, false, 0);
      if (params != null)
        for (ParserRuleContext p : descendants(params, "Tfpdef", 0))
          scope.blocked.add(text(direct(p, "Name")));
      for (String name : scope.blocked) scope.localFunctions.remove(name);
      for (String name : scope.mutated) scope.localFunctions.remove(name);
      for (String name : scope.rebound) scope.localFunctions.remove(name);
      if (scope.opaque) scope.localFunctions.clear();
      return scope;
    }

    /** Resolve only stable, same-file module declarations; never infer targets from API symbols. */
    void indexLocalFunctions(ParserRuleContext tree, Scope module) {
      if (module.opaque || dynamicBindings(tree, 0)) return;
      Map<String, LocalFunction> found = new LinkedHashMap<String, LocalFunction>();
      Set<String> rejected = new HashSet<String>();
      localDefinitions(tree, true, found, rejected, 0);
      for (Map.Entry<String, LocalFunction> entry : found.entrySet())
        if (!rejected.contains(entry.getKey())
            && !module.rebound.contains(entry.getKey())
            && !module.mutated.contains(entry.getKey()))
          module.localFunctions.put(entry.getKey(), entry.getValue());
    }

    boolean dynamicBindings(ParserRuleContext node, int depth) {
      check(depth);
      String k = kind(node);
      if ("Global_stmt".equals(k) || "Nonlocal_stmt".equals(k)) return true;
      if ("Import_from".equals(k) && has(node, "*")) return true;
      if ("Atom_expr".equals(k)) {
        String atom = text(direct(node, "Atom"));
        if ("exec".equals(atom)
            || "eval".equals(atom)
            || "globals".equals(atom)
            || "locals".equals(atom)) return true;
      }
      for (ParserRuleContext child : children(node))
        if (dynamicBindings(child, depth + 1)) return true;
      return false;
    }

    void localDefinitions(
        ParserRuleContext node,
        boolean unconditional,
        Map<String, LocalFunction> found,
        Set<String> rejected,
        int depth) {
      check(depth);
      String k = kind(node);
      if ("Classdef".equals(k)) {
        rejected.add(text(direct(node, "Name")));
        return;
      }
      if ("Funcdef".equals(k)) {
        String name = text(direct(node, "Name"));
        ParserRuleContext params = direct(node, "Parameters");
        ParserRuleContext typed = direct(params, "Typedargslist");
        LocalFunction target = new LocalFunction();
        target.id = file.path + ":" + kind(node) + ":" + node.getStart().getTokenIndex();
        target.at = node.getStart().getTokenIndex();
        boolean eligible =
            unconditional
                && !has(node, "->")
                && (typed == null || !has(typed, "=") && !has(typed, "*") && !has(typed, "**"))
                && !containsYield(direct(node, "Block"), 0);
        Set<String> names = new HashSet<String>();
        for (ParserRuleContext param : descendants(params, "Tfpdef", 0)) {
          String parameter = text(direct(param, "Name"));
          eligible &= identifier(parameter) && names.add(parameter) && !has(param, ":");
          target.parameters.add(parameter);
        }
        if (!eligible || found.containsKey(name)) rejected.add(name);
        found.put(name, target);
        return;
      }
      boolean declarationWrapper =
          "File_input".equals(k) || "Stmt".equals(k) || "Compound_stmt".equals(k);
      for (ParserRuleContext child : children(node))
        localDefinitions(child, unconditional && declarationWrapper, found, rejected, depth + 1);
    }

    boolean containsYield(ParserRuleContext node, int depth) {
      if (node == null) return false;
      check(depth);
      String k = kind(node);
      if ("Yield_expr".equals(k) || "Yield_stmt".equals(k)) return true;
      if ("Funcdef".equals(k) || "Classdef".equals(k)) return false;
      for (ParserRuleContext child : children(node))
        if (containsYield(child, depth + 1)) return true;
      return false;
    }

    void bindings(ParserRuleContext n, Scope s, boolean conditional, int depth) {
      check(depth);
      String k = kind(n);
      if ("Funcdef".equals(k) || "Classdef".equals(k)) {
        s.blocked.add(text(direct(n, "Name")));
        return;
      }
      if ("Import_name".equals(k)) {
        for (ParserRuleContext alias : descendants(n, "Dotted_as_name", 0)) {
          String imported = text(direct(alias, "Dotted_name"));
          String renamed = text(direct(alias, "Name"));
          String local = renamed.length() == 0 ? root(imported) : renamed;
          bindImport(
              s,
              local,
              renamed.length() == 0 ? root(imported) : imported,
              conditional,
              n.getStart().getTokenIndex());
        }
        return;
      }
      if ("Import_from".equals(k)) {
        boolean relative = n.getChildCount() > 1 && n.getChild(1).getText().startsWith(".");
        for (ParserRuleContext alias : descendants(n, "Import_as_name", 0)) {
          List<ParserRuleContext> names = directs(alias, "Name");
          if (!names.isEmpty()) {
            String local = text(names.get(names.size() - 1));
            bindImport(
                s,
                local,
                text(direct(n, "Dotted_name")) + "." + text(names.get(0)),
                conditional || relative,
                n.getStart().getTokenIndex());
          }
        }
        if (has(n, "*")) s.opaque = true;
        return;
      }
      if ("Expr_stmt".equals(k)) {
        List<ParserRuleContext> parts = directs(n, "Testlist_star_expr");
        if (parts.size() > 1 || direct(n, "Annassign") != null || direct(n, "Augassign") != null) {
          if (parts.size() == 2
              && identifier(text(parts.get(1)))
              && !text(parts.get(0)).equals(text(parts.get(1)))) s.mutated.add(text(parts.get(1)));
          int count = Math.max(1, parts.size() - 1);
          for (int i = 0; i < count && i < parts.size(); i++)
            bindTarget(parts.get(i), s, conditional, depth + 1);
        }
      }
      if ("For_stmt".equals(k)) bindTarget(direct(n, "Exprlist"), s, true, depth + 1);
      if ("With_item".equals(k) && has(n, "as")) bindTarget(direct(n, "Expr"), s, true, depth + 1);
      if ("Except_clause".equals(k)) {
        String name = text(direct(n, "Name"));
        if (name.length() > 0) {
          s.blocked.add(name);
          s.rebound.add(name);
        }
      }
      if ("Global_stmt".equals(k) || "Nonlocal_stmt".equals(k)) s.opaque = true;
      if ("Del_stmt".equals(k)) bindTarget(direct(n, "Exprlist"), s, true, depth + 1);
      if ("Atom_expr".equals(k)) {
        String atom = text(direct(n, "Atom"));
        if ("exec".equals(atom)
            || "eval".equals(atom)
            || "globals".equals(atom)
            || "locals".equals(atom)) s.opaque = true;
        if ("setattr".equals(atom) || "delattr".equals(atom)) {
          List<ParserRuleContext> args = descendants(n, "Argument", 0);
          if (!args.isEmpty()) s.mutated.add(root(text(args.get(0))));
        }
      }
      boolean branch =
          conditional
              || "If_stmt".equals(k)
              || "Try_stmt".equals(k)
              || "For_stmt".equals(k)
              || "While_stmt".equals(k)
              || "With_stmt".equals(k)
              || "Match_stmt".equals(k)
              || "Lambdef".equals(k);
      for (ParserRuleContext child : children(n)) bindings(child, s, branch, depth + 1);
    }

    void bindImport(Scope scope, String local, String symbol, boolean conditional, int at) {
      scope.rebound.add(local);
      if (conditional || scope.imports.containsKey(local)) scope.blocked.add(local);
      else {
        scope.imports.put(local, symbol);
        scope.importAt.put(local, Integer.valueOf(at));
      }
    }

    void bindTarget(ParserRuleContext n, Scope s, boolean conditional, int depth) {
      if (n == null) return;
      check(depth);
      String target = text(n);
      if (identifier(target)) {
        Integer count = s.assignments.get(target);
        s.assignments.put(target, Integer.valueOf(count == null ? 1 : count.intValue() + 1));
        s.blocked.add(target);
        s.rebound.add(target);
        if (conditional) s.mutated.add(target);
      } else {
        for (ParserRuleContext atom : descendants(n, "Atom_expr", 0)) {
          String base = text(direct(atom, "Atom"));
          if (identifier(base)) {
            if (directs(atom, "Trailer").isEmpty()) {
              s.blocked.add(base);
              s.rebound.add(base);
            } else s.mutated.add(base);
          }
        }
      }
    }

    void definitions(
        ParserRuleContext n,
        Scope outer,
        String prefix,
        int depth,
        boolean decorated,
        String owner) {
      check(depth);
      String k = kind(n);
      if ("Funcdef".equals(k)) {
        ParserRuleContext block = direct(n, "Block"), params = direct(n, "Parameters");
        Scope scope = scope(block, outer, params);
        BusinessFlow.Function f = function(prefix + "." + text(direct(n, "Name")), n);
        List<ParserRuleContext> parameters = descendants(params, "Tfpdef", 0);
        scope.owner = owner;
        for (int i = 0; i < parameters.size(); i++) {
          String name = text(direct(parameters.get(i), "Name"));
          if (i == 0 && owner.length() > 0 && ("self".equals(name) || "cls".equals(name))) {
            scope.receiverName = name;
            continue;
          }
          f.params.add(name);
          f.parameterNames.add(name);
        }
        ParserRuleContext typed = direct(params, "Typedargslist");
        if (typed != null && (has(typed, "*") || has(typed, "**"))) decorated = true;
        f.executionUncertain = decorated || scope.opaque;
        if (decorated || scope.opaque) f.body.add(unknown(n, scope, false, depth + 1));
        statements(block, scope, f.body, depth + 1);
        functions.add(f);
        definitions(block, scope, f.symbol, depth + 1, true, "");
        return;
      }
      if ("Classdef".equals(k)) {
        String qualified = prefix + "." + text(direct(n, "Name"));
        definitions(direct(n, "Block"), outer, qualified, depth + 1, decorated, qualified);
        return;
      }
      for (ParserRuleContext child : children(n))
        definitions(
            child,
            outer,
            prefix,
            depth + 1,
            decorated
                || "Decorated".equals(k)
                || "Async_funcdef".equals(k)
                || "Async_stmt".equals(k),
            owner);
    }

    void statements(ParserRuleContext n, Scope scope, List<BusinessFlow.Stmt> out, int depth) {
      if (n == null) return;
      check(depth);
      String k = kind(n);
      if ("File_input".equals(k)
          || "Block".equals(k)
          || "Stmt".equals(k)
          || "Simple_stmts".equals(k)
          || "Simple_stmt".equals(k)
          || "Compound_stmt".equals(k)
          || "Flow_stmt".equals(k)
          || "Import_stmt".equals(k)) {
        for (ParserRuleContext child : children(n)) statements(child, scope, out, depth + 1);
        return;
      }
      if ("Import_name".equals(k)
          || "Import_from".equals(k)
          || "Pass_stmt".equals(k)
          || "Funcdef".equals(k)) return;
      if ("Classdef".equals(k) && declarationsOnly(n, depth + 1)) return;
      if ("Expr_stmt".equals(k)) {
        List<ParserRuleContext> parts = directs(n, "Testlist_star_expr");
        ParserRuleContext ann = direct(n, "Annassign");
        ParserRuleContext augmented = direct(n, "Augassign");
        if (parts.size() == 1
            && augmented != null
            && "+=".equals(text(augmented))
            && identifier(text(parts.get(0)))) {
          ParserRuleContext rhs = direct(n, "Testlist");
          if (rhs == null || !linearExpression(rhs, 0)) {
            out.add(unknown(n, scope, true, depth + 1));
            return;
          }
          BusinessFlow.Stmt add = statement("ASSIGN", n);
          add.orderUncertain = false;
          add.target = text(parts.get(0));
          add.expr = expr("BINARY", n);
          add.expr.operator = "+";
          BusinessFlow.Expr previous = expr("NAME", parts.get(0));
          previous.name = add.target;
          add.expr.args.add(previous);
          add.expr.args.add(expression(rhs, scope, depth + 1));
          out.add(add);
        } else if (parts.size() == 2 && !identifier(text(parts.get(0))) && augmented == null) {
          BusinessFlow.Expr target = expression(parts.get(0), scope, depth + 1);
          if ("MEMBER".equals(target.kind) && "dict-key".equals(target.operator)) {
            target.kind = "PUT_MEMBER";
            target.args.add(expression(parts.get(1), scope, depth + 1));
            BusinessFlow.Stmt put = statement("EXPR", n);
            put.expr = target;
            out.add(put);
          } else out.add(unknown(n, scope, true, depth + 1));
        } else if (parts.size() == 2
            && identifier(text(parts.get(0)))
            && direct(n, "Augassign") == null) {
          assignment(n, text(parts.get(0)), parts.get(1), scope, out, depth + 1);
        } else if (parts.size() == 1
            && ann != null
            && has(ann, "=")
            && identifier(text(parts.get(0)))) {
          List<ParserRuleContext> tests = directs(ann, "Test");
          assignment(n, text(parts.get(0)), tests.get(tests.size() - 1), scope, out, depth + 1);
        } else if (parts.size() == 1 && ann == null && direct(n, "Augassign") == null) {
          BusinessFlow.Stmt s = statement("EXPR", n);
          s.expr = expression(parts.get(0), scope, depth + 1);
          out.add(s);
        } else out.add(unknown(n, scope, true, depth + 1));
        return;
      }
      if ("If_stmt".equals(k)) {
        List<ParserRuleContext> tests = directs(n, "Test"), blocks = directs(n, "Block");
        BusinessFlow.Stmt current = null;
        for (int i = 0; i < tests.size(); i++) {
          BusinessFlow.Stmt branch = statement("IF", tests.get(i));
          branch.expr = expression(tests.get(i), scope, depth + 1);
          statements(blocks.get(i), scope, branch.body, depth + 1);
          if (current == null) out.add(branch);
          else current.otherwise.add(branch);
          current = branch;
        }
        if (blocks.size() > tests.size())
          statements(blocks.get(blocks.size() - 1), scope, current.otherwise, depth + 1);
        return;
      }
      if ("Try_stmt".equals(k)) {
        BusinessFlow.Stmt s = statement("TRY", n);
        String branch = "try";
        for (int i = 0; i < n.getChildCount(); i++) {
          ParseTree child = n.getChild(i);
          if (child instanceof ParserRuleContext
              && "Except_clause".equals(kind((ParserRuleContext) child))) branch = "except";
          else if ("else".equals(child.getText()) || "finally".equals(child.getText()))
            branch = child.getText();
          else if (child instanceof ParserRuleContext
              && "Block".equals(kind((ParserRuleContext) child))) {
            List<BusinessFlow.Stmt> destination;
            if ("try".equals(branch)) destination = s.body;
            else if ("else".equals(branch)) destination = s.otherwise;
            else if ("finally".equals(branch)) destination = s.finalizer;
            else {
              destination = new ArrayList<BusinessFlow.Stmt>();
              s.handlers.add(destination);
            }
            statements((ParserRuleContext) child, scope, destination, depth + 1);
          }
        }
        out.add(s);
        return;
      }
      if ("Return_stmt".equals(k) || "Raise_stmt".equals(k)) {
        BusinessFlow.Stmt s = statement("Return_stmt".equals(k) ? "RETURN" : "THROW", n);
        List<ParserRuleContext> children = children(n);
        if (!children.isEmpty()) s.expr = expression(children.get(0), scope, depth + 1);
        out.add(s);
        return;
      }
      if ("Yield_stmt".equals(k)) {
        ParserRuleContext yield = direct(n, "Yield_expr");
        ParserRuleContext arg = direct(yield, "Yield_arg");
        if (arg != null && has(arg, "from")) {
          out.add(unknown(n, scope, true, depth + 1));
          return;
        }
        BusinessFlow.Stmt s = statement("YIELD", n);
        if (arg != null) s.expr = expression(arg, scope, depth + 1);
        out.add(s);
        return;
      }
      if ("For_stmt".equals(k) || "While_stmt".equals(k)) {
        String target = "For_stmt".equals(k) ? text(direct(n, "Exprlist")) : "";
        // Only a single name has a defined element binding. Unpacking and mutation stay opaque.
        BusinessFlow.Stmt s =
            identifier(target) ? statement("ITERATE", n) : unknown(n, scope, false, depth + 1);
        if ("ITERATE".equals(s.kind)) s.target = target;
        ParserRuleContext condition = direct(n, "For_stmt".equals(k) ? "Testlist" : "Test");
        if (condition != null) s.expr = expression(condition, scope, depth + 1);
        List<ParserRuleContext> blocks = directs(n, "Block");
        if (!blocks.isEmpty()) statements(blocks.get(0), scope, s.body, depth + 1);
        if (blocks.size() > 1) statements(blocks.get(1), scope, s.otherwise, depth + 1);
        out.add(s);
        return;
      }
      out.add(unknown(n, scope, true, depth + 1));
    }

    boolean declarationsOnly(ParserRuleContext n, int depth) {
      check(depth);
      String k = kind(n);
      if ("Funcdef".equals(k) || "Pass_stmt".equals(k)) return true;
      if ("Classdef".equals(k)) {
        if (direct(n, "Arglist") != null) return false;
        return declarationsOnly(direct(n, "Block"), depth + 1);
      }
      if ("Expr_stmt".equals(k)) {
        List<ParserRuleContext> atoms = descendants(n, "Atom", 0);
        return atoms.size() == 1 && literalString(text(atoms.get(0))) != null;
      }
      if ("Decorated".equals(k)) return false;
      for (ParserRuleContext child : children(n))
        if (!declarationsOnly(child, depth + 1)) return false;
      return !children(n).isEmpty();
    }

    void assignment(
        ParserRuleContext node,
        String name,
        ParserRuleContext value,
        Scope scope,
        List<BusinessFlow.Stmt> out,
        int depth) {
      BusinessFlow.Stmt s = statement("ASSIGN", node);
      s.target = name;
      s.expr = expression(value, scope, depth + 1);
      out.add(s);
      if (Integer.valueOf(1).equals(scope.assignments.get(name))
          && !scope.mutated.contains(name)
          && "CALL".equals(s.expr.kind)
          && s.expr.symbol.length() > 0
          && s.expr.receiver == null) scope.instances.put(name, s.expr.symbol);
    }

    BusinessFlow.Stmt statement(String kind, ParserRuleContext n) {
      BusinessFlow.Stmt s = new BusinessFlow.Stmt(kind);
      s.path = file.path;
      s.line = n.getStart().getLine();
      return s;
    }

    BusinessFlow.Stmt unknown(ParserRuleContext n, Scope scope, boolean calls, int depth) {
      unsupported = true;
      BusinessFlow.Stmt s = statement("UNKNOWN", n);
      if ("Expr_stmt".equals(kind(n)) && linearExpression(n, 0)) s.orderUncertain = false;
      if (calls) {
        s.expr = expr("UNKNOWN", n);
        nestedCalls(n, scope, s.expr.args, depth + 1);
      }
      return s;
    }

    /** A synchronous calculation may obscure a value without obscuring later statement order. */
    boolean linearExpression(ParserRuleContext node, int depth) {
      check(depth);
      String k = kind(node);
      if ("Yield_expr".equals(k)
          || "Yield_stmt".equals(k)
          || "Lambdef".equals(k)
          || "Lambdef_nocond".equals(k)
          || "Comp_for".equals(k)
          || "Comp_if".equals(k)
          || "Atom_expr".equals(k) && has(node, "await")
          || "Test".equals(k) && children(node).size() > 1
          || ("And_test".equals(k) || "Or_test".equals(k)) && children(node).size() > 1)
        return false;
      for (ParserRuleContext child : children(node))
        if (!linearExpression(child, depth + 1)) return false;
      return true;
    }

    void nestedCalls(ParserRuleContext n, Scope scope, List<BusinessFlow.Expr> out, int depth) {
      check(depth);
      if ("Funcdef".equals(kind(n)) || "Classdef".equals(kind(n))) return;
      if ("Atom_expr".equals(kind(n))) {
        out.add(expression(n, scope, depth + 1));
        return;
      }
      for (ParserRuleContext child : children(n)) nestedCalls(child, scope, out, depth + 1);
    }

    BusinessFlow.Expr expression(ParserRuleContext n, Scope scope, int depth) {
      check(depth);
      String k = kind(n);
      if ("Atom_expr".equals(k)) return atomExpression(n, scope, depth + 1);
      if ("Name".equals(k)) {
        BusinessFlow.Expr e = expr("NAME", n);
        e.name = text(n);
        return e;
      }
      if ("Atom".equals(k)) {
        ParserRuleContext name = direct(n, "Name");
        if (name != null) return expression(name, scope, depth + 1);
        if (has(n, "{")) return dictionary(n, scope, depth + 1);
        if (has(n, "[")) return listLiteral(n, scope, depth + 1);
        if (direct(n, "Testlist_comp") != null && !has(n, "["))
          return expression(direct(n, "Testlist_comp"), scope, depth + 1);
        if (children(n).isEmpty()) {
          BusinessFlow.Expr e = expr("LITERAL", n);
          String value = text(n);
          if ("True".equals(value)) e.literal = Boolean.TRUE;
          else if ("False".equals(value)) e.literal = Boolean.FALSE;
          else if ("None".equals(value)) e.literal = null;
          else if (value.matches("[0-9]+")) {
            try {
              e.literal = Long.valueOf(value);
            } catch (NumberFormatException failure) {
              return expr("UNKNOWN", n);
            }
          } else if (n.getChildCount() == 1 && literalString(value) != null)
            e.literal = literalString(value);
          else return unsupportedExpr(n, scope, depth + 1);
          return e;
        }
        return composite(n, scope, depth + 1);
      }
      List<ParserRuleContext> cs = children(n);
      if ("Not_test".equals(k) && has(n, "not")) {
        BusinessFlow.Expr e = expr("UNARY", n);
        e.operator = "not";
        e.args.add(expression(cs.get(0), scope, depth + 1));
        return e;
      }
      if ("Or_test".equals(k) || "And_test".equals(k)) {
        if (cs.size() == 1) return expression(cs.get(0), scope, depth + 1);
        BusinessFlow.Expr value = expression(cs.get(0), scope, depth + 1);
        for (int i = 1; i < cs.size(); i++) {
          BusinessFlow.Expr binary = expr("BINARY", n);
          binary.operator = "Or_test".equals(k) ? "or" : "and";
          binary.args.add(value);
          binary.args.add(expression(cs.get(i), scope, depth + 1));
          value = binary;
        }
        return value;
      }
      if ("Comparison".equals(k) && cs.size() > 1) {
        if (cs.size() != 3) return unsupportedExpr(n, scope, depth + 1);
        BusinessFlow.Expr e = expr("BINARY", n);
        e.operator = text(cs.get(1));
        e.args.add(expression(cs.get(0), scope, depth + 1));
        e.args.add(expression(cs.get(2), scope, depth + 1));
        return e;
      }
      if ("Lambdef".equals(k)
          || "Lambdef_nocond".equals(k)
          || "Yield_expr".equals(k)
          || "Comp_for".equals(k)
          || "Argument".equals(k) && (has(n, "=") || has(n, "*") || has(n, "**"))
          || "Test".equals(k) && cs.size() > 1) return unsupportedExpr(n, scope, depth + 1);
      if ("Expr".equals(k) && cs.size() > 1) {
        BusinessFlow.Expr e = expr("BINARY", n);
        e.operator = n.getChildCount() == 3 ? n.getChild(1).getText() : "unknown";
        for (ParserRuleContext c : cs) e.args.add(expression(c, scope, depth + 1));
        return e;
      }
      if (cs.size() == 1) return expression(cs.get(0), scope, depth + 1);
      return composite(n, scope, depth + 1);
    }

    BusinessFlow.Expr atomExpression(ParserRuleContext n, Scope scope, int depth) {
      ParserRuleContext atom = direct(n, "Atom");
      BusinessFlow.Expr value = expression(atom, scope, depth + 1);
      String path = direct(atom, "Name") == null ? "" : text(atom);
      boolean receiver = false;
      for (ParserRuleContext trailer : directs(n, "Trailer")) {
        if (has(trailer, ".")) {
          String member = text(direct(trailer, "Name"));
          if (path.length() > 0) path += "." + member;
          BusinessFlow.Expr field = expr("MEMBER", trailer);
          field.name = member;
          field.receiver = value;
          value = field;
        } else if (has(trailer, "(")) {
          BusinessFlow.Expr call = expr("CALL", n);
          call.symbol = symbol(path, scope, n.getStart().getTokenIndex());
          BusinessPolicy.Receiver mappedReceiver = receiver(path, scope);
          if (mappedReceiver != null)
            call.bindingUncertain = !"reviewed".equals(mappedReceiver.assurance);
          ParserRuleContext arglist = direct(trailer, "Arglist");
          Set<String> keywords = new HashSet<String>();
          boolean sawKeyword = false;
          if (arglist != null)
            for (ParserRuleContext argument : directs(arglist, "Argument")) {
              List<ParserRuleContext> tests = directs(argument, "Test");
              boolean keyword = has(argument, "=");
              String argumentName = keyword && !tests.isEmpty() ? text(tests.get(0)) : "";
              if (has(argument, "*")
                  || has(argument, "**")
                  || direct(argument, "Comp_for") != null
                  || keyword && (!identifier(argumentName) || !keywords.add(argumentName))
                  || !keyword && sawKeyword) {
                call.kind = "UNKNOWN";
                call.symbol = "";
                unsupported = true;
              }
              sawKeyword |= keyword;
              if (!tests.isEmpty()) {
                call.args.add(expression(tests.get(tests.size() - 1), scope, depth + 1));
                call.argNames.add(argumentName);
              }
            }
          if (receiver || path.length() == 0) call.receiver = value;
          else if (mappedReceiver != null) call.receiver = value.receiver;
          else if (scope.instances.containsKey(root(path))) {
            call.receiver = expr("NAME", atom);
            call.receiver.name = root(path);
          }
          if ("CALL".equals(call.kind) && call.receiver == null)
            bindLocalCall(call, path, scope, n.getStart().getTokenIndex());
          if ("CALL".equals(call.kind)
              && call.symbol.isEmpty()
              && "MEMBER".equals(value.kind)
              && "get".equals(value.name)
              && call.argNames.size() == call.args.size()
              && !call.argNames.contains("default")
              && (call.args.size() == 1 || call.args.size() == 2)) {
            boolean positional = true;
            for (String name : call.argNames) positional &= name.isEmpty();
            if (positional) {
              call.kind = "DICT_GET";
              call.receiver = value.receiver;
            }
          }
          if ("CALL".equals(call.kind)
              && "json.loads".equals(call.symbol)
              && standardJsonUnambiguous
              && policy.contractsForSymbol(call.symbol).isEmpty()
              && call.args.size() == 1
              && call.argNames.get(0).isEmpty()) call.kind = "JSON_LOADS";
          if ("CALL".equals(call.kind)
              && call.symbol.length() == 0
              && call.localTargetId.length() == 0) unsupported = true;
          value = call;
          path = "";
          receiver = true;
        } else {
          BusinessFlow.Expr sub;
          ParserRuleContext subscripts = direct(trailer, "Subscriptlist");
          List<ParserRuleContext> slots = directs(subscripts, "Subscript_");
          BusinessFlow.Expr key =
              slots.size() == 1 && !has(subscripts, ",") && !has(slots.get(0), ":")
                  ? expression(slots.get(0), scope, depth + 1)
                  : null;
          if (key != null) {
            sub = expr("MEMBER", trailer);
            if ("LITERAL".equals(key.kind) && key.literal instanceof String)
              sub.name = (String) key.literal;
            else sub.args.add(key);
            sub.operator = "dict-key";
            sub.receiver = value;
          } else {
            sub = expr("UNKNOWN", trailer);
            sub.args.add(value);
            for (ParserRuleContext child : children(trailer))
              sub.args.add(expression(child, scope, depth + 1));
            unsupported = true;
          }
          value = sub;
          path = "";
        }
      }
      if (has(n, "await")) return unsupportedExpr(n, scope, depth + 1);
      return value;
    }

    void bindLocalCall(BusinessFlow.Expr call, String name, Scope scope, int at) {
      if (!identifier(name) || scope.opaque) return;
      LocalFunction target = scope.localFunctions.get(name);
      if (target == null || target.at >= at || target.parameters.size() != call.args.size()) return;
      Set<Integer> assigned = new HashSet<Integer>();
      for (int i = 0; i < call.args.size(); i++) {
        String keyword = call.argNames.get(i);
        int slot = keyword.length() == 0 ? i : target.parameters.indexOf(keyword);
        if (slot < 0 || !assigned.add(Integer.valueOf(slot))) return;
      }
      call.localTargetId = target.id;
    }

    String symbol(String path, Scope scope, int at) {
      if (path.length() == 0 || scope.opaque) return "";
      String root = root(path);
      if (scope.mutated.contains(root)) return "";
      BusinessPolicy.Receiver mappedReceiver = receiver(path, scope);
      if (mappedReceiver != null) {
        String suffix = path.substring(scope.receiverName.length() + 1);
        return mappedReceiver.type + suffix.substring(suffix.indexOf('.'));
      }
      String instance = scope.instances.get(root);
      if (instance != null && path.indexOf('.') >= 0)
        return instance + path.substring(root.length());
      if (scope.blocked.contains(root)) return "";
      Integer boundAt = scope.importAt.get(root);
      if (boundAt != null && boundAt.intValue() >= at) return "";
      String imported = scope.imports.get(root);
      return imported == null ? "" : imported + path.substring(root.length());
    }

    BusinessPolicy.Receiver receiver(String path, Scope scope) {
      if (scope.opaque
          || scope.owner.length() == 0
          || scope.receiverName.length() == 0
          || scope.mutated.contains(scope.receiverName)
          || scope.assignments.containsKey(scope.receiverName)
          || !path.startsWith(scope.receiverName + ".")) return null;
      String suffix = path.substring(scope.receiverName.length() + 1);
      int dot = suffix.indexOf('.');
      return dot < 0 ? null : policy.receiver(scope.owner, suffix.substring(0, dot));
    }

    BusinessFlow.Expr dictionary(ParserRuleContext atom, Scope scope, int depth) {
      ParserRuleContext items = direct(atom, "Dictorsetmaker");
      BusinessFlow.Expr out = expr("MAP", atom);
      out.name = "dict";
      if (items == null) return out;
      if (!has(items, ":") || has(items, "**") || direct(items, "Comp_for") != null)
        return unsupportedExpr(atom, scope, depth + 1);
      List<ParserRuleContext> parts = directs(items, "Test");
      if ((parts.size() & 1) != 0) return unsupportedExpr(atom, scope, depth + 1);
      for (int i = 0; i < parts.size(); i += 2) {
        BusinessFlow.Expr key = expression(parts.get(i), scope, depth + 1);
        if (!"LITERAL".equals(key.kind)
            || !(key.literal instanceof String)
            || out.members.containsKey((String) key.literal))
          return unsupportedExpr(atom, scope, depth + 1);
        out.members.put((String) key.literal, expression(parts.get(i + 1), scope, depth + 1));
      }
      return out;
    }

    BusinessFlow.Expr listLiteral(ParserRuleContext atom, Scope scope, int depth) {
      BusinessFlow.Expr out = expr("MAP", atom);
      out.name = "list";
      ParserRuleContext items = direct(atom, "Testlist_comp");
      if (items == null) return out;
      if (direct(items, "Comp_for") != null || !directs(items, "Star_expr").isEmpty())
        return unsupportedExpr(atom, scope, depth + 1);
      List<ParserRuleContext> values = directs(items, "Test");
      if (values.size() > 128) return unsupportedExpr(atom, scope, depth + 1);
      for (int i = 0; i < values.size(); i++)
        out.members.put("i:" + i, expression(values.get(i), scope, depth + 1));
      return out;
    }

    BusinessFlow.Expr unsupportedExpr(ParserRuleContext n, Scope scope, int depth) {
      unsupported = true;
      BusinessFlow.Expr e = expr("UNKNOWN", n);
      for (ParserRuleContext child : children(n)) e.args.add(expression(child, scope, depth + 1));
      return e;
    }

    BusinessFlow.Expr composite(ParserRuleContext n, Scope scope, int depth) {
      BusinessFlow.Expr e = expr("COMPOSITE", n);
      for (ParserRuleContext child : children(n)) e.args.add(expression(child, scope, depth + 1));
      return e;
    }

    BusinessFlow.Expr expr(String kind, ParserRuleContext n) {
      BusinessFlow.Expr e = new BusinessFlow.Expr(kind);
      e.path = file.path;
      e.line = n.getStart().getLine();
      return e;
    }

    List<ParserRuleContext> descendants(ParserRuleContext n, String name, int depth) {
      List<ParserRuleContext> found = new ArrayList<ParserRuleContext>();
      if (n == null) return found;
      check(depth);
      for (ParserRuleContext c : children(n)) {
        if (name.equals(kind(c))) found.add(c);
        else found.addAll(descendants(c, name, depth + 1));
      }
      return found;
    }
  }

  private static String moduleName(String path) {
    String name = path.replace('\\', '/').replaceAll("\\.py$", "").replace('/', '.');
    return name.endsWith(".__init__") ? name.substring(0, name.length() - 9) : name;
  }

  /** Decode only literal text; f-strings, bytes and unrecognised escapes stay unknown. */
  private static String literalString(String value) {
    if (value.length() < 2) return null;
    int offset = 0;
    boolean raw = false;
    char first = value.charAt(0);
    if (first == 'r' || first == 'R' || first == 'u' || first == 'U') {
      raw = first == 'r' || first == 'R';
      offset = 1;
    }
    if (offset >= value.length()) return null;
    char quote = value.charAt(offset);
    if (quote != '\'' && quote != '"') return null;
    String delimiter = String.valueOf(quote);
    if (value.startsWith(delimiter + delimiter + delimiter, offset))
      delimiter = delimiter + delimiter + delimiter;
    int start = offset + delimiter.length(), end = value.length() - delimiter.length();
    if (start > end || !value.endsWith(delimiter)) return null;
    String body = value.substring(start, end);
    if (raw) return body;
    StringBuilder out = new StringBuilder();
    for (int i = 0; i < body.length(); i++) {
      char c = body.charAt(i);
      if (c != '\\') {
        out.append(c);
        continue;
      }
      if (++i >= body.length()) return null;
      c = body.charAt(i);
      switch (c) {
        case '\\':
        case '\'':
        case '"':
          out.append(c);
          break;
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
        case 'a':
          out.append((char) 7);
          break;
        case 'v':
          out.append((char) 11);
          break;
        case '\n':
          break;
        case '\r':
          if (i + 1 < body.length() && body.charAt(i + 1) == '\n') i++;
          break;
        case 'x':
        case 'u':
        case 'U':
          int width = c == 'x' ? 2 : c == 'u' ? 4 : 8;
          if (i + width >= body.length()) return null;
          long code = 0;
          for (int j = 0; j < width; j++) {
            int digit = Character.digit(body.charAt(++i), 16);
            if (digit < 0) return null;
            code = code * 16 + digit;
          }
          if (code > Character.MAX_CODE_POINT || code >= 0xd800 && code <= 0xdfff) return null;
          out.append(Character.toChars((int) code));
          break;
        default:
          if (c < '0' || c > '7') return null;
          int octal = c - '0', digits = 1;
          while (digits < 3
              && i + 1 < body.length()
              && body.charAt(i + 1) >= '0'
              && body.charAt(i + 1) <= '7') {
            octal = octal * 8 + body.charAt(++i) - '0';
            digits++;
          }
          out.append((char) octal);
      }
    }
    return out.toString();
  }

  private static String root(String name) {
    int dot = name.indexOf('.');
    return dot < 0 ? name : name.substring(0, dot);
  }

  private static boolean identifier(String name) {
    return name.matches("[A-Za-z_][A-Za-z_0-9]*");
  }

  private static String kind(ParserRuleContext n) {
    return n == null ? "" : n.getClass().getSimpleName().replaceFirst("Context$", "");
  }

  private static String text(ParserRuleContext n) {
    return n == null ? "" : n.getText();
  }

  private static boolean has(ParserRuleContext n, String value) {
    for (int i = 0; i < n.getChildCount(); i++)
      if (value.equals(n.getChild(i).getText())) return true;
    return false;
  }

  private static List<ParserRuleContext> children(ParserRuleContext n) {
    List<ParserRuleContext> out = new ArrayList<ParserRuleContext>();
    if (n != null)
      for (int i = 0; i < n.getChildCount(); i++)
        if (n.getChild(i) instanceof ParserRuleContext) out.add((ParserRuleContext) n.getChild(i));
    return out;
  }

  private static ParserRuleContext direct(ParserRuleContext n, String name) {
    for (ParserRuleContext child : children(n)) if (name.equals(kind(child))) return child;
    return null;
  }

  private static List<ParserRuleContext> directs(ParserRuleContext n, String name) {
    List<ParserRuleContext> out = new ArrayList<ParserRuleContext>();
    for (ParserRuleContext child : children(n)) if (name.equals(kind(child))) out.add(child);
    return out;
  }
}
