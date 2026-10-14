package dev.aiguard.compat;

import dev.aiguard.compat.pygrammar.Python3Lexer;
import dev.aiguard.compat.pygrammar.Python3Parser;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.antlr.v4.runtime.BaseErrorListener;
import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.ParserRuleContext;
import org.antlr.v4.runtime.RecognitionException;
import org.antlr.v4.runtime.Recognizer;
import org.antlr.v4.runtime.Token;
import org.antlr.v4.runtime.tree.ParseTree;

/** Conservative Python syntax adapter; it never imports or executes the inspected application. */
public final class BankPythonAnalysis {
  private BankPythonAnalysis() {}

  public static BankFlow.Program adapt(List<SourceFile> files, Cancel cancel) {
    BankFlow.Program program = new BankFlow.Program();
    for (SourceFile file : files) {
      cancel.check();
      new Adapter(file, cancel, program).parse();
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
    boolean opaque;
  }

  private static final class Adapter {
    final SourceFile file;
    final Cancel cancel;
    final BankFlow.Program program;
    final List<BankFlow.Function> functions = new ArrayList<BankFlow.Function>();
    int visits;
    boolean unsupported;

    Adapter(SourceFile file, Cancel cancel, BankFlow.Program program) {
      this.file = file;
      this.cancel = cancel;
      this.program = program;
    }

    void check(int depth) {
      cancel.check();
      if (depth > 160 || ++visits > 300000) throw new Limit();
    }

    void parse() {
      final boolean[] failed = {false};
      BaseErrorListener errors =
          new BaseErrorListener() {
            @Override
            public void syntaxError(
                Recognizer<?, ?> r,
                Object symbol,
                int line,
                int column,
                String message,
                RecognitionException exception) {
              failed[0] = true;
            }
          };
      try {
        Python3Lexer lexer =
            new Python3Lexer(CharStreams.fromString(file.content)) {
              int count;

              @Override
              public Token nextToken() {
                if ((++count & 255) == 0) cancel.check();
                if (count > 150000) throw new Limit();
                return super.nextToken();
              }
            };
        lexer.removeErrorListeners();
        lexer.addErrorListener(errors);
        CommonTokenStream tokens =
            new CommonTokenStream(lexer) {
              int reads;

              @Override
              public Token LT(int lookahead) {
                if ((++reads & 1023) == 0) cancel.check();
                if (reads > 5000000) throw new Limit();
                return super.LT(lookahead);
              }
            };
        Python3Parser parser = new Python3Parser(tokens);
        parser.removeErrorListeners();
        parser.addErrorListener(errors);
        ParserRuleContext tree = parser.file_input();
        if (failed[0]) {
          diagnostic(
              "BANK_PYTHON_PARSE_FAILED",
              "Python syntax failed; bank flow for this file was discarded.");
          return;
        }
        Scope module = scope(tree, null, null);
        BankFlow.Function top = function(moduleName(file.path) + ".<module>", tree);
        statements(tree, module, top.body, 0);
        functions.add(top);
        definitions(tree, module, moduleName(file.path), 0, false);
        program.functions.addAll(functions);
        if (unsupported)
          diagnostic(
              "BANK_PYTHON_UNSUPPORTED_FLOW",
              "Unsupported Python flow or dynamic binding remains unknown in the bank adapter.");
      } catch (Limit limit) {
        diagnostic(
            "BANK_PYTHON_ANALYSIS_LIMIT",
            "Python bank flow exceeded its bounded analysis budget; this file was discarded.");
      } catch (StackOverflowError error) {
        diagnostic(
            "BANK_PYTHON_ANALYSIS_DEPTH",
            "Python bank flow exceeded supported nesting; this file was discarded.");
      }
    }

    void diagnostic(String code, String message) {
      program.diagnostics.add(Findings.diagnostic(code, file.path, message));
    }

    BankFlow.Function function(String symbol, ParserRuleContext node) {
      BankFlow.Function f = new BankFlow.Function();
      f.path = file.path;
      f.line = node.getStart().getLine();
      f.symbol = symbol;
      return f;
    }

    Scope scope(ParserRuleContext body, Scope outer, ParserRuleContext params) {
      Scope scope = new Scope();
      if (outer != null) {
        scope.imports.putAll(outer.imports);
        for (String name : outer.blocked) scope.imports.remove(name);
        for (String name : outer.mutated) scope.imports.remove(name);
        scope.opaque = outer.opaque;
      }
      bindings(body, scope, false, 0);
      if (params != null)
        for (ParserRuleContext p : descendants(params, "Tfpdef", 0))
          scope.blocked.add(text(direct(p, "Name")));
      return scope;
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
        if (name.length() > 0) s.blocked.add(name);
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
        if (conditional) s.mutated.add(target);
      } else {
        for (ParserRuleContext atom : descendants(n, "Atom_expr", 0)) {
          String base = text(direct(atom, "Atom"));
          if (identifier(base)) {
            if (directs(atom, "Trailer").isEmpty()) s.blocked.add(base);
            else s.mutated.add(base);
          }
        }
      }
    }

    void definitions(
        ParserRuleContext n, Scope outer, String prefix, int depth, boolean decorated) {
      check(depth);
      String k = kind(n);
      if ("Funcdef".equals(k)) {
        ParserRuleContext block = direct(n, "Block"), params = direct(n, "Parameters");
        Scope scope = scope(block, outer, params);
        BankFlow.Function f = function(prefix + "." + text(direct(n, "Name")), n);
        for (ParserRuleContext p : descendants(params, "Tfpdef", 0))
          f.params.add(text(direct(p, "Name")));
        if (decorated || scope.opaque) f.body.add(unknown(n, scope, false, depth + 1));
        statements(block, scope, f.body, depth + 1);
        functions.add(f);
        definitions(block, scope, f.symbol, depth + 1, true);
        return;
      }
      if ("Classdef".equals(k)) {
        definitions(
            direct(n, "Block"), outer, prefix + "." + text(direct(n, "Name")), depth + 1, true);
        return;
      }
      for (ParserRuleContext child : children(n))
        definitions(
            child,
            outer,
            prefix,
            depth + 1,
            decorated || "Decorated".equals(k) || "Async_funcdef".equals(k));
    }

    void statements(ParserRuleContext n, Scope scope, List<BankFlow.Stmt> out, int depth) {
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
      if ("Expr_stmt".equals(k)) {
        List<ParserRuleContext> parts = directs(n, "Testlist_star_expr");
        ParserRuleContext ann = direct(n, "Annassign");
        if (parts.size() == 2 && identifier(text(parts.get(0))) && direct(n, "Augassign") == null) {
          assignment(n, text(parts.get(0)), parts.get(1), scope, out, depth + 1);
        } else if (parts.size() == 1
            && ann != null
            && has(ann, "=")
            && identifier(text(parts.get(0)))) {
          List<ParserRuleContext> tests = directs(ann, "Test");
          assignment(n, text(parts.get(0)), tests.get(tests.size() - 1), scope, out, depth + 1);
        } else if (parts.size() == 1 && ann == null && direct(n, "Augassign") == null) {
          BankFlow.Stmt s = statement("EXPR", n);
          s.expr = expression(parts.get(0), scope, depth + 1);
          out.add(s);
        } else out.add(unknown(n, scope, true, depth + 1));
        return;
      }
      if ("If_stmt".equals(k)) {
        List<ParserRuleContext> tests = directs(n, "Test"), blocks = directs(n, "Block");
        BankFlow.Stmt current = null;
        for (int i = 0; i < tests.size(); i++) {
          BankFlow.Stmt branch = statement("IF", tests.get(i));
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
        BankFlow.Stmt s = statement("TRY", n);
        String branch = "try";
        for (int i = 0; i < n.getChildCount(); i++) {
          ParseTree child = n.getChild(i);
          if (child instanceof ParserRuleContext
              && "Except_clause".equals(kind((ParserRuleContext) child))) branch = "except";
          else if ("else".equals(child.getText()) || "finally".equals(child.getText()))
            branch = child.getText();
          else if (child instanceof ParserRuleContext
              && "Block".equals(kind((ParserRuleContext) child))) {
            List<BankFlow.Stmt> destination;
            if ("try".equals(branch)) destination = s.body;
            else if ("else".equals(branch)) destination = s.otherwise;
            else if ("finally".equals(branch)) destination = s.finalizer;
            else {
              destination = new ArrayList<BankFlow.Stmt>();
              s.handlers.add(destination);
            }
            statements((ParserRuleContext) child, scope, destination, depth + 1);
          }
        }
        out.add(s);
        return;
      }
      if ("Return_stmt".equals(k) || "Raise_stmt".equals(k)) {
        BankFlow.Stmt s = statement("Return_stmt".equals(k) ? "RETURN" : "THROW", n);
        List<ParserRuleContext> children = children(n);
        if (!children.isEmpty()) s.expr = expression(children.get(0), scope, depth + 1);
        out.add(s);
        return;
      }
      out.add(unknown(n, scope, true, depth + 1));
    }

    void assignment(
        ParserRuleContext node,
        String name,
        ParserRuleContext value,
        Scope scope,
        List<BankFlow.Stmt> out,
        int depth) {
      BankFlow.Stmt s = statement("ASSIGN", node);
      s.target = name;
      s.expr = expression(value, scope, depth + 1);
      out.add(s);
      if (Integer.valueOf(1).equals(scope.assignments.get(name))
          && !scope.mutated.contains(name)
          && "CALL".equals(s.expr.kind)
          && s.expr.symbol.length() > 0
          && s.expr.receiver == null) scope.instances.put(name, s.expr.symbol);
    }

    BankFlow.Stmt statement(String kind, ParserRuleContext n) {
      BankFlow.Stmt s = new BankFlow.Stmt(kind);
      s.path = file.path;
      s.line = n.getStart().getLine();
      return s;
    }

    BankFlow.Stmt unknown(ParserRuleContext n, Scope scope, boolean calls, int depth) {
      unsupported = true;
      BankFlow.Stmt s = statement("UNKNOWN", n);
      if (calls) {
        s.expr = expr("UNKNOWN", n);
        nestedCalls(n, scope, s.expr.args, depth + 1);
      }
      return s;
    }

    void nestedCalls(ParserRuleContext n, Scope scope, List<BankFlow.Expr> out, int depth) {
      check(depth);
      if ("Funcdef".equals(kind(n)) || "Classdef".equals(kind(n))) return;
      if ("Atom_expr".equals(kind(n))) {
        out.add(expression(n, scope, depth + 1));
        return;
      }
      for (ParserRuleContext child : children(n)) nestedCalls(child, scope, out, depth + 1);
    }

    BankFlow.Expr expression(ParserRuleContext n, Scope scope, int depth) {
      check(depth);
      String k = kind(n);
      if ("Atom_expr".equals(k)) return atomExpression(n, scope, depth + 1);
      if ("Name".equals(k)) {
        BankFlow.Expr e = expr("NAME", n);
        e.name = text(n);
        return e;
      }
      if ("Atom".equals(k)) {
        ParserRuleContext name = direct(n, "Name");
        if (name != null) return expression(name, scope, depth + 1);
        if (direct(n, "Testlist_comp") != null && !has(n, "["))
          return expression(direct(n, "Testlist_comp"), scope, depth + 1);
        if (children(n).isEmpty()) {
          BankFlow.Expr e = expr("LITERAL", n);
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
          } else if (value.matches("(?is)[rub]*['\"].*")) e.literal = value;
          else return unsupportedExpr(n, scope, depth + 1);
          return e;
        }
        return composite(n, scope, depth + 1);
      }
      List<ParserRuleContext> cs = children(n);
      if ("Not_test".equals(k) && has(n, "not")) {
        BankFlow.Expr e = expr("UNARY", n);
        e.operator = "not";
        e.args.add(expression(cs.get(0), scope, depth + 1));
        return e;
      }
      if ("Or_test".equals(k) || "And_test".equals(k)) {
        if (cs.size() == 1) return expression(cs.get(0), scope, depth + 1);
        BankFlow.Expr e = expr("BINARY", n);
        e.operator = "Or_test".equals(k) ? "or" : "and";
        for (ParserRuleContext c : cs) e.args.add(expression(c, scope, depth + 1));
        return e;
      }
      if ("Comparison".equals(k) && cs.size() > 1) {
        if (cs.size() != 3) return unsupportedExpr(n, scope, depth + 1);
        BankFlow.Expr e = expr("BINARY", n);
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
        BankFlow.Expr e = expr("BINARY", n);
        e.operator = n.getChildCount() == 3 ? n.getChild(1).getText() : "unknown";
        for (ParserRuleContext c : cs) e.args.add(expression(c, scope, depth + 1));
        return e;
      }
      if (cs.size() == 1) return expression(cs.get(0), scope, depth + 1);
      return composite(n, scope, depth + 1);
    }

    BankFlow.Expr atomExpression(ParserRuleContext n, Scope scope, int depth) {
      ParserRuleContext atom = direct(n, "Atom");
      BankFlow.Expr value = expression(atom, scope, depth + 1);
      String path = direct(atom, "Name") == null ? "" : text(atom);
      boolean receiver = false;
      for (ParserRuleContext trailer : directs(n, "Trailer")) {
        if (has(trailer, ".")) {
          if (path.length() > 0) path += "." + text(direct(trailer, "Name"));
          BankFlow.Expr field = expr("UNKNOWN", trailer);
          field.args.add(value);
          value = field;
        } else if (has(trailer, "(")) {
          BankFlow.Expr call = expr("CALL", n);
          call.symbol = symbol(path, scope, n.getStart().getTokenIndex());
          ParserRuleContext arglist = direct(trailer, "Arglist");
          if (arglist != null)
            for (ParserRuleContext argument : directs(arglist, "Argument")) {
              if (has(argument, "=")
                  || has(argument, "*")
                  || has(argument, "**")
                  || direct(argument, "Comp_for") != null) {
                call.kind = "UNKNOWN";
                call.symbol = "";
                unsupported = true;
              }
              List<ParserRuleContext> tests = directs(argument, "Test");
              if (!tests.isEmpty())
                call.args.add(expression(tests.get(tests.size() - 1), scope, depth + 1));
            }
          if (receiver || path.length() == 0) call.receiver = value;
          else if (scope.instances.containsKey(root(path))) {
            call.receiver = expr("NAME", atom);
            call.receiver.name = root(path);
          }
          if (call.symbol.length() == 0) unsupported = true;
          value = call;
          path = "";
          receiver = true;
        } else {
          BankFlow.Expr sub = expr("UNKNOWN", trailer);
          sub.args.add(value);
          for (ParserRuleContext child : children(trailer))
            sub.args.add(expression(child, scope, depth + 1));
          value = sub;
          path = "";
          unsupported = true;
        }
      }
      if (has(n, "await")) return unsupportedExpr(n, scope, depth + 1);
      return value;
    }

    String symbol(String path, Scope scope, int at) {
      if (path.length() == 0 || scope.opaque) return "";
      String root = root(path);
      if (scope.mutated.contains(root)) return "";
      String instance = scope.instances.get(root);
      if (instance != null && path.indexOf('.') >= 0)
        return instance + path.substring(root.length());
      if (scope.blocked.contains(root)) return "";
      Integer boundAt = scope.importAt.get(root);
      if (boundAt != null && boundAt.intValue() >= at) return "";
      String imported = scope.imports.get(root);
      return imported == null ? "" : imported + path.substring(root.length());
    }

    BankFlow.Expr unsupportedExpr(ParserRuleContext n, Scope scope, int depth) {
      unsupported = true;
      BankFlow.Expr e = expr("UNKNOWN", n);
      for (ParserRuleContext child : children(n)) e.args.add(expression(child, scope, depth + 1));
      return e;
    }

    BankFlow.Expr composite(ParserRuleContext n, Scope scope, int depth) {
      BankFlow.Expr e = expr("COMPOSITE", n);
      for (ParserRuleContext child : children(n)) e.args.add(expression(child, scope, depth + 1));
      return e;
    }

    BankFlow.Expr expr(String kind, ParserRuleContext n) {
      BankFlow.Expr e = new BankFlow.Expr(kind);
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
