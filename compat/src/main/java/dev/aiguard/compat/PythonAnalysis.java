package dev.aiguard.compat;

import dev.aiguard.compat.pygrammar.Python3Lexer;
import dev.aiguard.compat.pygrammar.Python3Parser;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
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

/** Native Java 7 Python AST adapter. Target code is parsed, never imported or executed. */
public final class PythonAnalysis {
  private PythonAnalysis() {}

  private static final String[] TITLES = {
    "Python prompt and RAG boundary",
    "Python retrieval tenant boundary",
    "Python model content logging",
    "Python model rate and quota controls",
    "Python content and streaming controls",
    "Python audit trace coverage",
    "Python model output and dynamic execution"
  };
  private static final String[] RECOMMENDATIONS = {
    "Keep retrieved documents in an untrusted data boundary and validate application intent.",
    "Bind retrieval scope and metadata filters to an authenticated principal; test cross-tenant"
        + " access.",
    "Redact model content before logging and minimize retained payloads.",
    "Enforce per-principal rate limits, concurrency and token budgets at the actual gateway.",
    "Validate or buffer model output before emitting it; test rejection and exception paths.",
    "Correlate principal, request, retrieval, model, guard decisions and output using a safe audit"
        + " identifier.",
    "Validate model output against a closed schema; never execute model-supplied code or shell"
        + " commands."
  };

  public static List<Map<String, Object>> catalog() {
    List<Map<String, Object>> out = new ArrayList<Map<String, Object>>();
    for (int i = 0; i < 7; i++)
      out.add(
          Findings.map(
              "id",
              id(i),
              "domain",
              "L" + (i + 1),
              "title",
              TITLES[i],
              "description",
              TITLES[i] + "; bounded static evidence, not a safety certification.",
              "recommendation",
              RECOMMENDATIONS[i],
              "references",
              Arrays.asList(
                  "https://owasp.org/www-project-top-10-for-large-language-model-applications/")));
    return out;
  }

  private static String id(int i) {
    return "AI-PY-00" + (i + 1);
  }

  public static AnalysisResult analyze(List<SourceFile> files, Cancel cancel) {
    Engine engine = new Engine(cancel);
    for (SourceFile file : files) {
      cancel.check();
      engine.parse(file);
    }
    engine.scan();
    return engine.result;
  }

  private static final int UNKNOWN = 0,
      CLIENT = 1,
      RESPONSE = 2,
      RAW = 3,
      STREAM = 4,
      LOGGER = 5,
      CHROMA = 6,
      COLLECTION = 7,
      RETRIEVAL = 8,
      INSTANCE = 9;

  private static final class Value {
    int kind;
    String symbol = "";
    String chain = "";
    boolean candidate, literalContainer;
    Scope instance;
    final List<Map<String, Object>> evidence = new ArrayList<Map<String, Object>>();

    Value(int kind) {
      this.kind = kind;
    }

    Value copy() {
      Value v = new Value(kind);
      v.symbol = symbol;
      v.chain = chain;
      v.candidate = candidate;
      v.instance = instance;
      v.literalContainer = literalContainer;
      v.evidence.addAll(evidence);
      return v;
    }
  }

  private static final class Scope {
    final String name, module;
    final SourceFile file;
    final Scope parent;
    final ParserRuleContext node;
    final List<Binding> bindings = new ArrayList<Binding>();
    final List<ParserRuleContext> returns = new ArrayList<ParserRuleContext>();
    final List<ParserRuleContext> yields = new ArrayList<ParserRuleContext>();
    final Set<String> parameters = new LinkedHashSet<String>();
    final Map<String, String> imports = new LinkedHashMap<String, String>();
    Scope owner;

    Scope(String name, SourceFile file, Scope parent, ParserRuleContext node) {
      this.name = name;
      this.file = file;
      this.parent = parent;
      this.node = node;
      this.module = parent == null ? moduleName(file.path) : parent.module;
    }

    String qualified() {
      return parent == null ? module : parent.qualified() + "." + name;
    }
  }

  private static final class Binding {
    final String name;
    final ParserRuleContext value, node;
    final boolean loop, conditional;

    Binding(
        String name,
        ParserRuleContext value,
        ParserRuleContext node,
        boolean loop,
        boolean conditional) {
      this.name = name;
      this.value = value;
      this.node = node;
      this.loop = loop;
      this.conditional = conditional;
    }
  }

  private static final class Call {
    final ParserRuleContext node;
    final Scope scope;
    final Value receiver;
    final List<ParserRuleContext> args;

    Call(ParserRuleContext node, Scope scope, Value receiver, List<ParserRuleContext> args) {
      this.node = node;
      this.scope = scope;
      this.receiver = receiver;
      this.args = args;
    }
  }

  private static final class Engine {
    final Cancel cancel;
    final AnalysisResult result = new AnalysisResult();
    final List<Scope> scopes = new ArrayList<Scope>();
    final Map<String, Scope> named = new LinkedHashMap<String, Scope>();
    final Map<ParserRuleContext, Scope> owners = new IdentityHashMap<ParserRuleContext, Scope>();
    final Map<ParserRuleContext, Value> memo = new IdentityHashMap<ParserRuleContext, Value>();
    final List<ParserRuleContext> expressions = new ArrayList<ParserRuleContext>();
    final Map<String, Map<String, Object>> gateways =
        new LinkedHashMap<String, Map<String, Object>>();
    final List<Map<String, Object>> retrieval = new ArrayList<Map<String, Object>>();
    final List<Map<String, Object>> rawLogs = new ArrayList<Map<String, Object>>();
    final List<Map<String, Object>> candidateLogs = new ArrayList<Map<String, Object>>();
    final List<Map<String, Object>> dangerous = new ArrayList<Map<String, Object>>();
    final List<Map<String, Object>> emissions = new ArrayList<Map<String, Object>>();
    final List<Map<String, Object>> controls = new ArrayList<Map<String, Object>>();
    final List<Map<String, Object>> toolCalls = new ArrayList<Map<String, Object>>();
    final List<Map<String, Object>> unresolvedModelCalls = new ArrayList<Map<String, Object>>();
    final List<Map<String, Object>> budgets = new ArrayList<Map<String, Object>>();
    final Set<String> seen = new LinkedHashSet<String>();
    final Set<String> active = new LinkedHashSet<String>();
    boolean fstrings, exhausted, depthLimited;
    int work, recursiveMisses;

    Engine(Cancel cancel) {
      this.cancel = cancel;
    }

    void parse(final SourceFile file) {
      final boolean[] failed = {false};
      BaseErrorListener listener =
          new BaseErrorListener() {
            @Override
            public void syntaxError(
                Recognizer<?, ?> r,
                Object offending,
                int line,
                int col,
                String message,
                RecognitionException error) {
              failed[0] = true;
            }
          };
      try {
        Python3Lexer lexer =
            new Python3Lexer(CharStreams.fromString(file.content)) {
              private int count;

              @Override
              public Token nextToken() {
                if ((++count & 255) == 0) cancel.check();
                if (count > 150000) throw new Limit();
                return super.nextToken();
              }
            };
        lexer.removeErrorListeners();
        lexer.addErrorListener(listener);
        CommonTokenStream tokens =
            new CommonTokenStream(lexer) {
              private int reads;

              @Override
              public Token LT(int lookahead) {
                if ((++reads & 1023) == 0) cancel.check();
                if (reads > 5000000) throw new Limit();
                return super.LT(lookahead);
              }
            };
        tokens.fill();
        for (Token token : tokens.getTokens())
          if (token.getType() == Python3Lexer.STRING) {
            String s = token.getText();
            int quote =
                Math.min(
                    s.indexOf('\'') < 0 ? 10 : s.indexOf('\''),
                    s.indexOf('"') < 0 ? 10 : s.indexOf('"'));
            if (quote < 4
                && s.substring(0, quote).toLowerCase(java.util.Locale.ROOT).indexOf('f') >= 0)
              fstrings = true;
          }
        Python3Parser parser = new Python3Parser(tokens);
        parser.removeErrorListeners();
        parser.addErrorListener(listener);
        ParserRuleContext tree = parser.file_input();
        if (failed[0]) {
          result.diagnostics.add(
              Findings.diagnostic(
                  "PYTHON_PARSE_FAILED",
                  file.path,
                  "Python syntax was not fully parsed; this file contributes no positive security"
                      + " conclusions."));
          return;
        }
        Scope module = new Scope("", file, null, tree);
        scopes.add(module);
        named.put(module.qualified(), module);
        index(tree, module, false, 0);
      } catch (Limit limit) {
        discard(file);
        result.diagnostics.add(
            Findings.diagnostic(
                "PYTHON_ANALYSIS_LIMIT",
                file.path,
                "Python parsing exceeded the bounded token or tree budget; partial syntax was"
                    + " discarded."));
      } catch (StackOverflowError error) {
        discard(file);
        result.diagnostics.add(
            Findings.diagnostic(
                "PYTHON_PARSE_DEPTH",
                file.path,
                "Python parsing exceeded the supported nesting depth; partial syntax was"
                    + " discarded."));
      }
    }

    void discard(SourceFile file) {
      for (java.util.Iterator<ParserRuleContext> it = expressions.iterator(); it.hasNext(); ) {
        Scope owner = owners.get(it.next());
        if (owner != null && owner.file == file) it.remove();
      }
      for (java.util.Iterator<Map.Entry<ParserRuleContext, Scope>> it =
              owners.entrySet().iterator();
          it.hasNext(); ) if (it.next().getValue().file == file) it.remove();
      for (java.util.Iterator<Map.Entry<String, Scope>> it = named.entrySet().iterator();
          it.hasNext(); ) if (it.next().getValue().file == file) it.remove();
      for (java.util.Iterator<Scope> it = scopes.iterator(); it.hasNext(); )
        if (it.next().file == file) it.remove();
    }

    void index(ParserRuleContext n, Scope scope, boolean conditional, int depth) {
      cancel.check();
      if (depth > 180) throw new Limit();
      String k = kind(n);
      if ("Funcdef".equals(k) || "Classdef".equals(k)) {
        Scope child = new Scope(text(direct(n, "Name")), scope.file, scope, n);
        child.owner =
            "Classdef".equals(k)
                ? child
                : ("Classdef".equals(kind(scope.node)) ? scope : scope.owner);
        scopes.add(child);
        named.put(child.qualified(), child);
        scope = child;
        ParserRuleContext params = direct(n, "Parameters");
        if (params != null)
          for (ParserRuleContext p : descendants(params, "Tfpdef"))
            child.parameters.add(text(direct(p, "Name")));
        conditional = false;
      }
      owners.put(n, scope);
      if ("Atom_expr".equals(k)) expressions.add(n);
      if ("Import_name".equals(k))
        for (ParserRuleContext alias : descendants(n, "Dotted_as_name")) {
          String imported = text(direct(alias, "Dotted_name"));
          ParserRuleContext rename = direct(alias, "Name");
          scope.imports.put(
              rename == null ? imported.split("\\.")[0] : text(rename),
              rename == null ? imported.split("\\.")[0] : imported);
        }
      if ("Import_from".equals(k)) {
        String base = text(direct(n, "Dotted_name"));
        for (ParserRuleContext alias : descendants(n, "Import_as_name")) {
          List<ParserRuleContext> names = directs(alias, "Name");
          if (!names.isEmpty())
            scope.imports.put(text(names.get(names.size() - 1)), base + "." + text(names.get(0)));
        }
      }
      if ("Expr_stmt".equals(k)) {
        List<ParserRuleContext> parts = directs(n, "Testlist_star_expr");
        ParserRuleContext ann = direct(n, "Annassign");
        if (parts.size() >= 2)
          scope.bindings.add(
              new Binding(text(parts.get(0)), parts.get(parts.size() - 1), n, false, conditional));
        else if (parts.size() == 1 && ann != null && hasTerminal(ann, "=")) {
          List<ParserRuleContext> tests = directs(ann, "Test");
          if (tests.size() > 1)
            scope.bindings.add(
                new Binding(
                    text(parts.get(0)), tests.get(tests.size() - 1), n, false, conditional));
        } else if (parts.size() == 1 && direct(n, "Augassign") != null) {
          ParserRuleContext rhs = direct(n, "Testlist");
          if (rhs != null) scope.bindings.add(new Binding(text(parts.get(0)), rhs, n, false, true));
        }
      }
      if ("For_stmt".equals(k)) {
        ParserRuleContext lhs = direct(n, "Exprlist"), rhs = direct(n, "Testlist");
        if (lhs != null && rhs != null)
          scope.bindings.add(new Binding(text(lhs), rhs, n, true, conditional));
      }
      if ("Return_stmt".equals(k)) scope.returns.add(n);
      if ("Yield_expr".equals(k)) scope.yields.add(n);
      boolean branch =
          conditional || "If_stmt".equals(k) || "Try_stmt".equals(k) || "While_stmt".equals(k);
      for (int i = 0; i < n.getChildCount(); i++)
        if (n.getChild(i) instanceof ParserRuleContext)
          index((ParserRuleContext) n.getChild(i), scope, branch, depth + 1);
    }

    void scan() {
      for (ParserRuleContext expression : expressions) {
        cancel.check();
        eval(expression, owners.get(expression), 0);
      }
      for (Scope scope : scopes)
        for (ParserRuleContext n : scope.yields) {
          Value value = eval(firstRule(n), scope, 0);
          if (value.kind == RAW)
            add(
                emissions,
                scope,
                n,
                "Model-derived content reaches a Python yield; transport and downstream validation"
                    + " remain unverified.");
        }
      result.aiDetected = !gateways.isEmpty();
      result.gatewayMethods = gateways.size();
      if (result.aiDetected) result.protocols.add("openai-python-sdk");
      if (fstrings)
        result.diagnostics.add(
            Findings.diagnostic(
                "PYTHON_FSTRING_BOUNDARY",
                "",
                "F-string replacement fields are opaque in this parser; their data flow is UNKNOWN"
                    + " and never used to prove a violation."));
      if (exhausted || depthLimited)
        result.diagnostics.add(
            Findings.diagnostic(
                "PYTHON_FLOW_LIMIT",
                "",
                "Python interprocedural flow reached a bounded work or recursion limit."));
      if (!unresolvedModelCalls.isEmpty())
        result.diagnostics.add(
            Findings.diagnostic(
                "PYTHON_UNRESOLVED_MODEL_CALL",
                "",
                "SDK-shaped call sites have unresolved receiver identity, including externally"
                    + " injected clients; see UNKNOWN evidence. These sites do not prove model"
                    + " integration."));
      result.diagnostics.add(
          Findings.diagnostic(
              "PYTHON_STATIC_BOUNDARY",
              "",
              "Python dynamic imports, monkey patching, reflection, external packages and runtime"
                  + " dispatch are not resolved. Custom control semantics remain UNKNOWN."));
      List<Map<String, Object>> gatewayEvidence =
          new ArrayList<Map<String, Object>>(gateways.values());
      for (int i = 0; i < 7; i++) {
        List<Map<String, Object>> ev = new ArrayList<Map<String, Object>>(gatewayEvidence);
        String explanation;
        if (i == 0) {
          ev.addAll(retrieval);
          ev.addAll(unresolvedModelCalls);
          explanation =
              "Recognized SDK model calls and typed retrieval calls are observable; prompt trust"
                  + " levels, template substitution and RAG injection resistance are UNKNOWN.";
        } else if (i == 1) {
          ev.addAll(retrieval);
          explanation =
              "Retrieval calls are inspected structurally; principal binding, effective metadata"
                  + " filters and cross-tenant isolation are UNKNOWN.";
        } else if (i == 2) {
          ev.addAll(candidateLogs);
          explanation =
              "No complete redaction policy is inferred. Candidate dispatch or opaque"
                  + " transformations cannot establish raw-content logging.";
        } else if (i == 3)
          explanation =
              "SDK call parameters do not prove per-principal rate, quota, retry or concurrency"
                  + " enforcement; runtime resource controls are UNKNOWN.";
        else if (i == 4) {
          ev.addAll(emissions);
          ev.addAll(controls);
          explanation =
              "Model-derived yields and calls consuming model values are structural observations"
                  + " only; content safety, decision semantics and fail-closed behavior are"
                  + " UNKNOWN.";
        } else if (i == 5)
          explanation =
              "Source logging is insufficient to prove complete, tamper-resistant audit correlation"
                  + " and retention; end-to-end audit coverage is UNKNOWN.";
        else {
          ev.addAll(controls);
          explanation =
              "Custom output consumers, schemas and decisions require semantic and runtime"
                  + " validation; output acceptance and rollback coverage are UNKNOWN.";
        }
        result.assessments.add(
            Findings.assessment(
                id(i),
                "L" + (i + 1),
                "UNKNOWN",
                "INFO",
                TITLES[i],
                explanation,
                RECOMMENDATIONS[i],
                cap(ev),
                "Bounded native Python AST analysis; absence of a finding is not safety evidence.",
                "F-string interpolation, dynamic dispatch and external implementations are not"
                    + " analyzed."));
      }
      if (!gatewayEvidence.isEmpty())
        result.assessments.add(
            Findings.assessment(
                id(0),
                "L1",
                "OBSERVED",
                "INFO",
                TITLES[0],
                "A constructor from the imported OpenAI SDK reaches a supported model API call."
                    + " This proves integration only.",
                RECOMMENDATIONS[0],
                cap(gatewayEvidence),
                "Client injection and runtime configuration may select a different"
                    + " implementation."));
      if (!toolCalls.isEmpty())
        result.assessments.add(
            Findings.assessment(
                id(6),
                "L7",
                "OBSERVED",
                "INFO",
                TITLES[6],
                "Recognized model tool-call fields are traversed; JSON decoding is not schema"
                    + " validation or authorization.",
                RECOMMENDATIONS[6],
                cap(toolCalls),
                "Tool names, argument constraints and per-tool permissions remain UNKNOWN."));
      if (!budgets.isEmpty())
        result.assessments.add(
            Findings.assessment(
                id(3),
                "L4",
                "OBSERVED",
                "INFO",
                TITLES[3],
                "A supported token-budget argument is supplied to an SDK model call; effective"
                    + " numeric limits and per-principal quotas remain UNKNOWN.",
                RECOMMENDATIONS[3],
                cap(budgets),
                "A call argument alone does not prove enforcement or a safe budget."));
      if (!emissions.isEmpty() || !controls.isEmpty()) {
        List<Map<String, Object>> ev = new ArrayList<Map<String, Object>>(emissions);
        ev.addAll(controls);
        result.assessments.add(
            Findings.assessment(
                id(4),
                "L5",
                "OBSERVED",
                "INFO",
                TITLES[4],
                "Source locations show model-content emission and consumption order; no custom"
                    + " validator is certified as a security control.",
                RECOMMENDATIONS[4],
                cap(ev),
                "Source order alone is not a complete control-flow or runtime guarantee."));
      }
      if (!rawLogs.isEmpty())
        result.assessments.add(
            Findings.assessment(
                id(2),
                "L3",
                "VIOLATED",
                "HIGH",
                TITLES[2],
                "A supported logging API receives content extracted from a recognized SDK model"
                    + " response without a resolved redaction transformation.",
                RECOMMENDATIONS[2],
                cap(rawLogs),
                "The finding establishes a raw-content logging path, not that the content"
                    + " necessarily contains a secret."));
      if (!dangerous.isEmpty())
        result.assessments.add(
            Findings.assessment(
                id(6),
                "L7",
                "VIOLATED",
                "HIGH",
                TITLES[6],
                "Content extracted from a recognized SDK model response reaches Python dynamic code"
                    + " execution.",
                RECOMMENDATIONS[6],
                cap(dangerous),
                "Static evidence establishes the source-to-sink path; reachability still depends on"
                    + " runtime inputs."));
    }

    Value eval(ParserRuleContext n, Scope scope, int depth) {
      Value cached = memo.get(n);
      if (cached != null) return cached.copy();
      int misses = recursiveMisses;
      Value value = evaluate(n, scope, depth);
      if (n != null && !exhausted && recursiveMisses == misses) memo.put(n, value.copy());
      return value;
    }

    Value evaluate(ParserRuleContext n, Scope scope, int depth) {
      if (n == null || scope == null) return none();
      if ((++work & 255) == 0) cancel.check();
      if (depth > 64) {
        depthLimited = true;
        recursiveMisses++;
        return none();
      }
      if (work > 500000) {
        exhausted = true;
        return none();
      }
      String k = kind(n);
      if ("Atom_expr".equals(k)) {
        Value value = eval(direct(n, "Atom"), scope, depth);
        for (ParserRuleContext trailer : directs(n, "Trailer")) {
          ParserRuleContext member = direct(trailer, "Name");
          if (member != null) value = attribute(value, text(member), scope, n, depth + 1);
          else if (hasTerminal(trailer, "[")) {
            value = value.copy();
            if (value.literalContainer) value = none();
            else if (value.kind == STREAM && "tool-items".equals(value.chain)) {
              value.kind = RESPONSE;
              value.chain = "tool";
            } else value.chain += "[]";
          } else if (hasTerminal(trailer, "("))
            value = invoke(new Call(n, scope, value, arguments(trailer)), depth + 1);
        }
        return value;
      }
      if ("Atom".equals(k)) {
        ParserRuleContext name = direct(n, "Name");
        if (name != null) return lookup(text(name), scope, n, depth + 1);
        if (n.getChildCount() > 0 && !(n.getChild(0) instanceof ParserRuleContext)) {
          String lead = n.getChild(0).getText();
          if (!"(".equals(lead) && !"[".equals(lead) && !"{".equals(lead)) return none();
        }
      }
      if ("Name".equals(k)) return lookup(text(n), scope, n, depth + 1);
      if ("Comparison".equals(k) && direct(n, "Comp_op") != null) return none();
      if ("Not_test".equals(k) && hasTerminal(n, "not")) return none();
      List<Value> values = new ArrayList<Value>();
      for (int i = 0; i < n.getChildCount(); i++)
        if (n.getChild(i) instanceof ParserRuleContext)
          values.add(eval((ParserRuleContext) n.getChild(i), scope, depth));
      Value selected = none();
      for (Value value : values)
        if (priority(value.kind) > priority(selected.kind)
            || (selected.symbol.isEmpty() && !value.symbol.isEmpty())) selected = value.copy();
      // Unknown injection alternatives must never prove a definite SDK implementation.
      if (("Or_test".equals(k) || "Test".equals(k))
          && values.size() > 1
          && (selected.kind == CLIENT || selected.kind == INSTANCE)) selected.candidate = true;
      if ("Atom".equals(k) && (hasTerminal(n, "[") || hasTerminal(n, "{")))
        selected.literalContainer = true;
      return selected;
    }

    Value lookup(String name, Scope scope, ParserRuleContext at, int depth) {
      if (depth > 64) {
        depthLimited = true;
        recursiveMisses++;
        return none();
      }
      if ("self".equals(name) && scope.owner != null) {
        Value v = new Value(INSTANCE);
        v.instance = scope.owner;
        return v;
      }
      Scope cursor = scope;
      while (cursor != null) {
        Binding last = null;
        for (Binding binding : cursor.bindings)
          if (binding.name.equals(name)
              && (cursor != scope
                  || (binding.loop ? start(binding.node) < start(at) : before(binding.node, at)))) {
            if (last == null || start(binding.node) > start(last.node)) last = binding;
          }
        if (last != null) return bound(last, cursor, depth + 1);
        if (cursor.parameters.contains(name)) return none();
        if ("Funcdef".equals(kind(cursor.node)))
          for (Binding binding : cursor.bindings) if (binding.name.equals(name)) return none();
        Scope local = named.get(cursor.qualified() + "." + name);
        if (local != null) {
          Value v = none();
          v.symbol = local.qualified();
          return v;
        }
        String imported = cursor.imports.get(name);
        if (imported != null) {
          Value v = none();
          v.symbol = imported;
          return v;
        }
        cursor = cursor.parent;
      }
      Value v = none();
      if ("eval".equals(name) || "exec".equals(name) || "str".equals(name))
        v.symbol = "@builtin." + name;
      return v;
    }

    Value bound(Binding binding, Scope scope, int depth) {
      String key = scope.qualified() + ":" + start(binding.node) + ":" + binding.name;
      if (!active.add(key)) {
        recursiveMisses++;
        return none();
      }
      Value value;
      try {
        value = eval(binding.value, scope, depth + 1).copy();
      } finally {
        active.remove(key);
      }
      if (binding.loop && value.kind == STREAM) {
        String streamKind = value.chain;
        value.kind = "raw-items".equals(streamKind) ? RAW : RESPONSE;
        value.chain = "tool-items".equals(streamKind) ? "tool" : "";
      }
      // Conditional assignment can have a non-model runtime alternative.
      value.candidate |= binding.conditional;
      return value;
    }

    Value attribute(Value original, String name, Scope scope, ParserRuleContext at, int depth) {
      Value value = original.copy();
      if (value.kind == INSTANCE && value.instance != null) {
        Scope klass = value.instance;
        Scope method = named.get(klass.qualified() + "." + name);
        if (method != null) {
          ParseTree parent = method.node.getParent();
          if (parent instanceof ParserRuleContext
              && "Decorated".equals(kind((ParserRuleContext) parent))
              && "@property".equals(text(direct((ParserRuleContext) parent, "Decorators")).trim()))
            return summarize(method, depth + 1);
          value.symbol = method.qualified();
          return value;
        }
        Scope init = named.get(klass.qualified() + ".__init__");
        if (init != null)
          for (int i = init.bindings.size() - 1; i >= 0; i--) {
            Binding binding = init.bindings.get(i);
            if (binding.name.equals("self." + name)) {
              Value result = bound(binding, init, depth + 1);
              for (Scope other : scopes)
                if (other.owner == klass && other != init)
                  for (Binding assignment : other.bindings)
                    if (assignment.name.equals("self." + name)) result.candidate = true;
              return result;
            }
          }
        return none();
      }
      value.chain += "." + name;
      if (!value.symbol.isEmpty()) value.symbol += "." + name;
      if (value.kind == RESPONSE
          && (value.chain.matches("\\.choices\\[\\]\\.(message|delta)\\.content")
              || ".output_text".equals(value.chain))) {
        value.kind = RAW;
        value.chain = "";
      } else if (value.kind == RESPONSE && ".choices[].message.tool_calls".equals(value.chain)) {
        add(
            toolCalls,
            scope,
            at,
            "OpenAI tool-call output is traversed; argument schemas, authorization and tool"
                + " selection remain UNKNOWN.");
        value.kind = STREAM;
        value.chain = "tool-items";
      } else if (value.kind == RESPONSE
          && ("tool.function.arguments".equals(value.chain)
              || "tool.function.name".equals(value.chain))) {
        value.kind = RAW;
        value.chain = "";
      } else if (value.kind == RAW) {
        // An arbitrary attribute on model text is not itself the original content.
        value.kind = UNKNOWN;
      }
      return value;
    }

    Value invoke(Call call, int depth) {
      Value receiver = call.receiver;
      String symbol = receiver.symbol;
      if (receiver.kind != CLIENT
          && (".chat.completions.create".equals(receiver.chain)
              || ".responses.create".equals(receiver.chain)))
        add(
            unresolvedModelCalls,
            call.scope,
            call.node,
            "An SDK-shaped call has unresolved receiver identity; injected client provenance"
                + " remains UNKNOWN.");
      if ("openai.OpenAI".equals(symbol) || "openai.AsyncOpenAI".equals(symbol))
        return new Value(CLIENT);
      if (receiver.kind == CLIENT
          && (".chat.completions.create".equals(receiver.chain)
              || ".responses.create".equals(receiver.chain))) {
        Map<String, Object> ev =
            Findings.evidence(
                call.scope.file.path,
                line(call.node),
                receiver.candidate
                    ? "A candidate imported OpenAI client reaches a supported model API call;"
                          + " injected runtime selection is UNKNOWN."
                    : "An imported OpenAI SDK client reaches a supported model API call.");
        gateways.put(call.scope.file.path + ":" + line(call.node) + ":" + start(call.node), ev);
        for (ParserRuleContext arg : call.args) {
          List<ParserRuleContext> fields = directs(arg, "Test");
          if (fields.size() == 2
              && ("max_tokens".equals(text(fields.get(0)))
                  || "max_completion_tokens".equals(text(fields.get(0)))
                  || "max_output_tokens".equals(text(fields.get(0)))))
            add(
                budgets,
                call.scope,
                call.node,
                "A recognized token-budget keyword is passed to the SDK model API; effective"
                    + " enforcement is UNKNOWN.");
        }
        Value v = new Value(keywordTrue(call.args, "stream") ? STREAM : RESPONSE);
        v.candidate = receiver.candidate;
        v.evidence.add(ev);
        return v;
      }
      if ("logging.getLogger".equals(symbol)) return new Value(LOGGER);
      if ("chromadb.Client".equals(symbol)
          || "chromadb.PersistentClient".equals(symbol)
          || "chromadb.HttpClient".equals(symbol)) return new Value(CHROMA);
      if (receiver.kind == CHROMA
          && (".get_collection".equals(receiver.chain)
              || ".get_or_create_collection".equals(receiver.chain))) return new Value(COLLECTION);
      if (receiver.kind == COLLECTION && ".query".equals(receiver.chain)) {
        add(
            retrieval,
            call.scope,
            call.node,
            "A Chroma collection query is observed; effective tenant constraints and document trust"
                + " are UNKNOWN.");
        return new Value(RETRIEVAL);
      }
      List<Value> values = new ArrayList<Value>();
      for (ParserRuleContext arg : call.args)
        values.add(eval(argumentValue(arg), call.scope, depth + 1));
      boolean log =
          (receiver.kind == LOGGER
                  && receiver.chain.matches(
                      "\\.(debug|info|warning|warn|error|exception|critical|log)"))
              || symbol.matches("logging\\.(debug|info|warning|warn|error|exception|critical|log)");
      for (Value value : values)
        if (value.kind == RAW) {
          if (log) {
            List<Map<String, Object>> destination = value.candidate ? candidateLogs : rawLogs;
            destination.addAll(value.evidence);
            add(
                destination,
                call.scope,
                call.node,
                value.candidate
                    ? "A logging call consumes candidate model content; runtime source remains"
                          + " UNKNOWN."
                    : "A supported logging call consumes model response content.");
          } else if (("@builtin.eval".equals(symbol)
                  || "@builtin.exec".equals(symbol)
                  || "os.system".equals(symbol))
              && !value.candidate
              && !value.literalContainer) {
            dangerous.addAll(value.evidence);
            add(
                dangerous,
                call.scope,
                call.node,
                "Model response content reaches a supported dynamic execution sink.");
          } else if (!"json.loads".equals(symbol)
              && !"json.dumps".equals(symbol)
              && !"@builtin.str".equals(symbol))
            add(
                controls,
                call.scope,
                call.node,
                "A call consumes model-derived content; its decision and sanitization semantics are"
                    + " UNKNOWN.");
        }
      if (("json.loads".equals(symbol)
              || "json.dumps".equals(symbol)
              || "@builtin.str".equals(symbol))
          && !values.isEmpty()) return values.get(0).copy();
      Scope target = named.get(symbol);
      if (target != null && "Classdef".equals(kind(target.node))) {
        Value value = new Value(INSTANCE);
        value.instance = target;
        return value;
      }
      if (target != null && "Funcdef".equals(kind(target.node))) {
        Value value = summarize(target, depth + 1).copy();
        value.candidate |= receiver.candidate;
        return value;
      }
      return none();
    }

    Value summarize(Scope target, int depth) {
      String key = "return:" + target.qualified();
      if (depth > 64) {
        depthLimited = true;
        recursiveMisses++;
        return none();
      }
      if (!active.add(key)) {
        recursiveMisses++;
        return none();
      }
      try {
        Value out = none();
        for (ParserRuleContext ret : target.returns) {
          Value value = eval(firstRule(ret), target, depth + 1);
          if (priority(value.kind) > priority(out.kind)) out = value.copy();
          else if (value.kind != UNKNOWN
              && value.kind == out.kind
              && !value.symbol.equals(out.symbol)) out.candidate = true;
        }
        if (out.kind != UNKNOWN && target.returns.size() > 1) {
          for (ParserRuleContext ret : target.returns) {
            Value alternative = eval(firstRule(ret), target, depth + 1);
            if (alternative.kind != out.kind || alternative.candidate) out.candidate = true;
          }
        }
        for (ParserRuleContext yield : target.yields) {
          Value value = eval(firstRule(yield), target, depth + 1);
          if (value.kind == RAW) {
            out = value.copy();
            out.kind = STREAM;
            out.chain = "raw-items";
            break;
          }
        }
        if (target.node.getParent() instanceof ParserRuleContext
            && "Decorated".equals(kind((ParserRuleContext) target.node.getParent())))
          out.candidate = true;
        return out;
      } finally {
        active.remove(key);
      }
    }

    void add(
        List<Map<String, Object>> destination, Scope scope, ParserRuleContext n, String detail) {
      String key = scope.file.path + ":" + line(n) + ":" + detail;
      if (seen.add(key)) destination.add(Findings.evidence(scope.file.path, line(n), detail));
    }

    List<Map<String, Object>> cap(List<Map<String, Object>> values) {
      Set<String> unique = new LinkedHashSet<String>();
      for (Map<String, Object> value : values) unique.add(value.toString());
      if (unique.size() > 16 && seen.add("RESULT_LIMIT"))
        result.diagnostics.add(
            Findings.diagnostic(
                "PYTHON_RESULT_LIMIT",
                "",
                "At least one Python assessment exceeded 16 unique evidence locations; extra"
                    + " evidence was omitted."));
      return PythonAnalysis.cap(values);
    }
  }

  private static final class Limit extends RuntimeException {
    private static final long serialVersionUID = 1L;
  }

  private static Value none() {
    return new Value(UNKNOWN);
  }

  private static int priority(int kind) {
    return kind == RAW ? 100 : kind == STREAM ? 90 : kind;
  }

  private static String moduleName(String path) {
    String name = path.replace('\\', '/').replaceAll("\\.py$", "").replace('/', '.');
    if (name.endsWith(".__init__")) name = name.substring(0, name.length() - 9);
    return name;
  }

  private static String kind(ParserRuleContext n) {
    if (n == null) return "";
    String name = n.getClass().getSimpleName();
    return name.endsWith("Context") ? name.substring(0, name.length() - 7) : name;
  }

  private static String text(ParserRuleContext n) {
    return n == null ? "" : n.getText();
  }

  private static int line(ParserRuleContext n) {
    return n.getStart().getLine();
  }

  private static int start(ParserRuleContext n) {
    return n.getStart().getTokenIndex();
  }

  private static boolean before(ParserRuleContext binding, ParserRuleContext at) {
    return binding.getStop().getTokenIndex() < start(at);
  }

  private static ParserRuleContext direct(ParserRuleContext n, String name) {
    if (n == null) return null;
    for (int i = 0; i < n.getChildCount(); i++)
      if (n.getChild(i) instanceof ParserRuleContext
          && kind((ParserRuleContext) n.getChild(i)).equals(name))
        return (ParserRuleContext) n.getChild(i);
    return null;
  }

  private static List<ParserRuleContext> directs(ParserRuleContext n, String name) {
    List<ParserRuleContext> out = new ArrayList<ParserRuleContext>();
    if (n != null)
      for (int i = 0; i < n.getChildCount(); i++)
        if (n.getChild(i) instanceof ParserRuleContext
            && kind((ParserRuleContext) n.getChild(i)).equals(name))
          out.add((ParserRuleContext) n.getChild(i));
    return out;
  }

  private static List<ParserRuleContext> descendants(ParserRuleContext n, String name) {
    List<ParserRuleContext> out = new ArrayList<ParserRuleContext>();
    if (n == null) return out;
    for (int i = 0; i < n.getChildCount(); i++)
      if (n.getChild(i) instanceof ParserRuleContext) {
        ParserRuleContext c = (ParserRuleContext) n.getChild(i);
        if (kind(c).equals(name)) out.add(c);
        else out.addAll(descendants(c, name));
      }
    return out;
  }

  private static ParserRuleContext firstRule(ParserRuleContext n) {
    if (n != null)
      for (int i = 0; i < n.getChildCount(); i++)
        if (n.getChild(i) instanceof ParserRuleContext) return (ParserRuleContext) n.getChild(i);
    return null;
  }

  private static boolean hasTerminal(ParserRuleContext n, String token) {
    if (n != null)
      for (int i = 0; i < n.getChildCount(); i++)
        if (!(n.getChild(i) instanceof ParserRuleContext) && token.equals(n.getChild(i).getText()))
          return true;
    return false;
  }

  private static List<ParserRuleContext> arguments(ParserRuleContext trailer) {
    return directs(direct(trailer, "Arglist"), "Argument");
  }

  private static ParserRuleContext argumentValue(ParserRuleContext arg) {
    List<ParserRuleContext> tests = directs(arg, "Test");
    return tests.isEmpty() ? arg : tests.get(tests.size() - 1);
  }

  private static boolean keywordTrue(List<ParserRuleContext> args, String name) {
    for (ParserRuleContext arg : args) {
      List<ParserRuleContext> tests = directs(arg, "Test");
      if (tests.size() == 2 && text(tests.get(0)).equals(name) && text(tests.get(1)).equals("True"))
        return true;
    }
    return false;
  }

  private static List<Map<String, Object>> cap(List<Map<String, Object>> values) {
    List<Map<String, Object>> out = new ArrayList<Map<String, Object>>();
    Set<String> seen = new LinkedHashSet<String>();
    for (Map<String, Object> value : values)
      if (seen.add(value.toString())) {
        out.add(value);
        if (out.size() == 16) break;
      }
    return out;
  }
}
