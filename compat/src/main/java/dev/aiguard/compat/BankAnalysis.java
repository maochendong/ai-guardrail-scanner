package dev.aiguard.compat;

import java.util.*;

/** Contract-based bounded local interpretation. It never executes application code. */
public final class BankAnalysis {
  public final List<Map<String, Object>> assessments = new ArrayList<Map<String, Object>>();
  public final List<Map<String, Object>> diagnostics = new ArrayList<Map<String, Object>>();
  private final BankPolicy policy;
  private final Cancel cancel;
  private final Map<String, Outcome> outcomes = new LinkedHashMap<String, Outcome>();
  private final Map<String, String> literals = new HashMap<String, String>();
  private int operations, serial;
  private boolean incomplete;
  private List<State> exceptionFrame;

  private BankAnalysis(BankPolicy policy, Cancel cancel) {
    this.policy = policy;
    this.cancel = cancel;
  }

  public static BankAnalysis analyze(Inventory inventory, BankPolicy policy, Cancel cancel) {
    if (policy.contractCount() == 0) {
      BankFlow.Program empty = new BankFlow.Program();
      empty.diagnostics.add(
          Findings.diagnostic(
              "BANK_POLICY_UNMAPPED",
              "",
              "No operator semantic contracts supplied; bank controls remain unassessed."));
      return analyze(empty, policy, cancel);
    }
    BankFlow.Program java = BankJavaAnalysis.adapt(inventory.javaAndConfig, cancel);
    BankFlow.Program python = BankPythonAnalysis.adapt(inventory.python, cancel);
    java.functions.addAll(python.functions);
    java.diagnostics.addAll(python.diagnostics);
    return analyze(java, policy, cancel);
  }

  public static BankAnalysis analyze(BankFlow.Program program, BankPolicy policy, Cancel cancel) {
    BankAnalysis analysis = new BankAnalysis(policy, cancel);
    analysis.diagnostics.addAll(program.diagnostics);
    analysis.incomplete = !program.diagnostics.isEmpty();
    try {
      for (BankFlow.Function function : program.functions) {
        analysis.tick();
        State initial = new State();
        for (String param : function.params) initial.vars.put(param, analysis.fresh(null));
        analysis.walk(function.body, Arrays.asList(initial), 0);
      }
    } catch (Limit limit) {
      analysis.incomplete = true;
      analysis.diagnostics.add(
          Findings.diagnostic(
              "BANK_FLOW_LIMIT",
              "",
              "Bank local-flow budget exhausted; remaining paths are unknown."));
    }
    analysis.finish();
    return analysis;
  }

  private static final class Value {
    String id;
    boolean opaque, sensitive, redacted, trusted, identityKnown;
    boolean sense = true;
    Boolean bool;
    Proof decision;
    boolean accepted = true;
    final List<Map<String, Object>> trace = new ArrayList<Map<String, Object>>();
  }

  private static final class Proof {
    String key;
    int epoch;
    Map<String, Object> evidence;
  }

  private static final class State {
    final Map<String, Value> vars = new HashMap<String, Value>();
    final Map<String, Proof> proofs = new LinkedHashMap<String, Proof>();
    final Map<String, Boolean> conditions = new HashMap<String, Boolean>();
    final Set<String> invalidated = new HashSet<String>();
    boolean uncertain;
    int epoch;
    String stopped = "";

    State copy() {
      State copy = new State();
      copy.vars.putAll(vars);
      copy.proofs.putAll(proofs);
      copy.conditions.putAll(conditions);
      copy.invalidated.addAll(invalidated);
      copy.uncertain = uncertain;
      copy.stopped = stopped;
      copy.epoch = epoch;
      return copy;
    }
  }

  private static final class Outcome {
    boolean violated, unknown;
    int sites;
    final Set<String> seen = new HashSet<String>();
    final List<Map<String, Object>> evidence = new ArrayList<Map<String, Object>>();
  }

  private static final class Limit extends RuntimeException {
    private static final long serialVersionUID = 1L;
  }

  private void tick() {
    cancel.check();
    if (++operations > 200000) throw new Limit();
  }

  private Value fresh(BankFlow.Expr expr) {
    Value value = new Value();
    value.id = "v" + (++serial);
    return value;
  }

  private Value unknown(BankFlow.Expr expr) {
    Value v = fresh(expr);
    v.opaque = true;
    return v;
  }

  private List<State> walk(List<BankFlow.Stmt> block, List<State> states, int depth) {
    if (depth > 64 || states.size() > 64) throw new Limit();
    List<State> current = states;
    for (BankFlow.Stmt statement : block) {
      tick();
      List<State> next = new ArrayList<State>();
      for (State state : current) {
        if (!state.stopped.isEmpty()) {
          next.add(state);
          continue;
        }
        if ("ASSIGN".equals(statement.kind)) {
          Value value = eval(statement.expr, state, 0);
          if (statement.target.isEmpty()) {
            state.uncertain = true;
            state.proofs.clear();
          } else state.vars.put(statement.target, value);
          next.add(state);
        } else if ("EXPR".equals(statement.kind)) {
          eval(statement.expr, state, 0);
          next.add(state);
        } else if ("RETURN".equals(statement.kind) || "THROW".equals(statement.kind)) {
          if (statement.expr != null) eval(statement.expr, state, 0);
          if ("THROW".equals(statement.kind)) exceptional(state);
          state.stopped = statement.kind;
          next.add(state);
        } else if ("IF".equals(statement.kind)) {
          next.addAll(
              walk(statement.body, branch(statement.expr, state.copy(), true, 0), depth + 1));
          next.addAll(
              walk(statement.otherwise, branch(statement.expr, state.copy(), false, 0), depth + 1));
        } else if ("TRY".equals(statement.kind)) {
          List<State> previousFrame = exceptionFrame;
          List<State> thrown = new ArrayList<State>();
          exceptionFrame = thrown;
          List<State> tried;
          try {
            tried = walk(statement.body, Arrays.asList(state.copy()), depth + 1);
          } finally {
            exceptionFrame = previousFrame;
          }
          List<State> normal = new ArrayList<State>();
          for (State s : tried) {
            if (s.stopped.isEmpty())
              normal.addAll(walk(statement.otherwise, Arrays.asList(s), depth + 1));
            else if (!"THROW".equals(s.stopped)) normal.add(s);
          }
          // Capture reachable throw points before the operation establishes its result.
          // Exception types are not inferred; every declared handler remains a candidate.
          for (State thrownState : thrown) {
            for (List<BankFlow.Stmt> handler : statement.handlers)
              normal.addAll(walk(handler, Arrays.asList(thrownState.copy()), depth + 1));
            State escaping = thrownState.copy();
            escaping.stopped = "THROW";
            normal.add(escaping);
          }
          for (State s : normal) {
            String stopped = s.stopped;
            s.stopped = "";
            for (State finished : walk(statement.finalizer, Arrays.asList(s), depth + 1)) {
              if (finished.stopped.isEmpty()) finished.stopped = stopped;
              if ("THROW".equals(finished.stopped)) exceptional(finished);
              next.add(finished);
            }
          }
        } else {
          incomplete = true;
          state.uncertain = true;
          state.proofs.clear();
          exceptional(state);
          if (statement.expr != null) eval(statement.expr, state, 0);
          List<State> candidates =
              new ArrayList<State>(walk(statement.body, Arrays.asList(state.copy()), depth + 1));
          candidates.addAll(walk(statement.otherwise, Arrays.asList(state.copy()), depth + 1));
          for (State candidate : candidates) state.vars.putAll(candidate.vars);
          next.add(state);
        }
        if (next.size() > 64) throw new Limit();
      }
      current = next;
    }
    return current;
  }

  private void exceptional(State state) {
    if (exceptionFrame != null) {
      if (exceptionFrame.size() >= 64) throw new Limit();
      State copy = state.copy();
      copy.stopped = "";
      exceptionFrame.add(copy);
    }
  }

  private List<State> branch(BankFlow.Expr expr, State state, boolean desired, int depth) {
    tick();
    if (depth > 64) throw new Limit();
    if (expr != null
        && "UNARY".equals(expr.kind)
        && Arrays.asList("!", "not").contains(expr.operator)
        && expr.args.size() == 1) return branch(expr.args.get(0), state, !desired, depth + 1);
    if (expr != null && "BINARY".equals(expr.kind) && expr.args.size() == 2) {
      String op = expr.operator;
      boolean and = "&&".equals(op) || "and".equals(op), or = "||".equals(op) || "or".equals(op);
      if (and || or) {
        boolean both = and ? desired : !desired;
        List<State> left = branch(expr.args.get(0), state.copy(), desired, depth + 1);
        List<State> out = new ArrayList<State>();
        if (both) for (State s : left) out.addAll(branch(expr.args.get(1), s, desired, depth + 1));
        else {
          out.addAll(left);
          for (State s : branch(expr.args.get(0), state, !desired, depth + 1))
            out.addAll(branch(expr.args.get(1), s, desired, depth + 1));
        }
        if (out.size() > 64) throw new Limit();
        return out;
      }
    }
    Value value = eval(expr, state, 0);
    if (value.bool != null && value.bool.booleanValue() != desired) return Collections.emptyList();
    boolean originalDesired = desired == value.sense;
    Boolean prior = state.conditions.get(value.id);
    if (prior != null && prior.booleanValue() != originalDesired) return Collections.emptyList();
    state.conditions.put(value.id, originalDesired);
    if (value.opaque || (value.decision != null && value.decision.epoch != state.epoch))
      state.uncertain = true;
    if (value.decision != null && value.decision.epoch == state.epoch && desired == value.accepted)
      state.proofs.put(value.decision.key, value.decision);
    return Arrays.asList(state);
  }

  private Value eval(BankFlow.Expr expr, State state, int depth) {
    tick();
    if (depth > 64) throw new Limit();
    if (expr == null) return unknown(null);
    if ("UNKNOWN".equals(expr.kind) && (!expr.args.isEmpty() || expr.receiver != null)) {
      state.uncertain = true;
      incomplete = true;
    }
    if ("NAME".equals(expr.kind)) {
      Value value = state.vars.get(expr.name);
      return value == null ? unknown(expr) : value;
    }
    if ("LITERAL".equals(expr.kind)) {
      Value value = fresh(expr);
      String literalKey =
          expr.literal == null
              ? "null"
              : expr.literal.getClass().getName() + ":" + String.valueOf(expr.literal);
      String known = literals.get(literalKey);
      if (known == null) {
        known = value.id;
        literals.put(literalKey, known);
      }
      value.id = known;
      if (expr.literal instanceof Boolean) value.bool = (Boolean) expr.literal;
      return value;
    }
    if ("BINARY".equals(expr.kind)
        && expr.args.size() == 2
        && Arrays.asList("&&", "||", "and", "or").contains(expr.operator)) {
      Value left = eval(expr.args.get(0), state, depth + 1);
      boolean and = "&&".equals(expr.operator) || "and".equals(expr.operator);
      if (left.bool != null) {
        if (left.bool.booleanValue() != and) return left;
        return eval(expr.args.get(1), state, depth + 1);
      }
      BankFlow.Expr right = expr.args.get(1);
      if ("LITERAL".equals(right.kind) && right.literal instanceof Boolean) {
        if (((Boolean) right.literal).booleanValue() == and) return left;
        return eval(right, state, depth + 1);
      }
      state.uncertain = true;
      eval(right, state, depth + 1);
      return unknown(expr);
    }
    Value receiver = expr.receiver == null ? null : eval(expr.receiver, state, depth + 1);
    List<Value> args = new ArrayList<Value>();
    for (BankFlow.Expr arg : expr.args) args.add(eval(arg, state, depth + 1));
    if ("UNARY".equals(expr.kind)
        && args.size() == 1
        && Arrays.asList("!", "not").contains(expr.operator)) {
      Value value = copy(args.get(0));
      if (value.bool != null) value.bool = !value.bool;
      value.accepted = !value.accepted;
      value.sense = !value.sense;
      return value;
    }
    if ("BINARY".equals(expr.kind)
        && args.size() == 2
        && Arrays.asList("==", "!=", "is", "is not").contains(expr.operator)) {
      Value value = null;
      Boolean compare = null;
      if (args.get(1).bool != null) {
        value = copy(args.get(0));
        compare = args.get(1).bool;
      } else if (args.get(0).bool != null) {
        value = copy(args.get(1));
        compare = args.get(0).bool;
      }
      if (value != null) {
        boolean invert =
            (!compare.booleanValue())
                ^ ("!=".equals(expr.operator) || "is not".equals(expr.operator));
        if (invert) {
          value.accepted = !value.accepted;
          value.sense = !value.sense;
          if (value.bool != null) value.bool = !value.bool;
        }
        return value;
      }
    }
    if ("CALL".equals(expr.kind)) {
      BankPolicy.Contract contract = policy.contract(expr.symbol, args.size());
      if (contract == null) {
        State raised = state.copy();
        raised.uncertain = true;
        raised.proofs.clear();
        raised.epoch++;
        exceptional(raised);
      } else exceptional(state);
      if (contract != null) {
        if ("source".equals(contract.kind)) {
          Value value = fresh(expr);
          value.sensitive = "sensitive".equals(contract.label);
          value.trusted = "trusted-identity".equals(contract.label);
          value.identityKnown = value.trusted || "untrusted-identity".equals(contract.label);
          value.trace.add(location(expr, "source", "Operator-mapped value source."));
          return value;
        }
        if ("transform".equals(contract.kind)) {
          Value value = copy(args.get(contract.arg));
          value.id = "v" + (++serial);
          value.opaque |= state.invalidated.contains(args.get(contract.arg).id);
          value.redacted = true;
          value.trusted = false;
          value.decision = null;
          value.bool = null;
          append(value.trace, location(expr, "transform", "Mapped redaction return value used."));
          return value;
        }
        if ("check".equals(contract.kind)) {
          Value value = fresh(expr);
          List<Value> checked = select(args, contract.args);
          if (!opaque(checked, state)) {
            Proof proof = new Proof();
            proof.key = key(contract.control, checked);
            proof.epoch = state.epoch;
            proof.evidence =
                location(expr, "control", "Mapped check accepted for these exact argument values.");
            value.decision = proof;
            value.accepted = contract.accept;
          } else value.opaque = true;
          return value;
        }
        sink(contract, expr, args, state);
        // Sinks may return results but their content and validation are not inferred.
        return unknown(expr);
      }
      if (receiver != null) args.add(receiver);
      invalidateCall(state, args);
      // A callback may alter input objects; no previously checked mutable value stays proven.
      return unknown(expr);
    }
    if ("COMPOSITE".equals(expr.kind) || "BINARY".equals(expr.kind)) {
      Value value = fresh(expr);
      value.redacted = true;
      value.opaque = true;
      for (Value arg : args) {
        value.opaque |= arg.opaque;
        value.sensitive |= arg.sensitive;
        if (arg.sensitive && !arg.redacted) value.redacted = false;
        for (Map<String, Object> evidence : arg.trace) append(value.trace, evidence);
      }
      return value;
    }
    if (!expr.args.isEmpty() || expr.receiver != null) invalidateCall(state, args);
    return unknown(expr);
  }

  private void invalidateCall(State state, List<Value> args) {
    if (!state.proofs.isEmpty()) state.uncertain = true;
    state.proofs.clear();
    state.epoch++;
    Set<String> touched = new HashSet<String>();
    for (Value arg : args) touched.add(arg.id);
    state.invalidated.addAll(touched);
    for (Map.Entry<String, Value> entry : state.vars.entrySet()) {
      if (touched.contains(entry.getValue().id)) {
        Value changed = copy(entry.getValue());
        changed.opaque = true;
        changed.decision = null;
        changed.bool = null;
        entry.setValue(changed);
      }
    }
  }

  private Value copy(Value source) {
    Value value = new Value();
    value.id = source.id;
    value.opaque = source.opaque;
    value.sensitive = source.sensitive;
    value.redacted = source.redacted;
    value.trusted = source.trusted;
    value.identityKnown = source.identityKnown;
    value.sense = source.sense;
    value.bool = source.bool;
    value.decision = source.decision;
    value.accepted = source.accepted;
    value.trace.addAll(source.trace);
    return value;
  }

  private List<Value> select(List<Value> values, List<Integer> slots) {
    List<Value> out = new ArrayList<Value>();
    for (Integer slot : slots) out.add(values.get(slot));
    return out;
  }

  private boolean opaque(List<Value> values, State state) {
    for (Value value : values)
      if (value.opaque || state.invalidated.contains(value.id)) return true;
    return false;
  }

  private String key(String control, List<Value> values) {
    StringBuilder out = new StringBuilder(control);
    for (Value value : values) out.append(':').append(value.id);
    return out.toString();
  }

  private void sink(
      BankPolicy.Contract contract, BankFlow.Expr expr, List<Value> args, State state) {
    List<Value> data = select(args, contract.args);
    List<Value> scoped = new ArrayList<Value>();
    if (contract.identity >= 0) scoped.add(args.get(contract.identity));
    scoped.addAll(data);
    if ("egress".equals(contract.channel)) {
      boolean sensitive = false, redacted = true;
      for (Value value : data) {
        sensitive |= value.sensitive;
        if (value.sensitive && !value.redacted) redacted = false;
      }
      record(BankPolicy.DATA, expr, data, state, redacted, null, !sensitive);
    } else if ("release".equals(contract.channel))
      check(BankPolicy.GUARD, "guard", expr, data, state, true);
    else if ("access".equals(contract.channel) || "retrieve".equals(contract.channel)) {
      check(BankPolicy.IAM, "scope", expr, scoped, state, args.get(contract.identity).trusted);
      if ("retrieve".equals(contract.channel))
        check(BankPolicy.ACL, "doc-acl", expr, scoped, state, true);
    } else if ("recommend".equals(contract.channel)) {
      check(BankPolicy.FACTS, "facts", expr, data, state, true);
      check(
          BankPolicy.SUITABILITY,
          "suitability",
          expr,
          scoped,
          state,
          args.get(contract.identity).trusted);
    } else if ("tool".equals(contract.channel))
      check(BankPolicy.CAPABILITY, "capability", expr, data, state, true);
  }

  private void check(
      String id,
      String control,
      BankFlow.Expr expr,
      List<Value> values,
      State state,
      boolean extra) {
    Proof proof = state.proofs.get(key(control, values));
    boolean identityUnknown =
        (BankPolicy.IAM.equals(id) || BankPolicy.SUITABILITY.equals(id))
            && !values.get(0).identityKnown;
    record(id, expr, values, state, proof != null && extra, proof, identityUnknown);
  }

  private void record(
      String id,
      BankFlow.Expr expr,
      List<Value> values,
      State state,
      boolean covered,
      Proof proof,
      boolean noClassification) {
    if (!policy.ruleIds().contains(id)) return;
    Outcome outcome = outcomes.get(id);
    if (outcome == null) {
      outcome = new Outcome();
      outcomes.put(id, outcome);
    }
    boolean unknown = state.uncertain || opaque(values, state) || noClassification;
    String disposition = unknown ? "UNKNOWN" : covered ? "OBSERVED" : "VIOLATED";
    if (!outcome.seen.add(expr.path + ":" + expr.line + ":" + disposition)) return;
    outcome.sites++;
    outcome.unknown |= unknown;
    outcome.violated |= "VIOLATED".equals(disposition);
    List<Map<String, Object>> chain = new ArrayList<Map<String, Object>>();
    for (Value value : values)
      for (Map<String, Object> location : value.trace) append(chain, location);
    if (proof != null) append(chain, proof.evidence);
    append(
        chain,
        location(
            expr,
            "sink",
            unknown
                ? "Mapped sink reached with unresolved value or control flow."
                : covered
                    ? "Mapped sink uses the checked/transformed value on this path."
                    : "Mapped sink has a local path without its required bound control."));
    if ("VIOLATED".equals(disposition)) {
      chain.addAll(outcome.evidence);
      outcome.evidence.clear();
      for (Map<String, Object> e : chain) append(outcome.evidence, e);
    } else for (Map<String, Object> e : chain) append(outcome.evidence, e);
  }

  private static void append(List<Map<String, Object>> list, Map<String, Object> evidence) {
    if (list.size() < 16 && !list.contains(evidence)) list.add(evidence);
  }

  private static Map<String, Object> location(BankFlow.Expr expr, String role, String detail) {
    String path = expr == null ? "" : expr.path;
    int line = expr == null ? 1 : Math.max(1, expr.line);
    Map<String, Object> out = Findings.evidence(path, line, detail);
    out.put("role", role);
    out.put("nodeId", path + ":" + line + ":" + role);
    return out;
  }

  private void finish() {
    if (incomplete && diagnostics.isEmpty())
      diagnostics.add(
          Findings.diagnostic(
              "BANK_FLOW_INCOMPLETE",
              "",
              "Unsupported local control flow remains; bank coverage is incomplete."));
    for (String id : policy.ruleIds()) {
      Outcome outcome = outcomes.get(id);
      String disposition =
          outcome != null && outcome.violated
              ? "VIOLATED"
              : outcome == null || outcome.unknown || incomplete ? "UNKNOWN" : "OBSERVED";
      List<Map<String, Object>> evidence =
          outcome == null ? Collections.<Map<String, Object>>emptyList() : outcome.evidence;
      Map<String, Object> finding =
          Findings.assessment(
              id,
              BankPolicy.domain(id),
              disposition,
              "HIGH",
              BankPolicy.title(id),
              outcome == null
                  ? "No fully mapped applicable sink was resolved; missing mappings are not a pass."
                  : "VIOLATED".equals(disposition)
                      ? "A bounded local path reaches an operator-mapped sink without its required"
                            + " value-bound control."
                      : "UNKNOWN".equals(disposition)
                          ? "Mapped evidence exists but unresolved flow or source semantics"
                                + " prevents a coverage conclusion."
                          : "The mapped local sink paths use required controls on the same values;"
                                + " implementation semantics remain operator assumptions.",
              "Bind trusted API semantics and verify rejection, exception, timeout and streaming"
                  + " behavior with runtime tests.",
              evidence,
              "Operator contract assumptions are not implementation verification.",
              "Local flow only; cross-function, alias mutation and dynamic behavior may remain"
                  + " unknown.",
              "No security certification or regulatory compliance determination.");
      finding.put("profile", policy.profile);
      finding.put("mappedPathOutcomes", outcome == null ? 0 : outcome.sites);
      assessments.add(finding);
    }
  }
}
