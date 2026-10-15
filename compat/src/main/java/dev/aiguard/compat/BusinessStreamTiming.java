package dev.aiguard.compat;

import java.math.BigDecimal;
import java.util.*;

/** Independent, bounded facts about the first local release on a synchronous path. */
public final class BusinessStreamTiming {
  public final List<Map<String, Object>> sites = new ArrayList<Map<String, Object>>();
  public boolean truncated;
  private static final List<String> LIMITS =
      Collections.unmodifiableList(
          Arrays.asList(
              "FIRST_MAPPED_LOCAL_RELEASE_ON_A_MODELED_PATH",
              "ZERO_OR_ONE_ITERATION_ONLY",
              "SYNCHRONOUS_LOCAL_FLOW_ONLY",
              "VALUE_IDENTITY_NOT_CONTENT_EQUALITY",
              "UNMAPPED_RELEASES_NOT_EXCLUDED",
              "NOT_NETWORK_DELIVERY_OR_ALL_CHUNKS",
              "CANDIDATE_CHECK_IS_NOT_SECURITY_ASSURANCE"));
  private final Set<Map<String, Object>> seen = new HashSet<Map<String, Object>>();
  private BusinessPolicy policy;
  private Cancel cancel;
  private BusinessFlow.Function function;
  private List<State> exceptionFrame;
  private int serial, operations, operationLimit;

  public static BusinessStreamTiming analyze(
      BusinessFlow.Program program, BusinessPolicy policy, Cancel cancel) {
    BusinessStreamTiming analysis = new BusinessStreamTiming();
    analysis.policy = policy;
    analysis.cancel = cancel;
    // Scheduling is based only on operator-mapped boundaries, never application names.
    List<BusinessFlow.Function> candidates = new ArrayList<BusinessFlow.Function>();
    Set<String> callBoundaries = new HashSet<String>();
    for (BusinessPolicy.Contract contract : policy.allContracts())
      if ("sink".equals(contract.kind)
          && "release".equals(contract.channel)
          && "call".equals(contract.boundary)) callBoundaries.add(contract.symbol);
    cancel.check();
    for (BusinessFlow.Function function : program.functions) {
      cancel.check();
      if (analysis.mayRelease(function, callBoundaries)) candidates.add(function);
    }
    // Each candidate gets a fair, independent share; a hard function cannot starve later ones.
    analysis.operationLimit = Math.min(100000, 1000000 / Math.max(1, candidates.size()));
    for (BusinessFlow.Function function : candidates) {
      cancel.check();
      analysis.operations = 0;
      analysis.exceptionFrame = null;
      analysis.function = function;
      try {
        analysis.tick();
        State start = new State();
        start.orderOpaque =
            function.executionUncertain || program.incompletePaths.contains(function.path);
        for (String param : function.params) start.vars.put(param, analysis.unknown());
        for (State exit : analysis.walk(function.body, Arrays.asList(start), 0)) {
          if ("RETURN".equals(exit.stopped) && exit.returnStatement != null)
            analysis.boundary(exit.returnStatement, exit.returnValue, exit);
          analysis.finish(exit);
        }
      } catch (Limit limit) {
        // Discard this unfinished path; all other candidates retain their own bounded budget.
        analysis.truncated = true;
      } finally {
        analysis.exceptionFrame = null;
      }
    }
    return analysis;
  }

  /** A bounded syntactic filter. An incomplete traversal stays a candidate, never excluded. */
  private boolean mayRelease(BusinessFlow.Function function, Set<String> callBoundaries) {
    BusinessPolicy.Contract boundary = policy.contract(function.symbol, function.params.size());
    if (boundary != null
        && "sink".equals(boundary.kind)
        && "release".equals(boundary.channel)
        && !"call".equals(boundary.boundary)) return true;
    Deque<Object> pending = new ArrayDeque<Object>();
    pending.addAll(function.body);
    Set<Object> visited = Collections.newSetFromMap(new IdentityHashMap<Object, Boolean>());
    while (!pending.isEmpty()) {
      cancel.check();
      Object node = pending.removeLast();
      if (!visited.add(node)) continue;
      if (visited.size() > 20000) {
        truncated = true;
        return true;
      }
      if (node instanceof BusinessFlow.Stmt) {
        BusinessFlow.Stmt statement = (BusinessFlow.Stmt) node;
        if (statement.expr != null) pending.add(statement.expr);
        pending.addAll(statement.body);
        pending.addAll(statement.otherwise);
        pending.addAll(statement.finalizer);
        for (List<BusinessFlow.Stmt> handler : statement.handlers) pending.addAll(handler);
      } else {
        BusinessFlow.Expr expression = (BusinessFlow.Expr) node;
        if (("CALL".equals(expression.kind) || "NEW".equals(expression.kind))
            && callBoundaries.contains(expression.symbol)) return true;
        if (expression.receiver != null) pending.add(expression.receiver);
        pending.addAll(expression.args);
        pending.addAll(expression.members.values());
      }
    }
    return false;
  }

  private static final class Limit extends RuntimeException {
    private static final long serialVersionUID = 1L;
  }

  private void tick() {
    cancel.check();
    if (++operations > operationLimit) throw new Limit();
  }

  private static final class Value {
    int id;
    boolean opaque, knownLiteral, reviewed = true, sense = true;
    Object literal;
    Boolean bool;
    Check decision, pending;
    final Set<String> labels = new HashSet<String>();
    final Map<String, Value> members = new HashMap<String, Value>();

    Value copy() {
      Value v = new Value();
      v.id = id;
      v.opaque = opaque;
      v.knownLiteral = knownLiteral;
      v.reviewed = reviewed;
      v.sense = sense;
      v.literal = literal;
      v.bool = bool;
      v.decision = decision;
      v.pending = pending;
      v.labels.addAll(labels);
      v.members.putAll(members);
      return v;
    }
  }

  private static final class Ref {
    int id;
    boolean known;
  }

  private static final class Check {
    int id, sequence, line, orderEpoch;
    String path;
    boolean orderOpaque;
    BusinessPolicy.Contract contract;
    String assurance;
    List<Ref> values;
  }

  private static final class Release {
    int sequence, line, orderEpoch;
    String path;
    boolean qualified, boundaryCertain, orderOpaque;
    List<Ref> values;
    final Set<Integer> accepted = new HashSet<Integer>();
  }

  private static final class State {
    final Map<String, Value> vars = new HashMap<String, Value>();
    final Set<Integer> invalidated = new HashSet<Integer>(), accepted = new HashSet<Integer>();
    final Map<Integer, Boolean> conditions = new HashMap<Integer, Boolean>();
    final List<Check> checks = new ArrayList<Check>();
    Release first;
    String stopped = "";
    boolean orderOpaque, acceptanceOpaque;
    int sequence, orderEpoch;
    Value returnValue;
    BusinessFlow.Stmt returnStatement;

    State copy() {
      State s = new State();
      s.vars.putAll(vars);
      s.invalidated.addAll(invalidated);
      s.accepted.addAll(accepted);
      s.conditions.putAll(conditions);
      s.checks.addAll(checks);
      s.first = first;
      s.stopped = stopped;
      s.orderOpaque = orderOpaque;
      s.acceptanceOpaque = acceptanceOpaque;
      s.sequence = sequence;
      s.orderEpoch = orderEpoch;
      s.returnValue = returnValue;
      s.returnStatement = returnStatement;
      return s;
    }
  }

  private Value fresh() {
    Value v = new Value();
    v.id = ++serial;
    return v;
  }

  private Value unknown() {
    Value v = fresh();
    v.opaque = true;
    return v;
  }

  private Value literal(Object literal) {
    Value v = fresh();
    v.knownLiteral = true;
    v.literal = literal;
    if (literal instanceof Boolean) v.bool = (Boolean) literal;
    return v;
  }

  private List<Ref> refs(List<Value> values, State state) {
    List<Ref> refs = new ArrayList<Ref>();
    for (Value v : values) {
      Ref ref = new Ref();
      ref.id = v.id;
      ref.known = !v.opaque && !state.invalidated.contains(v.id);
      refs.add(ref);
    }
    return refs;
  }

  private List<State> walk(List<BusinessFlow.Stmt> block, List<State> states, int depth) {
    if (depth > 64 || states.size() > 64) throw new Limit();
    for (BusinessFlow.Stmt statement : block) {
      tick();
      List<State> next = new ArrayList<State>();
      for (State state : states) {
        if (!state.stopped.isEmpty()) {
          next.add(state);
          continue;
        }
        String kind = statement.kind;
        if ("ASSIGN".equals(kind)) {
          Value value = eval(statement.expr, state, 0);
          if (statement.target.isEmpty()) uncertain(state, false);
          else state.vars.put(statement.target, value);
          next.add(state);
        } else if ("EXPR".equals(kind)) {
          eval(statement.expr, state, 0);
          next.add(state);
        } else if ("RETURN".equals(kind) || "THROW".equals(kind) || "YIELD".equals(kind)) {
          Value value = statement.expr == null ? literal(null) : eval(statement.expr, state, 0);
          if ("YIELD".equals(kind)) boundary(statement, value, state);
          else {
            if ("THROW".equals(kind)) exceptional(state);
            else {
              state.returnValue = value;
              state.returnStatement = statement;
            }
            state.stopped = kind;
          }
          next.add(state);
        } else if ("IF".equals(kind)) {
          next.addAll(
              walk(statement.body, branch(statement.expr, state.copy(), true, 0), depth + 1));
          next.addAll(
              walk(statement.otherwise, branch(statement.expr, state.copy(), false, 0), depth + 1));
        } else if ("ITERATE".equals(kind)) {
          Value iterable = eval(statement.expr, state, 0);
          State iteration = state.copy();
          Value element = fresh();
          element.labels.addAll(iterable.labels);
          element.reviewed = iterable.reviewed;
          element.opaque =
              iterable.opaque
                  || iterable.labels.isEmpty()
                  || state.invalidated.contains(iterable.id);
          iteration.vars.put(statement.target, element);
          // Evaluating a generator expression creates a value; only this boundary visits an
          // element.
          next.addAll(walk(statement.otherwise, Arrays.asList(state.copy()), depth + 1));
          for (State candidate : walk(statement.body, Arrays.asList(iteration), depth + 1)) {
            // A representative element's successful check never controls later elements or
            // aggregates.
            candidate.accepted.clear();
            candidate.conditions.clear();
            if (!candidate.stopped.isEmpty()) next.add(candidate);
            else next.addAll(walk(statement.otherwise, Arrays.asList(candidate), depth + 1));
          }
        } else if ("TRY".equals(kind)) {
          List<State> previous = exceptionFrame, thrown = new ArrayList<State>();
          exceptionFrame = thrown;
          List<State> tried;
          try {
            tried = walk(statement.body, Arrays.asList(state.copy()), depth + 1);
          } finally {
            exceptionFrame = previous;
          }
          List<State> exits = new ArrayList<State>(), handlingThrown = new ArrayList<State>();
          // Handler and else exceptions must execute this finally before reaching an outer catch.
          exceptionFrame = handlingThrown;
          try {
            for (State candidate : tried) {
              if (candidate.stopped.isEmpty())
                exits.addAll(walk(statement.otherwise, Arrays.asList(candidate), depth + 1));
              else if (!"THROW".equals(candidate.stopped)) exits.add(candidate);
              exits = bound(exits);
            }
            for (State raised : thrown) {
              for (List<BusinessFlow.Stmt> handler : statement.handlers) {
                exits.addAll(walk(handler, Arrays.asList(raised.copy()), depth + 1));
                exits = bound(exits);
              }
              State escaping = raised.copy();
              escaping.stopped = "THROW";
              exits.add(escaping);
            }
          } finally {
            exceptionFrame = previous;
          }
          for (State raised : handlingThrown) {
            raised.stopped = "THROW";
            exits.add(raised);
          }
          exits = bound(exits);
          for (State candidate : exits) {
            String stopped = candidate.stopped;
            candidate.stopped = "";
            for (State finished : walk(statement.finalizer, Arrays.asList(candidate), depth + 1)) {
              if (finished.stopped.isEmpty()) finished.stopped = stopped;
              if ("THROW".equals(finished.stopped)) exceptional(finished);
              next.add(finished);
            }
          }
        } else {
          // Nested unknown control constructs may be callbacks or deferred bodies, not ordered
          // calls.
          boolean previousOrder = state.orderOpaque;
          uncertain(state, statement.orderUncertain);
          if (statement.orderUncertain) state.orderEpoch++;
          for (Value v : state.vars.values()) invalidate(v, state, 0);
          exceptional(state);
          if (statement.expr != null) eval(statement.expr, state, 0);
          List<State> exits =
              new ArrayList<State>(walk(statement.body, Arrays.asList(state.copy()), depth + 1));
          if (!statement.otherwise.isEmpty())
            exits.addAll(walk(statement.otherwise, Arrays.asList(state.copy()), depth + 1));
          for (State exit : exits) {
            exit.orderOpaque = previousOrder;
            if (statement.orderUncertain) exit.orderEpoch++;
            next.add(exit);
          }
        }
        next = bound(next);
      }
      states = next;
    }
    return states;
  }

  private void exceptional(State state) {
    if (exceptionFrame == null) return;
    State raised = state.copy();
    raised.stopped = "";
    exceptionFrame.add(raised);
    if (exceptionFrame.size() > 64) {
      List<State> kept = bound(exceptionFrame);
      exceptionFrame.clear();
      exceptionFrame.addAll(kept);
    }
  }

  /** Retain complete representative paths, never join a release with another path's checks. */
  private List<State> bound(List<State> states) {
    if (states.size() <= 64) return states;
    truncated = true;
    List<State> kept = new ArrayList<State>();
    Set<State> selected = Collections.newSetFromMap(new IdentityHashMap<State, Boolean>());
    Set<String> boundaries = new HashSet<String>();
    for (State state : states) {
      String boundary =
          state.stopped
              + ":"
              + (state.first == null ? "" : state.first.path + ":" + state.first.line);
      if (kept.size() < 64 && boundaries.add(boundary)) {
        kept.add(state);
        selected.add(state);
      }
    }
    // Active paths must still reach later statements instead of being crowded out by early returns.
    for (int pass = 0; pass < 2; pass++)
      for (State state : states)
        if (kept.size() < 64 && (pass == 1 || state.stopped.isEmpty()) && selected.add(state))
          kept.add(state);
    for (State state : states) if (!selected.contains(state)) finish(state);
    return kept;
  }

  private void uncertain(State state, boolean order) {
    state.acceptanceOpaque = true;
    state.orderOpaque |= order;
    state.accepted.clear();
    state.conditions.clear();
  }

  private List<State> branch(BusinessFlow.Expr expr, State state, boolean desired, int depth) {
    tick();
    if (depth > 64) throw new Limit();
    if (expr != null
        && "UNARY".equals(expr.kind)
        && Arrays.asList("!", "not").contains(expr.operator)
        && expr.args.size() == 1) return branch(expr.args.get(0), state, !desired, depth + 1);
    if (expr != null && "BINARY".equals(expr.kind) && expr.args.size() == 2) {
      boolean and = Arrays.asList("&&", "and").contains(expr.operator);
      boolean or = Arrays.asList("||", "or").contains(expr.operator);
      if (and || or) {
        List<State> result = new ArrayList<State>();
        if (and == desired) {
          for (State left : branch(expr.args.get(0), state, desired, depth + 1))
            result.addAll(branch(expr.args.get(1), left, desired, depth + 1));
        } else {
          result.addAll(branch(expr.args.get(0), state.copy(), desired, depth + 1));
          for (State left : branch(expr.args.get(0), state, !desired, depth + 1))
            result.addAll(branch(expr.args.get(1), left, desired, depth + 1));
        }
        return bound(result);
      }
    }
    Value value = eval(expr, state, 0);
    boolean valid = !value.opaque && !state.invalidated.contains(value.id);
    if (valid && value.bool != null && value.bool.booleanValue() != desired)
      return Collections.emptyList();
    boolean base = value.sense ? desired : !desired;
    if (valid && state.conditions.containsKey(value.id) && state.conditions.get(value.id) != base)
      return Collections.emptyList();
    if (valid) state.conditions.put(value.id, base);
    if (valid && value.decision != null && base == value.decision.contract.accept)
      state.accepted.add(value.decision.id);
    return Arrays.asList(state);
  }

  private Value eval(BusinessFlow.Expr expr, State state, int depth) {
    tick();
    if (depth > 64) throw new Limit();
    if (expr == null) return unknown();
    if ("NAME".equals(expr.kind)) {
      Value value = state.vars.get(expr.name);
      if (value == null) {
        value = unknown();
        state.vars.put(expr.name, value);
      }
      return value;
    }
    if ("LITERAL".equals(expr.kind)) return literal(expr.literal);
    if ("MAP".equals(expr.kind)) {
      Value value = fresh();
      for (Map.Entry<String, BusinessFlow.Expr> member : expr.members.entrySet())
        value.members.put(member.getKey(), eval(member.getValue(), state, depth + 1));
      return value;
    }
    if ("BINARY".equals(expr.kind)
        && expr.args.size() == 2
        && Arrays.asList("&&", "and", "||", "or").contains(expr.operator)) {
      Value left = eval(expr.args.get(0), state, depth + 1);
      boolean and = Arrays.asList("&&", "and").contains(expr.operator);
      if (left.bool != null && !left.opaque && !state.invalidated.contains(left.id)) {
        if (left.bool != and) return left;
        return eval(expr.args.get(1), state, depth + 1);
      }
      // An expression result cannot collapse conditional evaluation into a definite call order.
      boolean previousOrder = state.orderOpaque;
      state.orderEpoch++;
      uncertain(state, true);
      eval(expr.args.get(1), state, depth + 1);
      state.orderOpaque = previousOrder;
      state.orderEpoch++;
      return unknown();
    }
    if ("UNKNOWN".equals(expr.kind)) {
      boolean previousOrder = state.orderOpaque;
      state.orderEpoch++;
      uncertain(state, true);
      Value value = unknown();
      if (expr.receiver != null) invalidate(eval(expr.receiver, state, depth + 1), state, 0);
      for (BusinessFlow.Expr arg : expr.args) {
        Value v = eval(arg, state, depth + 1);
        invalidate(v, state, 0);
        value.labels.addAll(v.labels);
      }
      state.orderOpaque = previousOrder;
      state.orderEpoch++;
      return value;
    }
    Value receiver = expr.receiver == null ? null : eval(expr.receiver, state, depth + 1);
    List<Value> args = new ArrayList<Value>();
    for (BusinessFlow.Expr arg : expr.args) args.add(eval(arg, state, depth + 1));
    if ("MEMBER".equals(expr.kind)) {
      if (receiver != null && !receiver.opaque && !state.invalidated.contains(receiver.id)) {
        Value member = receiver.members.get(expr.name);
        if (member != null) return member;
      }
      return unknown();
    }
    if ("UNARY".equals(expr.kind)
        && args.size() == 1
        && Arrays.asList("!", "not").contains(expr.operator)) {
      Value value = args.get(0).copy();
      value.sense = !value.sense;
      if (value.bool != null) {
        value.bool = !value.bool;
        value.literal = value.bool;
      } else if (value.decision == null) {
        value.knownLiteral = false;
        value.literal = null;
        value.opaque = true;
      }
      return value;
    }
    if ("BINARY".equals(expr.kind)
        && args.size() == 2
        && Arrays.asList("==", "!=", "is", "is not").contains(expr.operator)) {
      Value operand = null;
      Boolean comparison = null;
      if (knownBoolean(args.get(1), state)) {
        operand = args.get(0).copy();
        comparison = args.get(1).bool;
      } else if (knownBoolean(args.get(0), state)) {
        operand = args.get(1).copy();
        comparison = args.get(0).bool;
      }
      if (operand != null) {
        if (state.invalidated.contains(operand.id) || operand.opaque) {
          operand.bool = null;
          operand.decision = null;
          operand.opaque = true;
        }
        boolean invert = !comparison ^ Arrays.asList("!=", "is not").contains(expr.operator);
        if (invert) {
          operand.sense = !operand.sense;
          if (operand.bool != null) operand.bool = !operand.bool;
        }
        operand.literal = operand.bool;
        operand.knownLiteral = operand.bool != null;
        if (operand.bool == null && operand.decision == null) operand.opaque = true;
        return operand;
      }
    }
    if ("CALL".equals(expr.kind) || "NEW".equals(expr.kind)) {
      Value projected = projectDecision(expr, receiver, args, state);
      if (projected != null) return projected;
      Binding binding = bind(expr, args);
      if (binding != null) {
        BusinessPolicy.Contract contract = binding.contract;
        args = binding.args;
        exceptional(state);
        boolean candidate = expr.bindingUncertain || "candidate".equals(contract.assurance);
        if ("source".equals(contract.kind)) {
          Value v = fresh();
          v.labels.add(contract.label);
          v.reviewed = !candidate;
          return v;
        }
        if ("transform".equals(contract.kind)) {
          Value input = contract.arg < 0 ? receiver : args.get(contract.arg);
          if (input == null) return unknown();
          Value v = input.copy();
          v.opaque |= state.invalidated.contains(v.id);
          if ("redaction".equals(contract.control)) {
            v.id = ++serial;
            v.knownLiteral = false;
            v.literal = null;
            v.bool = null;
            v.members.clear();
            v.decision = v.pending = null;
          }
          v.reviewed &= !candidate;
          if (candidate) v.opaque = true;
          return v;
        }
        if ("check".equals(contract.kind)) {
          if (!"guard".equals(contract.control)) return unknown();
          if (state.checks.size() >= 64) throw new Limit();
          Check c = new Check();
          c.id = ++serial;
          c.sequence = ++state.sequence;
          c.path = expr.path;
          c.line = expr.line;
          c.orderOpaque = state.orderOpaque;
          c.orderEpoch = state.orderEpoch;
          c.contract = contract;
          c.assurance = candidate ? "candidate" : "reviewed";
          c.values = refs(select(args, contract.args), state);
          state.checks.add(c);
          Value v = fresh();
          if ("normal-return".equals(contract.mode)) state.accepted.add(c.id);
          else if (contract.decisionSymbol.isEmpty()) v.decision = c;
          else v.pending = c;
          return v;
        }
        release(contract, expr.path, expr.line, args, state, !candidate);
        return unknown();
      }
      // No guessed helper semantics: unresolved calls can mutate referenced arguments or receivers.
      uncertain(state, false);
      exceptional(state);
      if (receiver != null) args.add(receiver);
      Value result = unknown();
      for (Value arg : args) {
        invalidate(arg, state, 0);
        result.labels.addAll(arg.labels);
      }
      return result;
    }
    Value value = unknown();
    for (Value arg : args) value.labels.addAll(arg.labels);
    return value;
  }

  private void invalidate(Value value, State state, int depth) {
    if (depth > 64) throw new Limit();
    state.invalidated.add(value.id);
    for (Value member : value.members.values()) invalidate(member, state, depth + 1);
  }

  private boolean knownBoolean(Value value, State state) {
    return value.bool != null && !value.opaque && !state.invalidated.contains(value.id);
  }

  private Value projectDecision(
      BusinessFlow.Expr expr, Value receiver, List<Value> args, State state) {
    Value owner =
        receiver != null && receiver.pending != null
            ? receiver
            : args.size() == 1 && args.get(0).pending != null ? args.get(0) : null;
    if (owner == null) return null;
    BusinessPolicy.Contract c = owner.pending.contract;
    if (!c.decisionSymbol.equals(expr.symbol)
        || (c.decisionArg < 0
            ? owner != receiver || !args.isEmpty()
            : args.size() != 1 || owner != args.get(0))) return null;
    exceptional(state);
    Value v = fresh();
    if (!owner.opaque && !state.invalidated.contains(owner.id) && !expr.bindingUncertain)
      v.decision = owner.pending;
    else v.opaque = true;
    return v;
  }

  private static final class Binding {
    BusinessPolicy.Contract contract;
    List<Value> args;
  }

  private Binding bind(BusinessFlow.Expr expr, List<Value> supplied) {
    Binding match = null;
    for (BusinessPolicy.Contract c : policy.contractsForSymbol(expr.symbol)) {
      if (!"call".equals(c.boundary)) continue;
      List<Value> args = new ArrayList<Value>(Collections.<Value>nCopies(c.arity, null));
      boolean valid = supplied.size() <= c.arity, keyword = false;
      for (int i = 0; valid && i < supplied.size(); i++) {
        String name = expr.argNames.size() > i ? expr.argNames.get(i) : "";
        int slot = name.isEmpty() ? i : c.parameterNames.indexOf(name);
        if (name.isEmpty() && keyword) valid = false;
        if (!name.isEmpty()) keyword = true;
        if (slot < 0 || slot >= args.size() || args.get(slot) != null) valid = false;
        if (valid) args.set(slot, supplied.get(i));
      }
      for (int i = 0; valid && i < args.size(); i++) {
        if (args.get(i) != null) continue;
        String name = c.parameterNames.size() > i ? c.parameterNames.get(i) : "";
        if (!c.defaults.containsKey(name)) valid = false;
        else args.set(i, literal(c.defaults.get(name)));
      }
      if (!valid) continue;
      if (match != null) return null;
      match = new Binding();
      match.contract = c;
      match.args = args;
    }
    return match;
  }

  private List<Value> select(List<Value> values, List<Integer> indexes) {
    List<Value> result = new ArrayList<Value>();
    for (int index : indexes) result.add(index < values.size() ? values.get(index) : unknown());
    return result;
  }

  private void boundary(BusinessFlow.Stmt statement, Value value, State state) {
    BusinessPolicy.Contract c = policy.contract(function.symbol, function.params.size());
    String boundary = "YIELD".equals(statement.kind) ? "yield" : "return";
    if (c == null || !"sink".equals(c.kind) || !boundary.equals(c.boundary)) return;
    List<Value> args = new ArrayList<Value>();
    args.add(value);
    for (String param : function.params) {
      Value v = state.vars.get(param);
      args.add(v == null ? unknown() : v);
    }
    release(c, statement.path, statement.line, args, state, "reviewed".equals(c.assurance));
  }

  private void release(
      BusinessPolicy.Contract c,
      String path,
      int line,
      List<Value> args,
      State state,
      boolean qualified) {
    if (!"sink".equals(c.kind) || !"release".equals(c.channel) || state.first != null) return;
    if (c.whenArg >= 0) {
      Value discriminator = args.get(c.whenArg);
      if (discriminator.knownLiteral
          && !discriminator.opaque
          && !state.invalidated.contains(discriminator.id)) {
        if (!sameLiteral(
            discriminator.bool == null ? discriminator.literal : discriminator.bool, c.whenEquals))
          return;
      } else qualified = false;
    }
    List<Value> values = select(args, c.args), data = new ArrayList<Value>();
    for (Value value : values) {
      for (String member : c.valuePath) {
        Value projected =
            value.opaque || state.invalidated.contains(value.id) ? null : value.members.get(member);
        if (projected == null) {
          value = unknown();
          qualified = false;
          break;
        }
        value = projected;
      }
      data.add(value);
    }
    if (!c.requiresLabel.isEmpty()) {
      boolean relevant = false, unresolved = false;
      for (Value value : data) {
        relevant |= value.labels.contains(c.requiresLabel);
        unresolved |=
            value.opaque
                || state.invalidated.contains(value.id)
                || (!value.knownLiteral && value.labels.isEmpty());
      }
      if (!relevant && !unresolved) return;
      if (!relevant) qualified = false;
    }
    boolean boundaryCertain = qualified;
    for (Value value : data)
      qualified &= value.reviewed && !value.opaque && !state.invalidated.contains(value.id);
    Release r = new Release();
    r.path = path;
    r.line = line;
    r.sequence = ++state.sequence;
    r.qualified = qualified && !state.acceptanceOpaque;
    r.orderOpaque = state.orderOpaque;
    r.orderEpoch = state.orderEpoch;
    r.boundaryCertain = boundaryCertain;
    r.values = refs(data, state);
    r.accepted.addAll(state.accepted);
    state.first = r;
  }

  private boolean sameLiteral(Object left, Object right) {
    if (left instanceof Number && right instanceof Number) {
      try {
        return new BigDecimal(left.toString()).compareTo(new BigDecimal(right.toString())) == 0;
      } catch (NumberFormatException invalid) {
        return false;
      }
    }
    return Objects.equals(left, right);
  }

  private String binding(List<Ref> released, List<Ref> checked) {
    if (released.isEmpty() || checked.isEmpty()) return "unknown";
    for (Ref r : released) if (!r.known) return "unknown";
    for (Ref r : checked) if (!r.known) return "unknown";
    if (released.size() != checked.size()) return "different";
    for (int i = 0; i < released.size(); i++)
      if (released.get(i).id != checked.get(i).id) return "different";
    return "same";
  }

  private void finish(State state) {
    Release r = state.first;
    if (r == null) return;
    if (state.checks.isEmpty()) {
      add(r, null, "ORDER_UNRESOLVED", "unknown");
      return;
    }
    for (Check c : state.checks) {
      String binding = binding(r.values, c.values), ordering = "ORDER_UNRESOLVED";
      if (r.boundaryCertain && !r.orderOpaque && !c.orderOpaque && r.orderEpoch == c.orderEpoch) {
        if (r.sequence < c.sequence) ordering = "RELEASE_PRECEDES_MAPPED_CHECK";
        else if (r.qualified
            && "same".equals(binding)
            && r.accepted.contains(c.id)
            && "reviewed".equals(c.assurance)
            && "closed".equals(c.contract.failureMode))
          ordering = "ACCEPTED_CHECK_PRECEDES_RELEASE";
      }
      add(r, c, ordering, binding);
    }
  }

  private void add(Release r, Check c, String ordering, String binding) {
    Map<String, Object> fact =
        Findings.map(
            "path",
            r.path,
            "line",
            Math.max(1, r.line),
            "checkPath",
            c == null ? "" : c.path,
            "checkLine",
            c == null ? 0 : Math.max(1, c.line),
            "ordering",
            ordering,
            "valueBinding",
            binding,
            "assurance",
            c == null ? "unknown" : c.assurance,
            "failureMode",
            c == null ? "unknown" : c.contract.failureMode,
            "limits",
            LIMITS);
    if (seen.contains(fact)) return;
    if (sites.size() >= 128) {
      truncated = true;
      return;
    }
    seen.add(fact);
    sites.add(fact);
  }
}
