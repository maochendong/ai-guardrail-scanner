package dev.aiguard.compat;

import java.util.*;

/** Source relations for append-built outputs; never an induction proof over every element. */
public final class BusinessCollectionAnalysis {
  public final Map<String, List<Map<String, Object>>> sitesByRule =
      new LinkedHashMap<String, List<Map<String, Object>>>();
  public boolean truncated;
  private static final List<String> LIMITATIONS =
      Collections.unmodifiableList(
          Arrays.asList(
              "ONE_REPRESENTATIVE_ITERATION_SOURCE_RELATION",
              "NO_ALL_ITERATIONS_PROOF",
              "APPEND_AND_OUTPUT_ALIAS_ONLY",
              "NO_ELEMENT_SCHEMA_OR_BUSINESS_APPLICABILITY_PROOF",
              "COPY_CONSTRUCTOR_NOT_FIELD_VALUE_EQUIVALENCE",
              "CANDIDATE_CHECK_IS_NOT_SECURITY_ASSURANCE",
              "NOT_RUNTIME_COLLECTION_COMPLETENESS"));
  private BusinessPolicy policy;
  private Cancel cancel;
  private BusinessFlow.Function function;
  private int serial, operations, totalOperations, count;

  public static BusinessCollectionAnalysis analyze(
      BusinessFlow.Program program, BusinessPolicy policy, Cancel cancel) {
    BusinessCollectionAnalysis result = new BusinessCollectionAnalysis();
    result.policy = policy;
    result.cancel = cancel;
    for (BusinessFlow.Function function : program.functions) {
      cancel.check();
      if (!result.containsCollection(function.body)) continue;
      result.function = function;
      result.operations = 0;
      State start = new State();
      start.opaqueControl =
          function.executionUncertain || program.incompletePaths.contains(function.path);
      for (String parameter : function.params) start.vars.put(parameter, result.value("PARAM"));
      try {
        for (State exit : result.walk(function.body, Arrays.asList(start), 0)) {
          if ("RETURN".equals(exit.stopped) && exit.returned != null) {
            BusinessPolicy.Contract contract =
                policy.contract(function.symbol, function.params.size());
            if (contract != null
                && "sink".equals(contract.kind)
                && "return".equals(contract.boundary)) {
              List<Value> args = new ArrayList<Value>();
              args.add(exit.returned);
              for (String parameter : function.params) args.add(exit.vars.get(parameter));
              result.output(contract, args, exit.returnSite, exit);
            }
          }
        }
      } catch (Limit limit) {
        result.truncated = true;
      }
    }
    return result;
  }

  private boolean containsCollection(List<BusinessFlow.Stmt> body) {
    Deque<Object> pending = new ArrayDeque<Object>(body);
    Set<Object> visited = Collections.newSetFromMap(new IdentityHashMap<Object, Boolean>());
    while (!pending.isEmpty()) {
      cancel.check();
      Object node = pending.removeLast();
      if (!visited.add(node)) continue;
      if (visited.size() > 20000) {
        truncated = true;
        return false;
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
        if ("COLLECTION_NEW".equals(expression.kind)) return true;
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
    if (++operations > 20000 || ++totalOperations > 500000) throw new Limit();
  }

  private static final class Value {
    int id, element;
    String kind;
    boolean derived, copied, uncertain;
    Boolean bool;
    Check check;
    int predicate = -1;
    final List<String> field = new ArrayList<String>();
    final Map<String, Value> members = new LinkedHashMap<String, Value>();
  }

  private static final class Check {
    int id;
    BusinessPolicy.Contract contract;
    BusinessFlow.Expr site;
    List<Value> checked;
    boolean candidate;
  }

  private static final class Append {
    int collection;
    Value element;
    final Map<Integer, Value> keys = new HashMap<Integer, Value>();
    final Set<Integer> accepted = new HashSet<Integer>();
    BusinessFlow.Expr site;
    boolean uncertain;
  }

  private static final class State {
    final Map<String, Value> vars = new LinkedHashMap<String, Value>();
    final Map<Integer, Map<String, Value>> members = new HashMap<Integer, Map<String, Value>>();
    final Map<Integer, List<Append>> appended = new HashMap<Integer, List<Append>>();
    final List<Check> checks = new ArrayList<Check>();
    final Map<Integer, Set<Integer>> predicates = new HashMap<Integer, Set<Integer>>();
    final Set<Integer> invalidated = new HashSet<Integer>();
    final Map<String, Boolean> conditions = new HashMap<String, Boolean>();
    boolean opaqueControl;
    String stopped = "";
    Value returned;
    BusinessFlow.Expr returnSite;

    State copy() {
      State copy = new State();
      copy.vars.putAll(vars);
      for (Map.Entry<Integer, Map<String, Value>> item : members.entrySet())
        copy.members.put(item.getKey(), new LinkedHashMap<String, Value>(item.getValue()));
      for (Map.Entry<Integer, List<Append>> item : appended.entrySet())
        copy.appended.put(item.getKey(), new ArrayList<Append>(item.getValue()));
      copy.checks.addAll(checks);
      for (Map.Entry<Integer, Set<Integer>> item : predicates.entrySet())
        copy.predicates.put(item.getKey(), new HashSet<Integer>(item.getValue()));
      copy.invalidated.addAll(invalidated);
      copy.conditions.putAll(conditions);
      copy.opaqueControl = opaqueControl;
      copy.stopped = stopped;
      copy.returned = returned;
      copy.returnSite = returnSite;
      return copy;
    }
  }

  private Value value(String kind) {
    Value value = new Value();
    value.id = ++serial;
    value.kind = kind;
    return value;
  }

  private List<State> bounded(List<State> states) {
    if (states.size() > 64) throw new Limit();
    return states;
  }

  private List<State> walk(List<BusinessFlow.Stmt> body, List<State> states, int depth) {
    if (depth > 64) throw new Limit();
    for (BusinessFlow.Stmt statement : body) {
      List<State> next = new ArrayList<State>();
      for (State state : states) {
        tick();
        if (!state.stopped.isEmpty()) {
          next.add(state);
          continue;
        }
        if ("ASSIGN".equals(statement.kind)) {
          state.vars.put(statement.target, eval(statement.expr, state, 0));
          next.add(state);
        } else if ("EXPR".equals(statement.kind)) {
          eval(statement.expr, state, 0);
          next.add(state);
        } else if ("IF".equals(statement.kind)) {
          next.addAll(
              walk(statement.body, branch(statement.expr, state.copy(), true, 0), depth + 1));
          next.addAll(
              walk(statement.otherwise, branch(statement.expr, state.copy(), false, 0), depth + 1));
        } else if ("ITERATE".equals(statement.kind)) {
          eval(statement.expr, state, 0);
          next.addAll(walk(statement.otherwise, Arrays.asList(state.copy()), depth + 1));
          State once = state.copy();
          once.predicates.clear();
          Value element = value("ITEM");
          element.element = element.id;
          once.vars.put(statement.target, element);
          for (State exit : walk(statement.body, Arrays.asList(once), depth + 1)) {
            exit.predicates.clear();
            if ("CONTINUE".equals(exit.stopped) || "BREAK".equals(exit.stopped)) exit.stopped = "";
            next.addAll(walk(statement.otherwise, Arrays.asList(exit), depth + 1));
          }
        } else if ("RETURN".equals(statement.kind)) {
          state.returned = eval(statement.expr, state, 0);
          state.returnSite = site(statement);
          state.stopped = "RETURN";
          next.add(state);
        } else if ("CONTINUE".equals(statement.kind)
            || "BREAK".equals(statement.kind)
            || "THROW".equals(statement.kind)) {
          state.stopped = statement.kind;
          next.add(state);
        } else {
          // Unknown control/handlers cannot establish an accepted append condition.
          state.opaqueControl = true;
          state.predicates.clear();
          if (statement.expr != null) eval(statement.expr, state, 0);
          List<State> candidates = new ArrayList<State>();
          candidates.addAll(walk(statement.body, Arrays.asList(state.copy()), depth + 1));
          candidates.addAll(walk(statement.otherwise, Arrays.asList(state.copy()), depth + 1));
          for (List<BusinessFlow.Stmt> handler : statement.handlers)
            candidates.addAll(walk(handler, Arrays.asList(state.copy()), depth + 1));
          for (State candidate : bounded(candidates))
            next.addAll(walk(statement.finalizer, Arrays.asList(candidate), depth + 1));
        }
      }
      states = bounded(next);
    }
    return states;
  }

  private BusinessFlow.Expr site(BusinessFlow.Stmt statement) {
    BusinessFlow.Expr site = new BusinessFlow.Expr("BOUNDARY");
    site.path = statement.path;
    site.line = statement.line;
    return site;
  }

  private List<State> branch(
      BusinessFlow.Expr expression, State state, boolean desired, int depth) {
    tick();
    if (depth > 64) throw new Limit();
    if (expression != null
        && "UNARY".equals(expression.kind)
        && Arrays.asList("!", "not").contains(expression.operator)
        && expression.args.size() == 1)
      return branch(expression.args.get(0), state, !desired, depth + 1);
    if (expression != null && "BINARY".equals(expression.kind) && expression.args.size() == 2) {
      if (Arrays.asList("==", "!=", "is", "is not").contains(expression.operator)) {
        BusinessFlow.Expr left = expression.args.get(0), right = expression.args.get(1);
        BusinessFlow.Expr literal = "LITERAL".equals(left.kind) ? left : right;
        BusinessFlow.Expr tested = literal == left ? right : left;
        if ("LITERAL".equals(literal.kind) && literal.literal instanceof Boolean) {
          boolean equal = "==".equals(expression.operator) || "is".equals(expression.operator);
          boolean expected = ((Boolean) literal.literal).booleanValue();
          return branch(tested, state, desired == equal ? expected : !expected, depth + 1);
        }
      }
      boolean and = Arrays.asList("&&", "and").contains(expression.operator);
      boolean or = Arrays.asList("||", "or").contains(expression.operator);
      if (and || or) {
        List<State> result = new ArrayList<State>();
        if (and == desired) {
          for (State left : branch(expression.args.get(0), state, desired, depth + 1))
            result.addAll(branch(expression.args.get(1), left, desired, depth + 1));
        } else {
          result.addAll(branch(expression.args.get(0), state.copy(), desired, depth + 1));
          for (State left : branch(expression.args.get(0), state, !desired, depth + 1))
            result.addAll(branch(expression.args.get(1), left, desired, depth + 1));
        }
        return bounded(result);
      }
    }
    Value value = eval(expression, state, 0);
    if (value.bool != null && value.bool.booleanValue() != desired) return Collections.emptyList();
    if (value.check != null && value.predicate >= 0 && !value.uncertain) {
      Check check = value.check;
      boolean expected =
          check.contract.decisionPredicates.isEmpty()
              ? check.contract.accept
              : check.contract.decisionPredicates.get(value.predicate).accept;
      String leaf = check.id + ":" + value.predicate;
      Boolean previous = state.conditions.get(leaf);
      if (previous != null && previous.booleanValue() != desired) return Collections.emptyList();
      state.conditions.put(leaf, desired);
      if (desired == expected) {
        Set<Integer> predicates = state.predicates.get(check.id);
        if (predicates == null) {
          predicates = new HashSet<Integer>();
          state.predicates.put(check.id, predicates);
        }
        predicates.add(value.predicate);
      }
    }
    return Arrays.asList(state);
  }

  private Map<String, Value> members(Value owner, State state) {
    Map<String, Value> overlay = state.members.get(owner.id);
    return overlay == null ? owner.members : overlay;
  }

  private Value member(Value receiver, String name, State state) {
    if (receiver == null) return value("UNKNOWN");
    boolean invalid = state.invalidated.contains(receiver.id);
    Value known = members(receiver, state).get(name);
    if (known != null && !invalid) return known;
    if (receiver.element > 0) {
      Value projected = value("FIELD");
      projected.element = receiver.element;
      projected.field.addAll(receiver.field);
      projected.field.add(name);
      projected.derived = receiver.derived;
      projected.uncertain =
          receiver.uncertain || invalid || state.invalidated.contains(receiver.element);
      return projected;
    }
    return value("UNKNOWN");
  }

  private Value eval(BusinessFlow.Expr expression, State state, int depth) {
    tick();
    if (depth > 64 || expression == null) return value("UNKNOWN");
    String kind = expression.generatedMethodUncertain ? "UNKNOWN" : expression.kind;
    if ("NAME".equals(kind)) {
      Value existing = state.vars.get(expression.name);
      if (existing == null) {
        existing = value("UNKNOWN");
        state.vars.put(expression.name, existing);
      }
      return existing;
    }
    if ("LITERAL".equals(kind)) {
      Value literal = value("LITERAL");
      if (expression.literal instanceof Boolean) literal.bool = (Boolean) expression.literal;
      return literal;
    }
    if ("MAP".equals(kind)) {
      Value object = value("OBJECT");
      for (Map.Entry<String, BusinessFlow.Expr> entry : expression.members.entrySet())
        object.members.put(entry.getKey(), eval(entry.getValue(), state, depth + 1));
      return object;
    }
    if ("COLLECTION_NEW".equals(kind) && expression.args.isEmpty()) {
      Value collection = value("COLLECTION");
      state.appended.put(collection.id, new ArrayList<Append>());
      return collection;
    }
    Value receiver =
        expression.receiver == null ? null : eval(expression.receiver, state, depth + 1);
    List<Value> args = new ArrayList<Value>();
    for (BusinessFlow.Expr argument : expression.args) args.add(eval(argument, state, depth + 1));
    if (expression.generatedMethodUncertain)
      for (BusinessFlow.Expr field : expression.members.values())
        args.add(eval(field, state, depth + 1));
    Value predicate = project(expression, receiver, args, state);
    if (predicate != null) return predicate;
    if ("MEMBER".equals(kind) && !expression.name.isEmpty() && args.isEmpty()) {
      Value projected = member(receiver, expression.name, state);
      return projected;
    }
    if ("MAP_COPY".equals(kind) && args.size() == 1) {
      Value source = args.get(0), copy = value("OBJECT");
      copy.element = source.element;
      copy.field.addAll(source.field);
      copy.copied = true;
      // An arbitrary Map can implement get() and entrySet() differently. The constructor
      // supplies a source dependency, not equality of the field previously checked via get().
      boolean knownMap =
          "OBJECT".equals(source.kind)
              && !source.uncertain
              && !state.invalidated.contains(source.id);
      copy.derived = source.derived || !knownMap;
      copy.uncertain = source.uncertain || !knownMap;
      if (knownMap) copy.members.putAll(members(source, state));
      else invalidate(source, state, new HashSet<Integer>(), 0);
      return copy;
    }
    if ("PUT_MEMBER".equals(kind)
        && receiver != null
        && args.size() == 1
        && !expression.name.isEmpty()
        && ("OBJECT".equals(receiver.kind) || "ITEM".equals(receiver.kind))
        && !state.invalidated.contains(receiver.id)
        && !expression.generatedMethodUncertain) {
      Map<String, Value> fields = new LinkedHashMap<String, Value>(members(receiver, state));
      Value old = fields.put(expression.name, args.get(0));
      state.members.put(receiver.id, fields);
      // A copied map is a new object, but changing a checked original item invalidates its check.
      if (receiver.element > 0 && !receiver.copied) {
        state.invalidated.add(receiver.id);
        state.invalidated.add(receiver.element);
      }
      return old == null ? value("UNKNOWN") : old;
    }
    if ("COLLECTION_APPEND".equals(kind)
        && receiver != null
        && args.size() == 1
        && "COLLECTION".equals(receiver.kind)) {
      Append append = new Append();
      append.collection = receiver.id;
      append.element = args.get(0);
      append.site = expression;
      append.uncertain =
          state.opaqueControl
              || state.invalidated.contains(receiver.id)
              || state.invalidated.contains(append.element.id)
              || append.element.uncertain;
      for (Check check : state.checks) {
        for (Value checked : check.checked) {
          if (checked.element > 0 && checked.element == append.element.element) {
            append.keys.put(check.id, checked);
            Set<Integer> accepted = state.predicates.get(check.id);
            int required = Math.max(1, check.contract.decisionPredicates.size());
            if (!append.uncertain
                && accepted != null
                && accepted.size() == required
                && !check.candidate
                && "closed".equals(check.contract.failureMode)
                && !state.invalidated.contains(checked.id)
                && !state.invalidated.contains(checked.element)
                && !checked.uncertain
                && !checked.derived
                && keyPreserved(append.element, checked, state)) append.accepted.add(check.id);
            break;
          }
        }
      }
      List<Append> records = state.appended.get(receiver.id);
      if (records == null || records.size() >= 128) throw new Limit();
      records.add(append);
      Value added = value("LITERAL");
      added.bool = Boolean.TRUE;
      return added;
    }
    if ("COLLECTION_SIZE".equals(kind)) return value("UNKNOWN");
    Binding binding = bind(expression, args);
    if (binding != null) {
      BusinessPolicy.Contract contract = binding.contract;
      args = binding.args;
      if ("check".equals(contract.kind)) {
        Check check = new Check();
        check.id = ++serial;
        check.contract = contract;
        check.site = expression;
        check.candidate =
            expression.bindingUncertain
                || expression.generatedMethodUncertain
                || "candidate".equals(contract.assurance);
        check.checked = select(args, contract.args);
        state.checks.add(check);
        Value decision = value("DECISION");
        decision.check = check;
        if (contract.decisionPredicates.isEmpty()) decision.predicate = 0;
        if ("normal-return".equals(contract.mode))
          state.predicates.put(check.id, new HashSet<Integer>(Arrays.asList(0)));
        return decision;
      }
      if ("sink".equals(contract.kind)) {
        output(contract, args, expression, state);
        return value("UNKNOWN");
      }
      if ("transform".equals(contract.kind)
          && "preserve".equals(contract.control)
          && "reviewed".equals(contract.assurance)
          && !expression.bindingUncertain
          && !expression.generatedMethodUncertain) {
        Value source = contract.arg < 0 ? receiver : args.get(contract.arg);
        return source == null ? value("UNKNOWN") : source;
      }
    }
    Value derived = value("UNKNOWN");
    List<Value> touched = new ArrayList<Value>(args);
    if (receiver != null) touched.add(receiver);
    Value origin = null;
    boolean ambiguous = false;
    for (Value input : touched) {
      if (input.element > 0) {
        if (origin == null) origin = input;
        else if (origin.element != input.element || !origin.field.equals(input.field))
          ambiguous = true;
      }
      invalidate(input, state, new HashSet<Integer>(), 0);
    }
    if (origin != null && !ambiguous) {
      derived.element = origin.element;
      derived.field.addAll(origin.field);
      derived.derived = derived.uncertain = true;
    }
    return derived;
  }

  private boolean keyPreserved(Value item, Value key, State state) {
    if (item.element != key.element || !item.field.isEmpty()) return false;
    if (key.field.isEmpty() && !members(item, state).isEmpty()) return false;
    Value current = item;
    for (int i = 0; i < key.field.size(); i++) {
      Value replacement = members(current, state).get(key.field.get(i));
      if (replacement == null) return true; // Unchanged source field, still only a source relation.
      current = replacement;
      if (current.element != key.element
          || current.uncertain
          || current.derived
          || !current.field.equals(key.field.subList(0, i + 1))) return false;
    }
    return true;
  }

  private void invalidate(Value value, State state, Set<Integer> visited, int depth) {
    if (depth > 64) throw new Limit();
    if (!visited.add(value.id)) return;
    state.invalidated.add(value.id);
    if (value.element > 0) state.invalidated.add(value.element);
    for (Value member : members(value, state).values())
      invalidate(member, state, visited, depth + 1);
    if (value.check != null) {
      state.predicates.remove(value.check.id);
      for (Iterator<String> keys = state.conditions.keySet().iterator(); keys.hasNext(); )
        if (keys.next().startsWith(value.check.id + ":")) keys.remove();
    }
  }

  private Value project(
      BusinessFlow.Expr expression, Value receiver, List<Value> args, State state) {
    if (expression.generatedMethodUncertain) return null;
    Value owner =
        receiver != null && receiver.check != null
            ? receiver
            : args.size() == 1 && args.get(0).check != null ? args.get(0) : null;
    if (owner == null) return null;
    List<BusinessPolicy.DecisionPredicate> predicates = owner.check.contract.decisionPredicates;
    for (int i = 0; i < predicates.size(); i++) {
      BusinessPolicy.DecisionPredicate predicate = predicates.get(i);
      if (predicate.symbol.equals(expression.symbol)
          && (predicate.arg < 0
              ? owner == receiver && args.isEmpty()
              : args.size() == 1 && owner == args.get(0))) {
        Value projected = value("PREDICATE");
        projected.check = owner.check;
        projected.predicate = i;
        projected.uncertain =
            expression.bindingUncertain
                || expression.generatedMethodUncertain
                || state.invalidated.contains(owner.id);
        return projected;
      }
    }
    return null;
  }

  private static final class Binding {
    BusinessPolicy.Contract contract;
    List<Value> args;
  }

  private Binding bind(BusinessFlow.Expr expression, List<Value> supplied) {
    Binding result = null;
    for (BusinessPolicy.Contract contract : policy.contractsForSymbol(expression.symbol)) {
      if (!"call".equals(contract.boundary)) continue;
      List<Value> args = new ArrayList<Value>(Collections.<Value>nCopies(contract.arity, null));
      boolean valid = supplied.size() <= args.size();
      for (int i = 0; valid && i < supplied.size(); i++) {
        String name = expression.argNames.size() > i ? expression.argNames.get(i) : "";
        int slot = name.isEmpty() ? i : contract.parameterNames.indexOf(name);
        if (slot < 0 || slot >= args.size() || args.get(slot) != null) valid = false;
        else args.set(slot, supplied.get(i));
      }
      for (int i = 0; valid && i < args.size(); i++)
        if (args.get(i) == null) {
          String name = contract.parameterNames.size() > i ? contract.parameterNames.get(i) : "";
          if (!contract.defaults.containsKey(name)) valid = false;
          else args.set(i, value("LITERAL"));
        }
      if (!valid) continue;
      if (result != null) return null;
      result = new Binding();
      result.contract = contract;
      result.args = args;
    }
    return result;
  }

  private List<Value> select(List<Value> values, List<Integer> indexes) {
    List<Value> selected = new ArrayList<Value>();
    for (Integer index : indexes)
      selected.add(index < values.size() ? values.get(index) : value("UNKNOWN"));
    return selected;
  }

  private void output(
      BusinessPolicy.Contract contract, List<Value> args, BusinessFlow.Expr site, State state) {
    if (contract.whenArg >= 0)
      return; // A conditional output needs a separately modeled discriminator.
    for (Value selected : select(args, contract.args)) {
      Value collection = selected;
      for (String field : contract.valuePath) collection = member(collection, field, state);
      if (!"COLLECTION".equals(collection.kind)) continue;
      List<Append> appends = state.appended.get(collection.id);
      if (appends == null) continue;
      for (Append append : appends) {
        for (Check check : state.checks) {
          if (!relevant(check.contract.control, contract.channel)) continue;
          String rule = rule(check.contract.control);
          if (rule.isEmpty()) continue;
          Value key = append.keys.get(check.id);
          boolean sameElement = key != null && keyPreserved(append.element, key, state);
          boolean accepted =
              append.accepted.contains(check.id)
                  && sameElement
                  && !state.invalidated.contains(collection.id)
                  && !state.invalidated.contains(append.element.id)
                  && !state.invalidated.contains(append.element.element);
          List<Map<String, Object>> reasons = new ArrayList<Map<String, Object>>();
          reasons.add(
              reason(
                  "UNSUPPORTED",
                  "COLLECTION_ALL_ITEMS_UNPROVEN",
                  "A representative append-to-output source relation is located; all iterations and"
                      + " all inserted elements remain unproven."));
          if (append.uncertain || !accepted)
            reasons.add(
                reason(
                    "UNSUPPORTED",
                    "COLLECTION_CONTROL_BINDING_UNRESOLVED",
                    "A check after append, a different element, mutation or an incomplete decision"
                        + " prevents proving that this append is controlled."));
          if (key != null && (key.derived || key.uncertain))
            reasons.add(
                reason(
                    "UNSUPPORTED",
                    "COLLECTION_KEY_TRANSFORMATION_UNRESOLVED",
                    "The checked element field crosses a transformation without qualified"
                        + " identity-preserving semantics."));
          if (check.candidate)
            reasons.add(
                reason(
                    "INSUFFICIENT_EVIDENCE",
                    "CONTROL_ASSURANCE_UNVERIFIED",
                    "The mapped check or receiver remains a candidate control requiring"
                        + " qualification."));
          if (!"closed".equals(check.contract.failureMode))
            reasons.add(
                reason(
                    "INSUFFICIENT_EVIDENCE",
                    "GUARD_FAILURE_MODE_UNVERIFIED",
                    "The check does not carry qualified fail-closed semantics for the collection"
                        + " output."));
          String subject = "not-required";
          if (contract.identity >= 0 && contract.identity < args.size()) {
            subject = "unresolved";
            Value identity = args.get(contract.identity);
            for (Value checked : check.checked)
              if (checked.id == identity.id && !state.invalidated.contains(identity.id))
                subject = "same-subject";
            reasons.add(
                reason(
                    "INSUFFICIENT_EVIDENCE",
                    "IDENTITY_TRUST_UNVERIFIED",
                    "A matching source argument does not establish the deployed subject trust"
                        + " boundary."));
          }
          Map<String, Object> fact =
              Findings.map(
                  "ruleId",
                  rule,
                  "path",
                  site.path,
                  "line",
                  Math.max(1, site.line),
                  "appendPath",
                  append.site.path,
                  "appendLine",
                  Math.max(1, append.site.line),
                  "checkPath",
                  check.site.path,
                  "checkLine",
                  Math.max(1, check.site.line),
                  "control",
                  check.contract.control,
                  "assurance",
                  check.candidate ? "candidate" : "reviewed",
                  "failureMode",
                  check.contract.failureMode,
                  "checkedElementPath",
                  key == null ? Collections.<String>emptyList() : new ArrayList<String>(key.field),
                  "elementBinding",
                  !sameElement
                      ? "unresolved"
                      : key.derived
                              || key.uncertain
                              || append.element.derived
                              || append.element.uncertain
                          ? "derived-element"
                          : append.element.copied ? "copied-element" : "same-element",
                  "subjectBinding",
                  subject,
                  "decisionBinding",
                  accepted ? "all-required-predicates" : "not-established",
                  "outputBinding",
                  "same-collection",
                  "coverage",
                  "UNKNOWN",
                  "disposition",
                  "UNKNOWN",
                  "unknownCategory",
                  "UNSUPPORTED",
                  "evidence",
                  Arrays.asList(
                      evidence(site, "collection-output"),
                      evidence(append.site, "collection-append"),
                      evidence(check.site, "collection-check")),
                  "unknownReasons",
                  reasons,
                  "limitations",
                  LIMITATIONS);
          List<Map<String, Object>> facts = sitesByRule.get(rule);
          if (facts == null) {
            facts = new ArrayList<Map<String, Object>>();
            sitesByRule.put(rule, facts);
          }
          Unknowns.set(
              fact,
              "UNSUPPORTED",
              "COLLECTION_ALL_ITEMS_UNPROVEN",
              "A representative append-to-output source relation is located; all iterations and all"
                  + " inserted elements remain unproven.");
          if (facts.contains(fact)) continue;
          if (count++ >= 128) {
            truncated = true;
            continue;
          }
          facts.add(fact);
        }
      }
    }
  }

  private Map<String, Object> evidence(BusinessFlow.Expr site, String role) {
    return Findings.map(
        "path",
        site.path,
        "line",
        Math.max(1, site.line),
        "role",
        role,
        "nodeId",
        site.path + ":" + Math.max(1, site.line) + ":" + role,
        "detail",
        "Source location for the bounded collection relationship; full coverage remains unknown.");
  }

  private boolean relevant(String control, String channel) {
    return "recommend".equals(channel) && Arrays.asList("facts", "suitability").contains(control)
        || "release".equals(channel) && "guard".equals(control)
        || "retrieve".equals(channel) && Arrays.asList("scope", "doc-acl").contains(control)
        || "access".equals(channel) && "scope".equals(control)
        || "tool".equals(channel) && "capability".equals(control);
  }

  private String rule(String control) {
    if ("guard".equals(control)) return BusinessPolicy.GUARD;
    if ("scope".equals(control)) return BusinessPolicy.IAM;
    if ("doc-acl".equals(control)) return BusinessPolicy.ACL;
    if ("facts".equals(control)) return BusinessPolicy.FACTS;
    if ("suitability".equals(control)) return BusinessPolicy.SUITABILITY;
    if ("capability".equals(control)) return BusinessPolicy.CAPABILITY;
    return "";
  }

  private Map<String, Object> reason(String category, String code, String explanation) {
    return Findings.map("category", category, "code", code, "explanation", explanation);
  }
}
