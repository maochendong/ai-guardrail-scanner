package dev.aiguard.compat;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/** Contract-based bounded source interpretation. It never executes application code. */
public final class BusinessAnalysis {
  public final List<Map<String, Object>> assessments = new ArrayList<Map<String, Object>>();
  // Shared engine facts are independent from which business rules the profile publishes.
  final List<Map<String, Object>> semanticAssessments = new ArrayList<Map<String, Object>>();
  // At most 2 languages * (3 Guard outcomes + 3 * 3 paired retrieval outcomes).
  // These representatives survive the public detail cap without changing flow budgets.
  private final Map<String, List<Map<String, Object>>> semanticRepresentatives =
      new LinkedHashMap<String, List<Map<String, Object>>>();
  private Map<String, Object> lastIdentitySite;
  private final Map<String, Set<String>> semanticFailureLanguages =
      new HashMap<String, Set<String>>();
  private String limitedPath = "";
  public final List<Map<String, Object>> diagnostics = new ArrayList<Map<String, Object>>();
  private final BusinessPolicy policy;
  private final Cancel cancel;
  private final Map<String, Outcome> outcomes = new LinkedHashMap<String, Outcome>();
  private final Map<String, Map<String, Object>> guardReviewSites =
      new LinkedHashMap<String, Map<String, Object>>();
  private boolean guardReviewTruncated;
  private final Map<String, String> literals = new HashMap<String, String>();
  private int operations, serial;
  private boolean incomplete;
  private final Set<String> limitedRules = new HashSet<String>();
  private final Set<String> incompleteSourceRules = new HashSet<String>();
  private final Set<String> bindingRules = new HashSet<String>();
  private final Set<String> declaredRules = new HashSet<String>();
  private List<State> exceptionFrame;
  private BusinessFlow.Function currentFunction;
  private final Map<String, BusinessFlow.Function> localFunctions =
      new LinkedHashMap<String, BusinessFlow.Function>();
  private final Set<String> callStack = new LinkedHashSet<String>();
  private final Set<String> relevanceStack = new HashSet<String>();
  private final Map<String, Boolean> relevanceCache = new HashMap<String, Boolean>();
  private final Set<String> relatedFunctions = new HashSet<String>();
  private final Map<String, Boolean> identityParameterCache = new HashMap<String, Boolean>();
  private final List<Map<String, Object>> callContextSites = new ArrayList<Map<String, Object>>();
  private boolean callContextSitesTruncated;
  private int localCalls;
  private int localDepth, callOperations;
  private List<Map<String, Object>> streamTimingSites = Collections.emptyList();
  private boolean streamTimingSitesTruncated;
  private Map<String, List<Map<String, Object>>> collectionReviewSites = Collections.emptyMap();
  private boolean collectionReviewSitesTruncated;
  private final Set<String> callSites = new HashSet<String>(),
      modelSourceSites = new HashSet<String>(),
      boundarySites = new HashSet<String>(),
      candidateSites = new HashSet<String>(),
      bindingFailures = new HashSet<String>();
  public final Map<String, Object> mappingCoverage =
      Findings.map(
          "contractDefinitions",
          0,
          "matchedDefinitions",
          0,
          "matchedCallSites",
          0,
          "matchedBoundarySites",
          0,
          "candidateCallSites",
          0,
          "argumentBindingFailures",
          0,
          "analyzedFunctions",
          0,
          "incompleteSourceFiles",
          0,
          "sourceDigestMatched",
          true);
  private String mappingFailure = "";

  private BusinessAnalysis(BusinessPolicy policy, Cancel cancel) {
    this.policy = policy;
    this.cancel = cancel;
    for (BusinessPolicy.Contract contract : policy.allContracts()) related(contract, declaredRules);
    mappingCoverage.put("contractDefinitions", policy.contractCount());
  }

  public static BusinessAnalysis analyze(
      Inventory inventory, BusinessPolicy policy, Cancel cancel) {
    return analyze(inventory, policy, cancel, new JavaSyntax.Cache(), new PythonSyntax.Cache());
  }

  public static BusinessAnalysis analyze(
      Inventory inventory,
      BusinessPolicy policy,
      Cancel cancel,
      JavaSyntax.Cache javaSyntax,
      PythonSyntax.Cache pythonSyntax) {
    if (policy.contractCount() == 0 || !policy.matchesSourceDigest(inventory.digest)) {
      BusinessFlow.Program empty = new BusinessFlow.Program();
      empty.diagnostics.add(
          Findings.diagnostic(
              "BANK_POLICY_UNMAPPED",
              "",
              "No operator semantic contracts supplied; bank controls remain unassessed."));
      BusinessAnalysis missing = new BusinessAnalysis(policy, cancel);
      missing.mappingFailure =
          policy.contractCount() == 0 ? "NO_OPERATOR_MAPPING" : "STALE_SOURCE_MAPPING";
      missing.mappingCoverage.put(
          "sourceDigestMatched", policy.matchesSourceDigest(inventory.digest));
      missing.diagnostics.addAll(empty.diagnostics);
      missing.finish();
      return missing;
    }
    BusinessFlow.Program java =
        BusinessJavaAnalysis.adapt(inventory.javaAndConfig, cancel, policy, javaSyntax);
    BusinessFlow.Program python =
        BusinessPythonAnalysis.adapt(inventory.python, cancel, policy, pythonSyntax);
    java.functions.addAll(python.functions);
    java.diagnostics.addAll(python.diagnostics);
    java.incompletePaths.addAll(python.incompletePaths);
    return analyze(java, policy, cancel);
  }

  public static BusinessAnalysis analyze(
      BusinessFlow.Program program, BusinessPolicy policy, Cancel cancel) {
    BusinessAnalysis analysis = new BusinessAnalysis(policy, cancel);
    Set<String> duplicateIds = new HashSet<String>();
    for (BusinessFlow.Function function : program.functions) {
      cancel.check();
      if (function.id.isEmpty()) continue;
      if (analysis.localFunctions.put(function.id, function) != null) duplicateIds.add(function.id);
    }
    for (String duplicate : duplicateIds) analysis.localFunctions.remove(duplicate);
    analysis.diagnostics.addAll(program.diagnostics);
    analysis.mappingCoverage.put("incompleteSourceFiles", program.incompletePaths.size());
    if (!program.incompletePaths.isEmpty()) {
      analysis.incompleteSourceRules.addAll(analysis.declaredRules);
      for (String path : program.incompletePaths)
        analysis.semanticFailure(analysis.declaredRules, "SOURCE_FLOW_INCOMPLETE", path);
    }
    int analyzed = 0;
    Set<String> definitions = new HashSet<String>();
    try {
      for (BusinessFlow.Function function : program.functions) {
        analysis.tick();
        if (policy.contract(function.symbol, function.params.size()) != null)
          definitions.add(function.symbol + "/" + function.params.size());
        if (!analysis.relevant(function)) continue;
        analyzed++;
        analysis.currentFunction = function;
        analysis.callStack.clear();
        if (!function.id.isEmpty()) analysis.callStack.add(function.id);
        State initial = new State();
        for (Map<String, Object> diagnostic : program.diagnostics)
          if (function.path.equals(diagnostic.get("path"))
              && !"local".equals(diagnostic.get("flowScope"))) initial.uncertain = true;
        for (String param : function.params) initial.vars.put(param, analysis.fresh(null));
        try {
          List<State> exits = analysis.walk(function.body, Arrays.asList(initial), 0);
          for (State exit : exits)
            if ("RETURN".equals(exit.stopped) && exit.returnStatement != null)
              analysis.boundary(exit.returnStatement, exit.returnValue, exit);
        } catch (Limit limit) {
          analysis.incomplete = true;
          analysis.markLimited(function);
          analysis.diagnostics.add(
              Findings.diagnostic(
                  "BANK_FLOW_LIMIT",
                  function.path,
                  "Mapped function exceeds local path or nesting limits; coverage is incomplete."));
        } finally {
          analysis.callStack.clear();
        }
      }
    } catch (Limit limit) {
      analysis.incomplete = true;
      for (BusinessFlow.Function function : program.functions) analysis.markLimited(function);
      analysis.diagnostics.add(
          Findings.diagnostic(
              "BANK_FLOW_LIMIT",
              "",
              "Bank local-flow budget exhausted; remaining paths are unknown."));
    }
    analysis.mappingCoverage.put("matchedDefinitions", definitions.size());
    analysis.mappingCoverage.put("analyzedFunctions", analyzed);
    if (policy.contractCount() > 0) {
      BusinessStreamTiming timing = BusinessStreamTiming.analyze(program, policy, cancel);
      analysis.streamTimingSites = timing.sites;
      analysis.streamTimingSitesTruncated = timing.truncated;
      BusinessCollectionAnalysis collections =
          BusinessCollectionAnalysis.analyze(program, policy, cancel);
      analysis.collectionReviewSites = collections.sitesByRule;
      analysis.collectionReviewSitesTruncated = collections.truncated;
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
    BusinessPolicy.Contract decisionContract;
    String decisionOwner = "";
    boolean accepted = true;
    boolean knownLiteral;
    boolean iterationElement;
    boolean structured;
    // A decoded JSON value has stable identity but an open, non-enumerated schema.
    boolean jsonUnknown;
    String jsonNodeKind = "";
    Object jsonScalar;
    String structureKind = "";
    Object literal;
    BusinessPolicy.Contract pending;
    Proof pendingProof;
    final Set<String> labels = new HashSet<String>();
    final Map<String, Value> members = new LinkedHashMap<String, Value>();
    // A get/default result may alias its container's field or its default, without
    // being provably equal to either. These edges only invalidate mutation proofs.
    final List<Value> mutationSources = new ArrayList<Value>();
    final List<Map<String, Object>> reasons = new ArrayList<Map<String, Object>>();
    final List<Map<String, Object>> trace = new ArrayList<Map<String, Object>>();
  }

  private static final class Proof {
    String key;
    int epoch;
    Map<String, Object> evidence;
    final List<Value> checked = new ArrayList<Value>();
    final Map<String, Value> objectSnapshots = new HashMap<String, Value>();
    boolean assured = true, failureOpen, failureUnknown;
  }

  private static final class State {
    final Map<String, Value> vars = new HashMap<String, Value>();
    // Immutable object versions keep field writes local to each explored path.
    final Map<String, Value> objects = new HashMap<String, Value>();
    // Lazy reads are path-local observations, not object writes. Inner maps are immutable.
    final Map<String, Map<String, Value>> jsonFields = new HashMap<String, Map<String, Value>>();
    final Map<String, Proof> proofs = new LinkedHashMap<String, Proof>();
    // Observed checks aid diagnosis even when opaque arguments prevent granting a proof.
    final Map<String, Proof> checks = new LinkedHashMap<String, Proof>();
    final List<Map<String, Object>> reasons = new ArrayList<Map<String, Object>>();
    final Map<String, Boolean> conditions = new HashMap<String, Boolean>();
    final Set<String> invalidated = new HashSet<String>();
    final Set<Proof> invalidatedProofs = new HashSet<Proof>();
    boolean uncertain;
    int epoch;
    String stopped = "";
    Value returnValue;
    BusinessFlow.Stmt returnStatement;

    State copy() {
      State copy = new State();
      copy.vars.putAll(vars);
      copy.objects.putAll(objects);
      copy.jsonFields.putAll(jsonFields);
      copy.proofs.putAll(proofs);
      copy.checks.putAll(checks);
      copy.reasons.addAll(reasons);
      copy.conditions.putAll(conditions);
      copy.invalidated.addAll(invalidated);
      copy.invalidatedProofs.addAll(invalidatedProofs);
      copy.uncertain = uncertain;
      copy.stopped = stopped;
      copy.returnValue = returnValue;
      copy.returnStatement = returnStatement;
      copy.epoch = epoch;
      return copy;
    }
  }

  private static final class Outcome {
    boolean violated, unknown;
    int sites;
    final Set<String> seen = new HashSet<String>();
    final List<Map<String, Object>> evidence = new ArrayList<Map<String, Object>>();
    final List<Map<String, Object>> reasons = new ArrayList<Map<String, Object>>();
    final Map<String, Map<String, Object>> siteAssessments =
        new LinkedHashMap<String, Map<String, Object>>();
    boolean sitesTruncated;
  }

  private static final class Limit extends RuntimeException {
    private static final long serialVersionUID = 1L;
  }

  private void tick() {
    cancel.check();
    // Expanded source calls must not consume the independent-entry coverage budget.
    if (localDepth > 0) {
      if (++callOperations > 200000) throw new Limit();
    } else if (++operations > 200000) throw new Limit();
  }

  private Value fresh(BusinessFlow.Expr expr) {
    Value value = new Value();
    value.id = "v" + (++serial);
    return value;
  }

  private Value unknown(BusinessFlow.Expr expr) {
    Value v = fresh(expr);
    v.opaque = true;
    return v;
  }

  private List<State> walk(List<BusinessFlow.Stmt> block, List<State> states, int depth) {
    if (depth > 64 || states.size() > 64) throw new Limit();
    List<State> current = states;
    for (BusinessFlow.Stmt statement : block) {
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
        } else if ("RETURN".equals(statement.kind)
            || "THROW".equals(statement.kind)
            || "YIELD".equals(statement.kind)) {
          Value value = statement.expr == null ? fresh(null) : eval(statement.expr, state, 0);
          if (!state.stopped.isEmpty()) {
            next.add(state);
            continue;
          }
          if (statement.expr == null) value.knownLiteral = true;
          if ("THROW".equals(statement.kind)) exceptional(state);
          else if ("YIELD".equals(statement.kind)) boundary(statement, value, state);
          else {
            state.returnValue = value;
            state.returnStatement = statement;
          }
          if (!"YIELD".equals(statement.kind)) state.stopped = statement.kind;
          next.add(state);
        } else if ("IF".equals(statement.kind)) {
          next.addAll(
              walk(statement.body, branch(statement.expr, state.copy(), true, 0), depth + 1));
          next.addAll(
              walk(statement.otherwise, branch(statement.expr, state.copy(), false, 0), depth + 1));
        } else if ("ITERATE".equals(statement.kind)) {
          Value iterable = eval(statement.expr, state, 0);
          State zero = state.copy(), iteration = state.copy();
          zero.uncertain = iteration.uncertain = true;
          zero.proofs.clear();
          iteration.proofs.clear();
          zero.epoch++;
          iteration.epoch++;
          reason(
              zero.reasons,
              "UNSUPPORTED",
              "ITERATION_FLOW_BOUNDED",
              "Only zero and one representative iteration are modeled; later iterations remain"
                  + " unresolved.");
          iteration.reasons.clear();
          iteration.reasons.addAll(zero.reasons);
          Value element = fresh(statement.expr);
          inherit(element, iterable);
          element.iterationElement = true;
          element.opaque =
              iterable.opaque
                  || iterable.labels.isEmpty()
                  || state.invalidated.contains(iterable.id);
          if (element.opaque)
            reason(
                element.reasons,
                "UNSUPPORTED",
                "STREAM_ELEMENT_UNRESOLVED",
                "The iteration source binding or element semantics is not fully established.");
          iteration.vars.put(statement.target, element);
          next.addAll(walk(statement.otherwise, Arrays.asList(zero), depth + 1));
          for (State candidate : walk(statement.body, Arrays.asList(iteration), depth + 1)) {
            // A check of one element cannot certify another iteration or an aggregate result.
            candidate.proofs.clear();
            candidate.epoch++;
            if (!candidate.stopped.isEmpty()) next.add(candidate);
            else next.addAll(walk(statement.otherwise, Arrays.asList(candidate), depth + 1));
          }
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
          List<State> beforeFinally = new ArrayList<State>();
          // Exceptions from handlers or an else suite must also pass through this finally.
          exceptionFrame = beforeFinally;
          try {
            for (State s : tried) {
              if (s.stopped.isEmpty())
                normal.addAll(walk(statement.otherwise, Arrays.asList(s), depth + 1));
              else if (!"THROW".equals(s.stopped)) normal.add(s);
            }
            // Exception types are not inferred; every declared handler remains a candidate.
            for (State thrownState : thrown) {
              for (List<BusinessFlow.Stmt> handler : statement.handlers)
                normal.addAll(walk(handler, Arrays.asList(thrownState.copy()), depth + 1));
              State escaping = thrownState.copy();
              escaping.stopped = "THROW";
              normal.add(escaping);
            }
          } finally {
            exceptionFrame = previousFrame;
          }
          for (State escaping : beforeFinally) {
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
        if (next.size() > 64) next = compress(next);
      }
      current = next;
    }
    return current;
  }

  /** Collapse excess paths conservatively, retaining later sites without certifying them. */
  private List<State> compress(List<State> states) {
    Map<String, State> groups = new LinkedHashMap<String, State>();
    for (State state : states) {
      String key =
          state.stopped
              + ":"
              + (state.returnStatement == null
                  ? ""
                  : state.returnStatement.path + ":" + state.returnStatement.line);
      State merged = groups.get(key);
      if (merged == null) {
        merged = state.copy();
        merged.uncertain = true;
        merged.proofs.clear();
        merged.conditions.clear();
        merged.checks.clear();
        merged.epoch++;
        groups.put(key, merged);
      } else {
        Set<String> names = new HashSet<String>(merged.vars.keySet());
        names.addAll(state.vars.keySet());
        for (String name : names)
          merged.vars.put(name, join(merged.vars.get(name), state.vars.get(name)));
        merged.invalidated.addAll(state.invalidated);
        merged.invalidatedProofs.addAll(state.invalidatedProofs);
        mergeObjects(merged, state);
        for (Map<String, Object> reason : state.reasons)
          if (!merged.reasons.contains(reason)) merged.reasons.add(reason);
        merged.epoch = Math.max(merged.epoch, state.epoch + 1);
        merged.returnValue = join(merged.returnValue, state.returnValue);
      }
    }
    if (groups.size() > 64) throw new Limit();
    String path = currentFunction == null ? "" : currentFunction.path;
    Map<String, Object> diagnostic =
        Findings.diagnostic(
            "BANK_PATHS_MERGED",
            path,
            "Excess local paths were conservatively merged; subsequent sites remain unknown.");
    if (!diagnostics.contains(diagnostic)) diagnostics.add(diagnostic);
    return new ArrayList<State>(groups.values());
  }

  private Value join(Value left, Value right) {
    if (left != null
        && right != null
        && left.id.equals(right.id)
        && left.opaque == right.opaque
        && left.sense == right.sense
        && Objects.equals(left.bool, right.bool)) return left;
    Value merged = unknown(null);
    if (left != null) inherit(merged, left);
    if (right != null) inherit(merged, right);
    return merged;
  }

  private void exceptional(State state) {
    if (exceptionFrame != null) {
      if (exceptionFrame.size() >= 64) {
        List<State> combined = compress(exceptionFrame);
        exceptionFrame.clear();
        exceptionFrame.addAll(combined);
      }
      State copy = state.copy();
      copy.stopped = "";
      exceptionFrame.add(copy);
    }
  }

  private List<State> branch(BusinessFlow.Expr expr, State state, boolean desired, int depth) {
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
        return out.size() > 64 ? compress(out) : out;
      }
    }
    Value value = eval(expr, state, 0);
    if (!state.stopped.isEmpty()) return Arrays.asList(state);
    if (value.bool != null && value.bool.booleanValue() != desired) return Collections.emptyList();
    boolean originalDesired = desired == value.sense;
    Boolean prior = state.conditions.get(value.id);
    if (prior != null && prior.booleanValue() != originalDesired) return Collections.emptyList();
    state.conditions.put(value.id, originalDesired);
    if (value.opaque || (value.decision != null && value.decision.epoch != state.epoch))
      state.uncertain = true;
    if (value.decision != null
        && value.decision.epoch == state.epoch
        && freshProof(value.decision, state)
        && desired == value.accepted
        && decisionSatisfied(value, state)) state.proofs.put(value.decision.key, value.decision);
    return Arrays.asList(state);
  }

  private Value eval(BusinessFlow.Expr expr, State state, int depth) {
    tick();
    if (depth > 64) throw new Limit();
    if (!state.stopped.isEmpty()) return unknown(expr);
    if (expr == null) return unknown(null);
    if ("UNKNOWN".equals(expr.kind) && (!expr.args.isEmpty() || expr.receiver != null)) {
      state.uncertain = true;
    }
    if ("NAME".equals(expr.kind)) {
      Value value = state.vars.get(expr.name);
      return value == null ? unknown(expr) : current(value, state);
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
      value.knownLiteral = true;
      value.literal = expr.literal;
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
      BusinessFlow.Expr right = expr.args.get(1);
      if ("LITERAL".equals(right.kind) && right.literal instanceof Boolean) {
        if (((Boolean) right.literal).booleanValue() == and) return left;
        return eval(right, state, depth + 1);
      }
      state.uncertain = true;
      eval(right, state, depth + 1);
      return unknown(expr);
    }
    if ("MAP".equals(expr.kind)) {
      Value map = fresh(expr);
      map.redacted = true;
      map.structured = true;
      map.structureKind = expr.name.isEmpty() ? "map" : expr.name;
      for (Map.Entry<String, BusinessFlow.Expr> member : expr.members.entrySet()) {
        Value value = eval(member.getValue(), state, depth + 1);
        map.members.put(member.getKey(), value);
        map.labels.addAll(value.labels);
        map.sensitive |= value.sensitive;
        map.opaque |= value.opaque;
        if (value.sensitive && !value.redacted) map.redacted = false;
        inherit(map, value);
      }
      if (expr.generatedMethodUncertain)
        return unverifiedGenerated(expr, state, new ArrayList<Value>(map.members.values()));
      return map;
    }
    // Python evaluates the assigned value before the subscription target/key.
    Value stored = null;
    boolean pythonStore = "PUT_MEMBER".equals(expr.kind) && "dict-key".equals(expr.operator);
    if (pythonStore && !expr.args.isEmpty())
      stored = eval(expr.args.get(expr.args.size() - 1), state, depth + 1);
    // JACKSON_PARSE is emitted only for a source-proven private final default mapper.
    // Its unmodeled instance field is not an arbitrary runtime getter invocation.
    Value receiver =
        expr.receiver == null || "JACKSON_PARSE".equals(expr.kind)
            ? null
            : eval(expr.receiver, state, depth + 1);
    if (receiver != null) receiver = current(receiver, state);
    if ("MEMBER".equals(expr.kind)) {
      if (expr.generatedMethodUncertain)
        return unverifiedGenerated(
            expr,
            state,
            receiver == null ? Collections.<Value>emptyList() : Arrays.asList(receiver));
      Value decision = projection(expr, receiver, Collections.<Value>emptyList(), state);
      if (decision != null) return decision;
      Value key =
          expr.args.size() == 1 ? eval(expr.args.get(0), state, depth + 1) : literal(expr.name);
      if (!state.stopped.isEmpty()) return unknown(expr);
      String selected = memberKey(receiver, key, state);
      if (receiver != null && receiver.jsonUnknown && !"dict-key".equals(expr.operator))
        selected = null;
      if (receiver != null && !state.invalidated.contains(receiver.id) && selected != null) {
        Value field = receiver.members.get(selected);
        if (field != null) return current(field, state);
        if (receiver.jsonUnknown && "dict-key".equals(expr.operator)) {
          exceptional(state);
          return jsonField(receiver, selected, state, expr);
        }
      }
      Value unresolved = unknown(expr);
      if (receiver != null) {
        inherit(unresolved, receiver);
        invalidateCall(state, Arrays.asList(receiver));
      }
      exceptional(state);
      return unresolved;
    }
    List<Value> args = new ArrayList<Value>();
    for (int i = 0; i < expr.args.size(); i++)
      args.add(
          pythonStore && i == expr.args.size() - 1
              ? stored
              : eval(expr.args.get(i), state, depth + 1));
    if (!state.stopped.isEmpty()) return unknown(expr);
    if (expr.kind.startsWith("JACKSON_")) return jackson(expr, receiver, args, state);
    if ("PUT_MEMBER".equals(expr.kind)) {
      if (expr.generatedMethodUncertain) {
        List<Value> touched = new ArrayList<Value>(args);
        if (receiver != null) touched.add(receiver);
        return unverifiedGenerated(expr, state, touched);
      }
      Value key = args.size() == 2 && pythonStore ? args.get(0) : literal(expr.name);
      String selected = memberKey(receiver, key, state);
      if (receiver != null
          && receiver.structured
          && receiver.pending == null
          && !state.invalidated.contains(receiver.id)
          && (args.size() == 1 || pythonStore && args.size() == 2)
          && selected != null) {
        if (receiver.jsonUnknown
            || "list".equals(receiver.structureKind)
            || "json-array".equals(receiver.structureKind)) exceptional(state);
        Value updated = copy(receiver);
        Value old = updated.members.put(selected, args.get(args.size() - 1));
        if (updated.members.size() > 128) throw new Limit();
        // A changed envelope is a new checked value, while unchanged child identities survive.
        invalidateProofsFor(state, receiver);
        refreshStructure(updated, state);
        state.objects.put(receiver.id, updated);
        return "void".equals(expr.operator) || old == null ? literal(null) : current(old, state);
      }
      List<Value> touched = new ArrayList<Value>(args);
      if (receiver != null) touched.add(receiver);
      invalidateCall(state, touched);
      exceptional(state);
      return unknown(expr);
    }
    if ("DICT_GET".equals(expr.kind)
        && receiver != null
        && receiver.structured
        && ("dict".equals(receiver.structureKind) || receiver.jsonUnknown)
        && !state.invalidated.contains(receiver.id)
        && (args.size() == 1 || args.size() == 2)
        && args.get(0).knownLiteral
        && args.get(0).literal instanceof String
        && !args.get(0).opaque) {
      String selected = memberKey(receiver, args.get(0), state);
      Value field = receiver.members.get(selected);
      if (field == null) field = cachedJsonField(receiver, selected, state);
      if (receiver.jsonUnknown) exceptional(state);
      if (field != null) return current(field, state);
      Value fallback = args.size() == 2 ? args.get(1) : literal(null);
      if (!receiver.jsonUnknown) return fallback;
      // Unknown presence is a distinct selected result, never equal to [] or the default.
      String getKey = "get:" + selected + ":default:" + fallback.id;
      Value selectedValue = cachedJsonField(receiver, getKey, state);
      if (selectedValue == null) {
        selectedValue = decodedJson(expr, receiver);
        selectedValue.mutationSources.add(receiver);
        selectedValue.mutationSources.add(fallback);
        inherit(selectedValue, fallback);
        selectedValue.opaque |= fallback.opaque;
        selectedValue.opaque |= state.invalidated.contains(fallback.id);
        if (!builtinJsonValue(fallback, state, new HashSet<String>(), 0)) {
          selectedValue.structured = false;
          selectedValue.jsonUnknown = false;
        }
        cacheJsonField(receiver, getKey, selectedValue, state);
      }
      return current(selectedValue, state);
    }
    if ("DICT_GET".equals(expr.kind)) {
      List<Value> touched = new ArrayList<Value>(args);
      if (receiver != null) touched.add(receiver);
      invalidateCall(state, touched);
      exceptional(state);
      Value unresolved = unknown(expr);
      for (Value value : touched) inherit(unresolved, value);
      return unresolved;
    }
    if ("JSON_LOADS".equals(expr.kind)) {
      if (args.size() == 1
          && args.get(0).knownLiteral
          && args.get(0).literal instanceof String
          && !args.get(0).opaque
          && ((String) args.get(0).literal).length() <= 65536) {
        try {
          return jsonValue(Json.parse((String) args.get(0).literal), 0);
        } catch (java.io.IOException invalidOrUnsupported) {
          // Python accepts some inputs rejected by the bounded strict parser (duplicate keys,
          // NaN or larger/deeper documents). Keep both paths, never invent definite throwing.
          exceptional(state);
          state.uncertain = true;
          return unknown(expr);
        }
      }
      // str/bytes subclasses may override methods used by the standard decoder. Preserve
      // possible input effects and catch paths, then establish a distinct decoded identity.
      Value input = args.size() == 1 ? args.get(0) : unknown(expr);
      invalidateCall(state, args);
      exceptional(state);
      Value decoded = decodedJson(expr, input);
      // A successful standard decode constructs new builtins even when the input's
      // previous value identity was unknown. Provenance reasons remain attached.
      decoded.opaque = false;
      return decoded;
    }
    if ("UNARY".equals(expr.kind)
        && args.size() == 1
        && Arrays.asList("!", "not").contains(expr.operator)) {
      Value value = copy(args.get(0));
      if (value.bool != null) value.bool = !value.bool;
      else if (value.knownLiteral) {
        value.knownLiteral = false;
        value.literal = null;
        value.opaque = true;
      }
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
        if (value.bool == null && value.knownLiteral) {
          value.knownLiteral = false;
          value.literal = null;
          value.opaque = true;
        }
        return value;
      }
    }
    if ("CALL".equals(expr.kind) || "NEW".equals(expr.kind)) {
      // A decision accessor is bound to the exact object returned by that check.
      Value projected = projection(expr, receiver, args, state);
      if (projected != null) return projected;
      Binding binding = bind(expr, args);
      BusinessPolicy.Contract contract = binding == null ? null : binding.contract;
      if (contract != null) {
        args = binding.args;
        callSites.add(site(expr));
        if (expr.bindingUncertain) candidateSites.add(site(expr));
        boolean candidate = expr.bindingUncertain || "candidate".equals(contract.assurance);
        if (!(candidate && "transform".equals(contract.kind))) exceptional(state);
        if ("source".equals(contract.kind)) {
          if ("model-output".equals(contract.label) && !candidate) modelSourceSites.add(site(expr));
          if (!contract.outboundArgs.isEmpty()) {
            State outgoing = state.copy();
            if (candidate) outgoing.uncertain = true;
            egress(expr, select(args, contract.outboundArgs), outgoing);
          }
          Value value = fresh(expr);
          value.labels.add(contract.label);
          value.sensitive = "sensitive".equals(contract.label);
          value.trusted = "trusted-identity".equals(contract.label) && !candidate;
          value.identityKnown = value.trusted || "untrusted-identity".equals(contract.label);
          value.trace.add(location(expr, "source", "Operator-mapped value source."));
          if (candidate)
            uncertain(
                value,
                expr.bindingUncertain ? "RECEIVER_BINDING_UNRESOLVED" : "SOURCE_NOT_QUALIFIED",
                "Mapped source has unresolved binding or candidate semantic assurance.");
          return value;
        }
        if ("transform".equals(contract.kind)) {
          if (candidate) {
            List<Value> touched = new ArrayList<Value>(args);
            if (receiver != null) touched.add(receiver);
            invalidateCall(state, touched);
            exceptional(state);
          }
          Value input = contract.arg < 0 ? receiver : args.get(contract.arg);
          if (input == null) return unknown(expr);
          Value value = copy(input);
          value.opaque |= state.invalidated.contains(input.id);
          if ("redaction".equals(contract.control)) {
            value.id = "v" + (++serial);
            value.redacted = !candidate;
            // Redaction declares a property of the returned value, not literal/member equality.
            value.knownLiteral = false;
            value.literal = null;
            value.members.clear();
            value.structured = false;
            value.jsonUnknown = false;
            value.jsonNodeKind = "";
            value.jsonScalar = null;
            value.structureKind = "";
            value.trusted = false;
            value.decision = null;
            value.pending = null;
            value.bool = null;
          }
          if (candidate) {
            // Candidate preservation is not proven equality, including object membership and
            // decision identity. A fresh identity also prevents an existing heap version from
            // replacing this qualified-unknown value with its trusted input alias.
            value.id = "v" + (++serial);
            value.members.clear();
            value.structured = false;
            value.jsonUnknown = false;
            value.jsonNodeKind = "";
            value.jsonScalar = null;
            value.structureKind = "";
            value.knownLiteral = false;
            value.literal = null;
            value.trusted = false;
            value.identityKnown = false;
            value.decision = null;
            value.decisionContract = null;
            value.decisionOwner = "";
            value.pending = null;
            value.pendingProof = null;
            value.bool = null;
            uncertain(
                value,
                "TRANSFORM_NOT_QUALIFIED",
                "Candidate transformation cannot establish coverage.");
          }
          append(value.trace, location(expr, "transform", "Mapped returned value transformation."));
          return value;
        }
        if ("check".equals(contract.kind)) {
          reviewGuardCall(contract, expr, candidate);
          Value value = fresh(expr);
          List<Value> checked = select(args, contract.args);
          Proof proof = new Proof();
          proof.key = key(contract.control, checked);
          proof.checked.addAll(checked);
          for (Value checkedValue : checked)
            snapshotObjects(checkedValue, proof.objectSnapshots, state, 0);
          proof.epoch = state.epoch;
          proof.assured = !candidate;
          proof.failureOpen = "open".equals(contract.failureMode);
          proof.failureUnknown = "unknown".equals(contract.failureMode);
          proof.evidence =
              location(expr, "control", "Mapped check for these exact argument values.");
          state.checks.put(proof.key, proof);
          if (!opaque(checked, state)) {
            value.accepted = contract.accept;
            if ("normal-return".equals(contract.mode)) state.proofs.put(proof.key, proof);
            else if (!contract.decisionPredicates.isEmpty()) {
              value.pending = contract;
              value.pendingProof = proof;
            } else value.decision = proof;
          } else value.opaque = true;
          return value;
        }
        State sinkState = state.copy();
        if (candidate) {
          sinkState.uncertain = true;
          reason(
              sinkState.reasons,
              "UNSUPPORTED",
              "RECEIVER_BINDING_UNRESOLVED",
              "The mapped sink binding is a candidate and cannot establish a definite boundary.");
        }
        sink(contract, expr, args, sinkState);
        return unknown(expr);
      }
      for (BusinessPolicy.Contract candidateContract : policy.contractsForSymbol(expr.symbol))
        if ("call".equals(candidateContract.boundary)) {
          bindingFailures.add(site(expr));
          related(candidateContract, bindingRules);
          Set<String> affected = new HashSet<String>();
          related(candidateContract, affected);
          semanticFailure(affected, "ARGUMENT_BINDING_UNRESOLVED", expr.path);
          break;
        }
      BusinessFlow.Function target = localFunctions.get(expr.localTargetId);
      if (target != null) {
        List<Value> actual = localArguments(expr, args, target);
        if (actual != null) {
          callContext(expr, target, actual, state);
          if (!expr.localTargetCandidate && !expr.bindingUncertain && !target.executionUncertain)
            return localCall(expr, target, actual, receiver, state);
        }
      }
      // Construction of an unrelated object cannot mutate already checked values.
      if ("NEW".equals(expr.kind)
          && "java.lang.Object#<init>".equals(expr.symbol)
          && args.isEmpty()
          && receiver == null) return unknown(expr);
      State raised = state.copy();
      raised.uncertain = true;
      raised.proofs.clear();
      raised.epoch++;
      exceptional(raised);
      if (receiver != null) args.add(receiver);
      invalidateCall(state, args);
      Value value = unknown(expr);
      for (Value arg : args) inherit(value, arg);
      return value;
    }
    if ("COMPOSITE".equals(expr.kind) || "BINARY".equals(expr.kind)) {
      if ("BINARY".equals(expr.kind) && "+".equals(expr.operator)) {
        boolean builtInLiterals = true;
        for (Value arg : args)
          builtInLiterals &= arg.knownLiteral && !arg.opaque && !state.invalidated.contains(arg.id);
        // Dynamic + may invoke __add__/__radd__/toString and mutate a checked operand.
        if (!builtInLiterals) {
          invalidateCall(state, args);
          exceptional(state);
        }
      }
      Value value = fresh(expr);
      value.redacted = true;
      value.opaque = true;
      for (Value arg : args) {
        value.opaque |= arg.opaque;
        value.sensitive |= arg.sensitive;
        value.labels.addAll(arg.labels);
        value.reasons.addAll(arg.reasons);
        if (arg.sensitive && !arg.redacted) value.redacted = false;
        for (Map<String, Object> evidence : arg.trace) append(value.trace, evidence);
      }
      return value;
    }
    if (!expr.args.isEmpty() || expr.receiver != null) invalidateCall(state, args);
    return unknown(expr);
  }

  /** Bind already evaluated actual values without reordering argument evaluation. */
  private List<Value> localArguments(
      BusinessFlow.Expr expr, List<Value> args, BusinessFlow.Function target) {
    if (args.size() != target.params.size()) return null;
    List<Value> normalized = new ArrayList<Value>(Collections.nCopies(args.size(), (Value) null));
    boolean named = false;
    for (int i = 0; i < args.size(); i++) {
      String name = i < expr.argNames.size() ? expr.argNames.get(i) : "";
      int slot = i;
      if (!name.isEmpty()) {
        named = true;
        slot = target.parameterNames.indexOf(name);
      } else if (named) return null;
      if (slot < 0 || slot >= normalized.size() || normalized.get(slot) != null) return null;
      normalized.set(slot, args.get(i));
    }
    return normalized.contains(null) ? null : normalized;
  }

  private Value localCall(
      BusinessFlow.Expr expr,
      BusinessFlow.Function target,
      List<Value> args,
      Value receiver,
      State caller) {
    if (callStack.size() >= 8
        || callStack.contains(target.id)
        || ++localCalls > 2048
        || callOperations >= 200000) return boundedCall(expr, target, args, receiver, caller);
    State entered = caller.copy();
    entered.vars.clear();
    // A caller executing finally may still hold a pending return; it is not a callee result.
    entered.stopped = "";
    entered.returnValue = null;
    entered.returnStatement = null;
    for (int i = 0; i < args.size(); i++) entered.vars.put(target.params.get(i), args.get(i));
    BusinessFlow.Function previousFunction = currentFunction;
    List<State> previousFrame = exceptionFrame;
    List<State> thrown = new ArrayList<State>();
    List<State> exits = null;
    callStack.add(target.id);
    localDepth++;
    currentFunction = target;
    exceptionFrame = thrown;
    try {
      exits = walk(target.body, Arrays.asList(entered), 0);
      for (State exit : exits)
        if ("RETURN".equals(exit.stopped) && exit.returnStatement != null)
          boundary(exit.returnStatement, exit.returnValue, exit);
    } catch (Limit limit) {
      // Restore the calling frame before recording a conservative normal/exceptional result.
      exits = null;
    } finally {
      currentFunction = previousFunction;
      exceptionFrame = previousFrame;
      callStack.remove(target.id);
      localDepth--;
    }
    if (exits == null) return boundedCall(expr, target, args, receiver, caller);
    for (State raised : thrown) {
      State escaping = caller.copy();
      applyEffects(escaping, raised);
      exceptional(escaping);
    }
    List<State> normal = new ArrayList<State>();
    for (State exit : exits) if (!"THROW".equals(exit.stopped)) normal.add(exit);
    if (normal.isEmpty()) {
      caller.stopped = "THROW";
      return unknown(expr);
    }
    State merged = normal.get(0).copy();
    Value result = returned(normal.get(0));
    for (int i = 1; i < normal.size(); i++) {
      State other = normal.get(i);
      merged.uncertain |= other.uncertain;
      merged.invalidated.addAll(other.invalidated);
      merged.invalidatedProofs.addAll(other.invalidatedProofs);
      mergeObjects(merged, other);
      merged.epoch = Math.max(merged.epoch, other.epoch);
      intersectProofs(merged.proofs, other.proofs);
      intersectProofs(merged.checks, other.checks);
      for (Iterator<Map.Entry<String, Boolean>> it = merged.conditions.entrySet().iterator();
          it.hasNext(); ) {
        Map.Entry<String, Boolean> entry = it.next();
        if (!Objects.equals(entry.getValue(), other.conditions.get(entry.getKey()))) it.remove();
      }
      for (Map<String, Object> item : other.reasons)
        if (!merged.reasons.contains(item)) merged.reasons.add(item);
      result = joinReturn(result, returned(other));
    }
    applyEffects(caller, merged);
    if (caller.invalidated.contains(result.id)) {
      result = copy(result);
      result.opaque = true;
      result.trusted = false;
    }
    result = copy(result);
    append(
        result.trace,
        location(expr, "call", "Value returned by a uniquely bound source call in this context."));
    return result;
  }

  private Value boundedCall(
      BusinessFlow.Expr expr,
      BusinessFlow.Function target,
      List<Value> args,
      Value receiver,
      State caller) {
    List<Value> touched = new ArrayList<Value>(args);
    if (receiver != null) touched.add(receiver);
    invalidateCall(caller, touched);
    caller.conditions.clear();
    caller.uncertain = true;
    reason(
        caller.reasons,
        "UNSUPPORTED",
        "INTERPROCEDURAL_FLOW_BOUNDED",
        "A recursive or bounded source call could not be expanded in this calling context.");
    markLimited(target);
    exceptional(caller);
    Value unresolved = unknown(expr);
    for (Value arg : touched) inherit(unresolved, arg);
    return unresolved;
  }

  private Value returned(State state) {
    if (state.returnValue != null) return current(state.returnValue, state);
    Value value = fresh(null);
    value.knownLiteral = true;
    return value;
  }

  private Value joinReturn(Value left, Value right) {
    if (left.id.equals(right.id)
        && left.opaque == right.opaque
        && left.trusted == right.trusted
        && left.identityKnown == right.identityKnown
        && left.sensitive == right.sensitive
        && left.iterationElement == right.iterationElement
        && left.members.equals(right.members)
        && left.jsonUnknown == right.jsonUnknown
        && left.structureKind.equals(right.structureKind)
        && left.jsonNodeKind.equals(right.jsonNodeKind)
        && Objects.equals(left.jsonScalar, right.jsonScalar)
        && left.labels.equals(right.labels)
        && left.reasons.equals(right.reasons)
        && left.sense == right.sense
        && left.accepted == right.accepted
        && Objects.equals(left.bool, right.bool)
        && left.redacted == right.redacted
        && left.knownLiteral == right.knownLiteral
        && Objects.equals(left.literal, right.literal)
        && left.decision == right.decision
        && left.decisionContract == right.decisionContract
        && left.decisionOwner.equals(right.decisionOwner)
        && left.pending == right.pending
        && left.pendingProof == right.pendingProof) return copy(left);
    Value joined = fresh(null);
    inherit(joined, left);
    inherit(joined, right);
    // Distinct returned identities cannot borrow either branch's value-bound proof.
    joined.opaque = true;
    joined.trusted = left.trusted && right.trusted;
    joined.identityKnown = left.identityKnown && right.identityKnown;
    joined.redacted = left.redacted && right.redacted;
    joined.knownLiteral =
        left.knownLiteral && right.knownLiteral && Objects.equals(left.literal, right.literal);
    if (joined.knownLiteral) {
      joined.literal = left.literal;
      joined.bool = left.bool;
    }
    // Joining values creates a fresh identity; no branch-specific proof or field survives.
    if (left.trusted != right.trusted
        || !left.members.equals(right.members)
        || left.decision != null
        || right.decision != null) joined.opaque = true;
    return joined;
  }

  private void intersectProofs(Map<String, Proof> left, Map<String, Proof> right) {
    for (Iterator<Map.Entry<String, Proof>> it = left.entrySet().iterator(); it.hasNext(); ) {
      Map.Entry<String, Proof> entry = it.next();
      Proof a = entry.getValue(), b = right.get(entry.getKey());
      if (b == null
          || a.epoch != b.epoch
          || a.assured != b.assured
          || a.failureOpen != b.failureOpen
          || a.failureUnknown != b.failureUnknown) it.remove();
    }
  }

  /** Only value effects cross the frame boundary; callee locals never overwrite caller locals. */
  private void applyEffects(State caller, State exit) {
    caller.objects.clear();
    caller.objects.putAll(exit.objects);
    caller.jsonFields.clear();
    caller.jsonFields.putAll(exit.jsonFields);
    caller.uncertain |= exit.uncertain;
    caller.epoch = exit.epoch;
    caller.proofs.clear();
    for (Map.Entry<String, Proof> item : exit.proofs.entrySet())
      if (item.getValue().epoch == exit.epoch) caller.proofs.put(item.getKey(), item.getValue());
    caller.checks.clear();
    caller.checks.putAll(exit.checks);
    caller.conditions.clear();
    caller.conditions.putAll(exit.conditions);
    caller.invalidated.addAll(exit.invalidated);
    caller.invalidatedProofs.addAll(exit.invalidatedProofs);
    for (Map<String, Object> item : exit.reasons)
      if (!caller.reasons.contains(item)) caller.reasons.add(item);
    for (Map.Entry<String, Value> entry : caller.vars.entrySet())
      if (caller.invalidated.contains(entry.getValue().id)) {
        Value changed = copy(entry.getValue());
        changed.opaque = true;
        changed.decision = null;
        changed.pending = null;
        changed.bool = null;
        entry.setValue(changed);
      }
  }

  private void callContext(
      BusinessFlow.Expr call, BusinessFlow.Function target, List<Value> args, State state) {
    List<String> statuses = new ArrayList<String>();
    boolean identity = false;
    for (Value arg : args) {
      identity |= arg.identityKnown;
      statuses.add(
          arg.opaque || state.invalidated.contains(arg.id) || !arg.identityKnown
              ? "unknown"
              : arg.trusted ? "trusted" : "untrusted");
    }
    if (!identity) {
      Boolean known = identityParameterCache.get(target.id);
      if (known == null) {
        known = hasIdentityParameter(target.body, target.params, 0);
        identityParameterCache.put(target.id, known);
      }
      if (!known.booleanValue()) return;
    }
    Map<String, Object> context =
        Findings.map(
            "calleePath",
            target.path,
            "calleeLine",
            target.line,
            "callPath",
            call.path,
            "callLine",
            call.line,
            "binding",
            call.localTargetCandidate || call.bindingUncertain || target.executionUncertain
                ? "candidate"
                : "definite",
            "parameterStates",
            statuses);
    if (callContextSites.contains(context)) return;
    if (callContextSites.size() >= 128) callContextSitesTruncated = true;
    else callContextSites.add(context);
  }

  private boolean hasIdentityParameter(
      List<BusinessFlow.Stmt> body, List<String> params, int depth) {
    cancel.check();
    if (depth > 64) return false;
    for (BusinessFlow.Stmt statement : body) {
      if (hasIdentityParameter(statement.expr, params, depth + 1)
          || hasIdentityParameter(statement.body, params, depth + 1)
          || hasIdentityParameter(statement.otherwise, params, depth + 1)
          || hasIdentityParameter(statement.finalizer, params, depth + 1)) return true;
      for (List<BusinessFlow.Stmt> handler : statement.handlers)
        if (hasIdentityParameter(handler, params, depth + 1)) return true;
    }
    return false;
  }

  private boolean hasIdentityParameter(BusinessFlow.Expr expr, List<String> params, int depth) {
    if (expr == null || depth > 64) return false;
    cancel.check();
    for (BusinessPolicy.Contract contract : policy.contractsForSymbol(expr.symbol)) {
      List<Integer> slots =
          contract.identity >= 0
              ? Arrays.asList(contract.identity)
              : "scope".equals(contract.control) ? contract.args : Collections.<Integer>emptyList();
      for (Integer slot : slots)
        if (slot >= 0
            && slot < expr.args.size()
            && "NAME".equals(expr.args.get(slot).kind)
            && params.contains(expr.args.get(slot).name)) return true;
    }
    if (hasIdentityParameter(expr.receiver, params, depth + 1)) return true;
    for (BusinessFlow.Expr arg : expr.args)
      if (hasIdentityParameter(arg, params, depth + 1)) return true;
    for (BusinessFlow.Expr member : expr.members.values())
      if (hasIdentityParameter(member, params, depth + 1)) return true;
    return false;
  }

  /** Check implementation review is independent of whether its result reaches a release. */
  private void reviewGuardCall(
      BusinessPolicy.Contract contract, BusinessFlow.Expr expr, boolean candidate) {
    if (!"guard".equals(contract.control)) return;
    List<Map<String, Object>> reasons = new ArrayList<Map<String, Object>>();
    if (candidate)
      reason(
          reasons,
          "INSUFFICIENT_EVIDENCE",
          "CONTROL_ASSURANCE_UNVERIFIED",
          "The called check or its runtime binding is a candidate; its security role requires"
              + " qualification.");
    if ("open".equals(contract.failureMode))
      reason(
          reasons,
          "INSUFFICIENT_EVIDENCE",
          "GUARD_FAILURE_OPEN",
          "An actually called check is mapped as failure-open; this observation alone does not"
              + " prove a later unprotected release.");
    else if ("unknown".equals(contract.failureMode))
      reason(
          reasons,
          "INSUFFICIENT_EVIDENCE",
          "GUARD_FAILURE_UNVERIFIED",
          "An actually called check has unverified failure behavior; its relation to output"
              + " requires separate evidence.");
    if (reasons.isEmpty()) return;
    String key = site(expr);
    Map<String, Object> existing = guardReviewSites.get(key);
    if (existing != null) {
      mergeDetails(existing, "unknownReasons", reasons, false);
      return;
    }
    if (guardReviewSites.size() >= 128) {
      guardReviewTruncated = true;
      return;
    }
    guardReviewSites.put(
        key,
        Findings.map(
            "ruleId",
            BusinessPolicy.GUARD,
            "path",
            expr.path,
            "line",
            expr.line,
            "disposition",
            "UNKNOWN",
            "unknownReasons",
            reasons,
            "evidence",
            Arrays.asList(
                location(
                    expr,
                    "control",
                    "Located mapped check requiring semantic review; output reachability is"
                        + " evaluated separately."))));
  }

  private static final class Binding {
    BusinessPolicy.Contract contract;
    List<Value> args;
  }

  private Binding bind(BusinessFlow.Expr expr, List<Value> supplied) {
    Binding match = null;
    for (BusinessPolicy.Contract contract : policy.contractsForSymbol(expr.symbol)) {
      if (!"call".equals(contract.boundary)) continue;
      List<Value> normalized =
          new ArrayList<Value>(Collections.<Value>nCopies(contract.arity, null));
      boolean valid = supplied.size() <= contract.arity;
      Set<String> named = new HashSet<String>();
      boolean keyword = false;
      for (int i = 0; valid && i < supplied.size(); i++) {
        String name = expr.argNames.size() > i ? expr.argNames.get(i) : "";
        int index;
        if (name.isEmpty()) {
          index = i;
          if (keyword) valid = false;
        } else {
          keyword = true;
          index = contract.parameterNames.indexOf(name);
          if (!named.add(name)) valid = false;
        }
        if (index < 0 || index >= normalized.size() || normalized.get(index) != null) valid = false;
        if (valid) normalized.set(index, supplied.get(i));
      }
      for (int i = 0; valid && i < normalized.size(); i++) {
        if (normalized.get(i) != null) continue;
        String name = contract.parameterNames.size() > i ? contract.parameterNames.get(i) : "";
        if (!contract.defaults.containsKey(name)) valid = false;
        else {
          BusinessFlow.Expr literal = new BusinessFlow.Expr("LITERAL");
          literal.literal = contract.defaults.get(name);
          if (literal.literal instanceof java.math.BigDecimal) {
            java.math.BigDecimal number = (java.math.BigDecimal) literal.literal;
            try {
              if (number.scale() <= 0) literal.literal = Long.valueOf(number.longValueExact());
              else literal.kind = "UNKNOWN";
            } catch (ArithmeticException outOfRange) {
              literal.kind = "UNKNOWN";
            }
          }
          normalized.set(i, eval(literal, new State(), 0));
        }
      }
      if (!valid) continue;
      if (match != null) return null; // An overloaded keyword/default match is ambiguous.
      match = new Binding();
      match.contract = contract;
      match.args = normalized;
    }
    return match;
  }

  private Value projection(BusinessFlow.Expr expr, Value receiver, List<Value> args, State state) {
    Value owner =
        receiver != null && receiver.pending != null
            ? receiver
            : args.size() == 1 && args.get(0).pending != null ? args.get(0) : null;
    if (owner == null) return null;
    BusinessPolicy.Contract contract = owner.pending;
    int selected = -1;
    for (int i = 0; i < contract.decisionPredicates.size(); i++) {
      BusinessPolicy.DecisionPredicate predicate = contract.decisionPredicates.get(i);
      if (predicate.symbol.equals(expr.symbol)
          && (predicate.arg == -1
              ? owner == receiver && args.isEmpty()
              : args.size() == 1 && owner == args.get(0))) {
        selected = i;
        break;
      }
    }
    if (selected < 0) return null;
    exceptional(state);
    Value projected = fresh(expr);
    projected.decision = owner.pendingProof;
    projected.accepted = contract.decisionPredicates.get(selected).accept;
    projected.decisionContract = contract;
    projected.decisionOwner = owner.id;
    projected.opaque =
        owner.opaque || expr.bindingUncertain || state.invalidated.contains(owner.id);
    projected.trace.addAll(owner.trace);
    callSites.add(site(expr));
    if (expr.bindingUncertain) candidateSites.add(site(expr));
    if (projected.opaque) projected.decision = null;
    else projected.id = owner.id + "#decision:" + selected;
    return projected;
  }

  private boolean decisionSatisfied(Value value, State state) {
    if (value.decisionContract == null) return true;
    if (state.invalidated.contains(value.decisionOwner)) return false;
    for (int i = 0; i < value.decisionContract.decisionPredicates.size(); i++) {
      Boolean actual = state.conditions.get(value.decisionOwner + "#decision:" + i);
      if (actual == null
          || actual.booleanValue() != value.decisionContract.decisionPredicates.get(i).accept)
        return false;
    }
    return true;
  }

  private void boundary(BusinessFlow.Stmt statement, Value returned, State state) {
    if (currentFunction == null) return;
    BusinessPolicy.Contract contract =
        policy.contract(currentFunction.symbol, currentFunction.params.size());
    String boundary = "YIELD".equals(statement.kind) ? "yield" : "return";
    if (contract == null || !"sink".equals(contract.kind) || !boundary.equals(contract.boundary))
      return;
    BusinessFlow.Expr expr = new BusinessFlow.Expr("CALL");
    expr.path = statement.path;
    expr.line = statement.line;
    expr.symbol = currentFunction.symbol;
    List<Value> values = new ArrayList<Value>();
    values.add(returned);
    for (String param : currentFunction.params) {
      Value value = state.vars.get(param);
      values.add(value == null ? unknown(expr) : value);
    }
    boundarySites.add(site(expr));
    State applied = state.copy();
    if ("candidate".equals(contract.assurance)) applied.uncertain = true;
    sink(contract, expr, values, applied);
  }

  private boolean relevant(BusinessFlow.Function function) {
    BusinessPolicy.Contract contract = policy.contract(function.symbol, function.params.size());
    return contract != null && !"call".equals(contract.boundary) || relevant(function.body, 0);
  }

  private boolean relevant(List<BusinessFlow.Stmt> body, int depth) {
    cancel.check();
    if (depth > 256) return true;
    for (BusinessFlow.Stmt statement : body) {
      if (relevant(statement.expr, depth + 1)
          || relevant(statement.body, depth + 1)
          || relevant(statement.otherwise, depth + 1)
          || relevant(statement.finalizer, depth + 1)) return true;
      for (List<BusinessFlow.Stmt> handler : statement.handlers)
        if (relevant(handler, depth + 1)) return true;
    }
    return false;
  }

  private boolean relevant(BusinessFlow.Expr expr, int depth) {
    if (expr == null) return false;
    cancel.check();
    if (depth > 256) return true;
    if (!policy.contractsForSymbol(expr.symbol).isEmpty() || relevant(expr.receiver, depth + 1))
      return true;
    BusinessFlow.Function target = localFunctions.get(expr.localTargetId);
    if (target != null) {
      Boolean cached = relevanceCache.get(target.id);
      if (cached == null) {
        // A recursion cycle is conservatively relevant, never cached as an absent mapping.
        if (!relevanceStack.add(target.id)) return true;
        try {
          BusinessPolicy.Contract boundary = policy.contract(target.symbol, target.params.size());
          cached =
              boundary != null && !"call".equals(boundary.boundary)
                  || relevant(target.body, depth + 1);
          relevanceCache.put(target.id, cached);
        } finally {
          relevanceStack.remove(target.id);
        }
      }
      if (cached.booleanValue()) return true;
    }
    for (BusinessFlow.Expr arg : expr.args) if (relevant(arg, depth + 1)) return true;
    for (BusinessFlow.Expr value : expr.members.values())
      if (relevant(value, depth + 1)) return true;
    return false;
  }

  private void markLimited(BusinessFlow.Function function) {
    String previous = limitedPath;
    limitedPath = function.path;
    try {
      related(policy.contract(function.symbol, function.params.size()));
      related(function.body, 0);
    } finally {
      limitedPath = previous;
    }
  }

  private void related(List<BusinessFlow.Stmt> body, int depth) {
    cancel.check();
    if (depth > 256) {
      limitedRules.addAll(declaredRules);
      semanticFailure(declaredRules, "BANK_ANALYSIS_BOUNDED", limitedPath);
      return;
    }
    for (BusinessFlow.Stmt statement : body) {
      related(statement.expr, depth + 1);
      related(statement.body, depth + 1);
      related(statement.otherwise, depth + 1);
      related(statement.finalizer, depth + 1);
      for (List<BusinessFlow.Stmt> handler : statement.handlers) related(handler, depth + 1);
    }
  }

  private void related(BusinessFlow.Expr expr, int depth) {
    if (expr == null) return;
    cancel.check();
    if (depth > 256) {
      limitedRules.addAll(declaredRules);
      semanticFailure(declaredRules, "BANK_ANALYSIS_BOUNDED", limitedPath);
      return;
    }
    for (BusinessPolicy.Contract contract : policy.contractsForSymbol(expr.symbol))
      related(contract);
    BusinessFlow.Function target = localFunctions.get(expr.localTargetId);
    if (target != null && relatedFunctions.add(target.id)) {
      related(policy.contract(target.symbol, target.params.size()));
      related(target.body, depth + 1);
    }
    related(expr.receiver, depth + 1);
    for (BusinessFlow.Expr arg : expr.args) related(arg, depth + 1);
    for (BusinessFlow.Expr value : expr.members.values()) related(value, depth + 1);
  }

  private void related(BusinessPolicy.Contract contract) {
    related(contract, limitedRules);
    Set<String> affected = new HashSet<String>();
    related(contract, affected);
    semanticFailure(affected, "BANK_ANALYSIS_BOUNDED", limitedPath);
  }

  private void semanticFailure(Set<String> rules, String code, String path) {
    String language = path.endsWith(".java") ? "java" : path.endsWith(".py") ? "python" : "";
    if (language.isEmpty()) return;
    for (String rule : rules) {
      String key = rule + ":" + code;
      if (!semanticFailureLanguages.containsKey(key))
        semanticFailureLanguages.put(key, new HashSet<String>());
      semanticFailureLanguages.get(key).add(language);
    }
  }

  boolean hasSemanticFailure(String rule, String code, String language) {
    Set<String> languages = semanticFailureLanguages.get(rule + ":" + code);
    return languages != null && languages.contains(language);
  }

  private void related(BusinessPolicy.Contract contract, Set<String> rules) {
    if (contract == null) return;
    if (!contract.outboundArgs.isEmpty()
        || "egress".equals(contract.channel)
        || "redaction".equals(contract.control)) rules.add(BusinessPolicy.DATA);
    if ("guard".equals(contract.control) || "release".equals(contract.channel))
      rules.add(BusinessPolicy.GUARD);
    if ("scope".equals(contract.control)
        || "access".equals(contract.channel)
        || "retrieve".equals(contract.channel)) rules.add(BusinessPolicy.IAM);
    if ("doc-acl".equals(contract.control) || "retrieve".equals(contract.channel))
      rules.add(BusinessPolicy.ACL);
    if ("facts".equals(contract.control) || "recommend".equals(contract.channel))
      rules.add(BusinessPolicy.FACTS);
    if ("suitability".equals(contract.control) || "recommend".equals(contract.channel))
      rules.add(BusinessPolicy.SUITABILITY);
    if ("capability".equals(contract.control) || "tool".equals(contract.channel))
      rules.add(BusinessPolicy.CAPABILITY);
  }

  private static String site(BusinessFlow.Expr expr) {
    return expr.path + ":" + expr.line + ":" + expr.symbol;
  }

  private static String publicSiteId(BusinessFlow.Expr expr) {
    try {
      byte[] bytes =
          MessageDigest.getInstance("SHA-256").digest(site(expr).getBytes(StandardCharsets.UTF_8));
      StringBuilder result = new StringBuilder();
      for (byte value : bytes) {
        result.append("0123456789abcdef".charAt((value & 255) >>> 4));
        result.append("0123456789abcdef".charAt(value & 15));
      }
      return result.toString();
    } catch (NoSuchAlgorithmException impossible) {
      throw new IllegalStateException("SHA-256 unavailable", impossible);
    }
  }

  private static void reason(
      List<Map<String, Object>> reasons, String category, String code, String explanation) {
    Map<String, Object> item =
        Findings.map("category", category, "code", code, "explanation", explanation);
    if (!reasons.contains(item)) reasons.add(item);
  }

  private void uncertain(Value value, String code, String explanation) {
    value.opaque = true;
    reason(
        value.reasons,
        "RECEIVER_BINDING_UNRESOLVED".equals(code) ? "UNSUPPORTED" : "INSUFFICIENT_EVIDENCE",
        code,
        explanation);
  }

  private void inherit(Value value, Value source) {
    value.labels.addAll(source.labels);
    value.sensitive |= source.sensitive;
    value.iterationElement |= source.iterationElement;
    for (Map<String, Object> item : source.reasons)
      if (!value.reasons.contains(item)) value.reasons.add(item);
    for (Map<String, Object> item : source.trace) append(value.trace, item);
  }

  private Value unverifiedGenerated(BusinessFlow.Expr expr, State state, List<Value> touched) {
    Value value = unknown(expr);
    for (Value source : touched) inherit(value, source);
    reason(
        value.reasons,
        "INSUFFICIENT_EVIDENCE",
        "GENERATED_METHOD_CONFIGURATION_UNVERIFIED",
        "The generated constructor or accessor has no closed, verified default configuration;"
            + " candidate field relationships cannot establish a value-bound security proof.");
    for (Map<String, Object> item : value.reasons)
      if (!state.reasons.contains(item)) state.reasons.add(item);
    state.uncertain = true;
    invalidateCall(state, touched);
    exceptional(state);
    return value;
  }

  private void egress(BusinessFlow.Expr expr, List<Value> data, State state) {
    boolean sensitive = false, redacted = true;
    for (Value raw : data) {
      Value value = materialized(raw, state, new HashSet<String>(), 0);
      sensitive |= value.sensitive;
      if (value.sensitive && !value.redacted) redacted = false;
    }
    record(BusinessPolicy.DATA, expr, data, state, redacted, null, !sensitive);
  }

  private void invalidateCall(State state, List<Value> args) {
    if (!state.proofs.isEmpty()) state.uncertain = true;
    state.proofs.clear();
    state.checks.clear();
    state.epoch++;
    Set<String> touched = new HashSet<String>();
    for (Value arg : args) collectTouched(current(arg, state), touched, state, 0);
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

  private void collectTouched(Value value, Set<String> touched, State state, int depth) {
    value = current(value, state);
    if (depth > 64) throw new Limit();
    if (!touched.add(value.id)) return;
    for (Value member : value.members.values()) collectTouched(member, touched, state, depth + 1);
    for (Value source : value.mutationSources) collectTouched(source, touched, state, depth + 1);
    Map<String, Value> observed = state.jsonFields.get(value.id);
    if (observed != null)
      for (Value member : observed.values()) collectTouched(member, touched, state, depth + 1);
  }

  private void snapshotObjects(Value value, Map<String, Value> snapshots, State state, int depth) {
    if (depth > 64) throw new Limit();
    value = current(value, state);
    if (snapshots.containsKey(value.id)) return;
    if (!value.structured && value.mutationSources.isEmpty()) return;
    snapshots.put(value.id, value);
    for (Value source : value.mutationSources) snapshotObjects(source, snapshots, state, depth + 1);
    for (Value member : value.members.values())
      snapshotObjects(member, snapshots, state, depth + 1);
    Map<String, Value> observed = state.jsonFields.get(value.id);
    if (observed != null)
      for (Value member : observed.values()) snapshotObjects(member, snapshots, state, depth + 1);
  }

  private boolean freshProof(Proof proof, State state) {
    if (state.invalidatedProofs.contains(proof)) return false;
    for (Value snapshot : proof.objectSnapshots.values())
      if (current(snapshot, state) != snapshot || state.invalidated.contains(snapshot.id))
        return false;
    return true;
  }

  private Value materialized(Value raw, State state, Set<String> seen, int depth) {
    if (depth > 64) throw new Limit();
    Value value = current(raw, state);
    if (!value.structured || !seen.add(value.id)) return value;
    Value resolved = copy(value);
    resolved.members.clear();
    for (Map.Entry<String, Value> member : value.members.entrySet())
      resolved.members.put(
          member.getKey(), materialized(member.getValue(), state, seen, depth + 1));
    Map<String, Value> observed = state.jsonFields.get(value.id);
    if (observed != null)
      for (Map.Entry<String, Value> member : observed.entrySet())
        if (!resolved.members.containsKey(member.getKey()))
          resolved.members.put(
              member.getKey(), materialized(member.getValue(), state, seen, depth + 1));
    refreshStructure(resolved, state);
    return resolved;
  }

  private void refreshStructure(Value value, State state) {
    if (!value.jsonUnknown) {
      value.labels.clear();
      value.sensitive = false;
      value.redacted = true;
      value.opaque = false;
    } else value.redacted = false;
    for (Value item : value.members.values()) {
      Value member = item;
      inherit(value, member);
      value.opaque |= member.opaque || state.invalidated.contains(member.id);
      if (member.sensitive && !member.redacted) value.redacted = false;
    }
  }

  private Value current(Value value, State state) {
    Value updated = state.objects.get(value.id);
    return updated == null ? value : updated;
  }

  private void invalidateProofsFor(State state, Value changed) {
    Set<String> changedIds = new HashSet<String>();
    changedIds.add(changed.id);
    for (Value source : changed.mutationSources) collectTouched(source, changedIds, state, 0);
    // A write through an uncertain get/default alias cannot update the alternate
    // view exactly. Invalidate that view's shape as well as already-granted proofs.
    if (!changed.mutationSources.isEmpty()) state.invalidated.addAll(changedIds);
    Set<String> examined = new HashSet<String>();
    for (Value value : state.vars.values())
      invalidateAliasViews(value, changedIds, state, examined, 0);
    for (Map<String, Value> observed : state.jsonFields.values())
      for (Value value : observed.values())
        invalidateAliasViews(value, changedIds, state, examined, 0);
    for (Map<String, Proof> proofs : Arrays.asList(state.proofs, state.checks))
      for (Iterator<Map.Entry<String, Proof>> it = proofs.entrySet().iterator(); it.hasNext(); ) {
        Proof proof = it.next().getValue();
        Set<String> touched = new HashSet<String>();
        for (Value checked : proof.checked) collectTouched(checked, touched, state, 0);
        if (!Collections.disjoint(touched, changedIds)) {
          state.invalidatedProofs.add(proof);
          it.remove();
        }
      }
  }

  private void invalidateAliasViews(
      Value raw, Set<String> changedIds, State state, Set<String> seen, int depth) {
    if (depth > 64) throw new Limit();
    Value value = current(raw, state);
    if (!seen.add(value.id)) return;
    if (!value.mutationSources.isEmpty()) {
      Set<String> reach = new HashSet<String>();
      collectTouched(value, reach, state, 0);
      if (!Collections.disjoint(reach, changedIds))
        collectOwned(value, state.invalidated, state, new HashSet<String>(), 0);
    }
    for (Value member : value.members.values())
      invalidateAliasViews(member, changedIds, state, seen, depth + 1);
    Map<String, Value> fields = state.jsonFields.get(value.id);
    if (fields != null)
      for (Value member : fields.values())
        invalidateAliasViews(member, changedIds, state, seen, depth + 1);
  }

  private void collectOwned(
      Value raw, Set<String> result, State state, Set<String> seen, int depth) {
    if (depth > 64) throw new Limit();
    Value value = current(raw, state);
    if (!seen.add(value.id)) return;
    result.add(value.id);
    for (Value member : value.members.values())
      collectOwned(member, result, state, seen, depth + 1);
    Map<String, Value> fields = state.jsonFields.get(value.id);
    if (fields != null)
      for (Value member : fields.values()) collectOwned(member, result, state, seen, depth + 1);
  }

  private void mergeObjects(State target, State other) {
    Set<String> ids = new HashSet<String>(target.objects.keySet());
    ids.addAll(other.objects.keySet());
    for (String id : ids) {
      Value a = target.objects.get(id), b = other.objects.get(id);
      if (a == null || b == null || !a.members.equals(b.members)) {
        target.invalidated.add(id);
        target.objects.remove(id);
      }
    }
    // Keep only observations shared by both exits; one branch cannot prove field presence
    // or a selected get/default result on its sibling branch.
    for (Iterator<Map.Entry<String, Map<String, Value>>> it =
            target.jsonFields.entrySet().iterator();
        it.hasNext(); ) {
      Map.Entry<String, Map<String, Value>> entry = it.next();
      Map<String, Value> right = other.jsonFields.get(entry.getKey());
      if (right == null) {
        it.remove();
        continue;
      }
      Map<String, Value> common = new LinkedHashMap<String, Value>();
      for (Map.Entry<String, Value> field : entry.getValue().entrySet())
        if (right.get(field.getKey()) == field.getValue())
          common.put(field.getKey(), field.getValue());
      entry.setValue(common);
    }
  }

  private String memberKey(Value receiver, Value key, State state) {
    if (key == null || !key.knownLiteral || key.opaque || state.invalidated.contains(key.id))
      return null;
    if (key.literal instanceof String) {
      if (receiver != null
          && ("json-array".equals(receiver.structureKind) || "list".equals(receiver.structureKind)))
        return null;
      return receiver != null && receiver.jsonUnknown ? "s:" + key.literal : (String) key.literal;
    }
    if (receiver == null
        || !(receiver.jsonUnknown
            || "json-array".equals(receiver.structureKind)
            || "list".equals(receiver.structureKind))
        || !(key.literal instanceof Byte
            || key.literal instanceof Short
            || key.literal instanceof Integer
            || key.literal instanceof Long
            || key.literal instanceof java.math.BigInteger)) return null;
    try {
      int index = new java.math.BigDecimal(key.literal.toString()).intValueExact();
      return index >= 0 && index < 128 ? "i:" + index : null;
    } catch (ArithmeticException invalid) {
      return null;
    } catch (NumberFormatException invalid) {
      return null;
    }
  }

  private Value decodedJson(BusinessFlow.Expr expr, Value source) {
    Value value = fresh(expr);
    value.structured = true;
    value.jsonUnknown = true;
    value.structureKind = "json";
    value.opaque = source.opaque;
    value.mutationSources.addAll(source.mutationSources);
    inherit(value, source);
    append(
        value.trace,
        location(
            expr,
            "value",
            "A decoded JSON value has a new identity; input approval, identity trust and redaction"
                + " are not transferred to decoded fields."));
    return value;
  }

  private boolean builtinJsonValue(Value raw, State state, Set<String> seen, int depth) {
    if (depth > 32) return false;
    Value value = current(raw, state);
    if (value.opaque || state.invalidated.contains(value.id)) return false;
    if (value.knownLiteral || value.jsonUnknown) return true;
    if (!value.structured
        || !("dict".equals(value.structureKind)
            || "list".equals(value.structureKind)
            || "json-array".equals(value.structureKind))
        || !seen.add(value.id)) return false;
    for (Value member : value.members.values())
      if (!builtinJsonValue(member, state, seen, depth + 1)) return false;
    return true;
  }

  private Value cachedJsonField(Value receiver, String key, State state) {
    Map<String, Value> fields = state.jsonFields.get(receiver.id);
    return fields == null ? null : fields.get(key);
  }

  private void cacheJsonField(Value receiver, String key, Value value, State state) {
    Map<String, Value> fields = new LinkedHashMap<String, Value>();
    Map<String, Value> previous = state.jsonFields.get(receiver.id);
    if (previous != null) fields.putAll(previous);
    if (fields.size() >= 128 && !fields.containsKey(key)) throw new Limit();
    fields.put(key, value);
    state.jsonFields.put(receiver.id, fields);
  }

  private Value jsonField(Value receiver, String key, State state, BusinessFlow.Expr expr) {
    Value value = cachedJsonField(receiver, key, state);
    if (value == null) {
      value = decodedJson(expr, receiver);
      cacheJsonField(receiver, key, value, state);
    }
    return current(value, state);
  }

  private Value jackson(BusinessFlow.Expr expr, Value receiver, List<Value> args, State state) {
    exceptional(state);
    if ("JACKSON_PARSE".equals(expr.kind) && args.size() == 1) {
      Value input = args.get(0);
      if (input.knownLiteral
          && !input.opaque
          && input.literal instanceof String
          && ((String) input.literal).length() <= 65536) {
        try {
          return jacksonValue(Json.parse((String) input.literal), 0);
        } catch (java.io.IOException unsupported) {
          state.uncertain = true;
          return unknown(expr);
        }
      }
      Value node = decodedJson(expr, input);
      node.jsonNodeKind = "unknown";
      node.structureKind = "jackson-json";
      node.opaque = false;
      return node;
    }
    if (receiver == null
        || receiver.jsonNodeKind.isEmpty()
        || state.invalidated.contains(receiver.id)) return unknown(expr);
    if ("JACKSON_TEXT".equals(expr.kind) && args.size() <= 1) {
      Value fallback = args.isEmpty() ? null : args.get(0);
      if (fallback != null
          && (fallback.opaque
              || !fallback.knownLiteral
              || fallback.literal != null && !(fallback.literal instanceof String)))
        return unknown(expr);
      if (!"unknown".equals(receiver.jsonNodeKind) && !"number".equals(receiver.jsonNodeKind)) {
        if (fallback != null
            && ("missing".equals(receiver.jsonNodeKind) || "null".equals(receiver.jsonNodeKind)))
          return fallback;
        if ("string".equals(receiver.jsonNodeKind) || "boolean".equals(receiver.jsonNodeKind))
          return literal(String.valueOf(receiver.jsonScalar));
        return literal("null".equals(receiver.jsonNodeKind) ? "null" : "");
      }
      String cacheKey = "jackson-text:" + (fallback == null ? "none" : fallback.id);
      Value text = cachedJsonField(receiver, cacheKey, state);
      if (text == null) {
        text = fresh(expr);
        inherit(text, receiver);
        text.opaque = receiver.opaque;
        if (fallback != null) inherit(text, fallback);
        append(
            text.trace,
            location(
                expr,
                "value",
                "Jackson asText creates a string value; approval of its JsonNode or source JSON"
                    + " text is not approval of this string."));
        cacheJsonField(receiver, cacheKey, text, state);
      }
      return current(text, state);
    }
    if (args.size() != 1
        || !args.get(0).knownLiteral
        || args.get(0).opaque
        || !(args.get(0).literal instanceof String)
        || state.invalidated.contains(args.get(0).id)) return unknown(expr);
    String key = (String) args.get(0).literal;
    boolean has = "JACKSON_HAS".equals(expr.kind);
    boolean get = "JACKSON_GET".equals(expr.kind);
    boolean path = "JACKSON_PATH".equals(expr.kind);
    if (!(has || get || path)) return unknown(expr);
    if (!"unknown".equals(receiver.jsonNodeKind)) {
      Value field = "object".equals(receiver.jsonNodeKind) ? receiver.members.get(key) : null;
      if (has) return literal(Boolean.valueOf(field != null));
      if (field != null) return current(field, state);
      return get ? literal(null) : missingJackson();
    }
    // PATH may produce MissingNode, GET may produce null. Their values are not interchangeable.
    String cacheKey = (has ? "jackson-has:" : get ? "jackson-get:" : "jackson-path:") + key;
    Value field = cachedJsonField(receiver, cacheKey, state);
    if (field == null) {
      field = has ? fresh(expr) : decodedJson(expr, receiver);
      inherit(field, receiver);
      field.opaque |= receiver.opaque;
      if (!has) {
        field.jsonNodeKind = "unknown";
        field.structureKind = "jackson-json";
      }
      cacheJsonField(receiver, cacheKey, field, state);
    }
    return current(field, state);
  }

  private Value missingJackson() {
    Value value = fresh(null);
    value.jsonNodeKind = "missing";
    return value;
  }

  private Value jacksonValue(com.google.gson.JsonElement element, int depth) {
    tick();
    if (depth > 32) throw new Limit();
    Value value = fresh(null);
    if (element.isJsonNull()) {
      value.jsonNodeKind = "null";
      return value;
    }
    if (element.isJsonPrimitive()) {
      com.google.gson.JsonPrimitive primitive = element.getAsJsonPrimitive();
      value.jsonNodeKind =
          primitive.isString() ? "string" : primitive.isBoolean() ? "boolean" : "number";
      value.jsonScalar =
          primitive.isString()
              ? primitive.getAsString()
              : primitive.isBoolean() ? primitive.getAsBoolean() : primitive.getAsString();
      return value;
    }
    value.structured = true;
    value.jsonNodeKind = element.isJsonArray() ? "array" : "object";
    value.structureKind = element.isJsonArray() ? "jackson-array" : "jackson-dict";
    if (element.isJsonArray()) {
      int index = 0;
      for (com.google.gson.JsonElement item : element.getAsJsonArray()) {
        if (index >= 128) throw new Limit();
        value.members.put("i:" + index++, jacksonValue(item, depth + 1));
      }
    } else
      for (Map.Entry<String, com.google.gson.JsonElement> field :
          element.getAsJsonObject().entrySet()) {
        if (value.members.size() >= 128) throw new Limit();
        value.members.put(field.getKey(), jacksonValue(field.getValue(), depth + 1));
      }
    return value;
  }

  private Value literal(Object object) {
    BusinessFlow.Expr expr = new BusinessFlow.Expr("LITERAL");
    expr.literal = object;
    return eval(expr, new State(), 0);
  }

  private Value jsonValue(com.google.gson.JsonElement element, int depth) {
    tick();
    if (depth > 32) throw new Limit();
    if (element.isJsonNull()) return literal(null);
    if (element.isJsonPrimitive()) {
      com.google.gson.JsonPrimitive p = element.getAsJsonPrimitive();
      if (p.isBoolean()) return literal(p.getAsBoolean());
      if (p.isString()) return literal(p.getAsString());
      // The strict shared parser normalizes numeric tokens and loses Python int/float
      // distinctions. Keep a stable value, not a literal that could prune a real path.
      return fresh(null);
    }
    Value value = fresh(null);
    value.structured = true;
    if (element.isJsonArray()) {
      value.structureKind = "json-array";
      int index = 0;
      for (com.google.gson.JsonElement item : element.getAsJsonArray()) {
        if (index >= 128) throw new Limit();
        value.members.put("i:" + index++, jsonValue(item, depth + 1));
      }
      return value;
    }
    if (!element.isJsonObject()) return unknown(null);
    value.structureKind = "dict";
    for (Map.Entry<String, com.google.gson.JsonElement> field :
        element.getAsJsonObject().entrySet()) {
      if (value.members.size() >= 128) throw new Limit();
      value.members.put(field.getKey(), jsonValue(field.getValue(), depth + 1));
    }
    return value;
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
    value.decisionContract = source.decisionContract;
    value.decisionOwner = source.decisionOwner;
    value.accepted = source.accepted;
    value.trace.addAll(source.trace);
    value.labels.addAll(source.labels);
    value.members.putAll(source.members);
    value.mutationSources.addAll(source.mutationSources);
    value.reasons.addAll(source.reasons);
    value.pending = source.pending;
    value.pendingProof = source.pendingProof;
    value.knownLiteral = source.knownLiteral;
    value.iterationElement = source.iterationElement;
    value.structured = source.structured;
    value.jsonUnknown = source.jsonUnknown;
    value.jsonNodeKind = source.jsonNodeKind;
    value.jsonScalar = source.jsonScalar;
    value.structureKind = source.structureKind;
    value.literal = source.literal;
    return value;
  }

  private List<Value> select(List<Value> values, List<Integer> slots) {
    List<Value> out = new ArrayList<Value>();
    for (Integer slot : slots) out.add(values.get(slot));
    return out;
  }

  private boolean opaque(List<Value> values, State state) {
    for (Value raw : values) {
      Value value = materialized(raw, state, new HashSet<String>(), 0);
      if (value.opaque || state.invalidated.contains(value.id)) return true;
    }
    return false;
  }

  private String key(String control, List<Value> values) {
    StringBuilder out = new StringBuilder(control);
    for (Value value : values) out.append(':').append(value.id);
    return out.toString();
  }

  private void sink(
      BusinessPolicy.Contract contract, BusinessFlow.Expr expr, List<Value> args, State state) {
    if (contract.whenArg >= 0) {
      Value discriminator = args.get(contract.whenArg);
      if (discriminator.knownLiteral
          && !discriminator.opaque
          && !state.invalidated.contains(discriminator.id)) {
        if (!sameLiteral(
            discriminator.bool == null ? discriminator.literal : discriminator.bool,
            contract.whenEquals)) return;
      } else {
        state = state.copy();
        state.uncertain = true;
        reason(
            state.reasons,
            "UNSUPPORTED",
            "SINK_CONDITION_UNRESOLVED",
            "The mapped boundary discriminator is not a known constant; this candidate cannot be"
                + " skipped.");
      }
    }
    List<Value> data = new ArrayList<Value>();
    for (Value raw : select(args, contract.args))
      data.add(materialized(raw, state, new HashSet<String>(), 0));
    if (!contract.valuePath.isEmpty()) {
      List<Value> projected = new ArrayList<Value>();
      for (Value value : data) {
        for (String member : contract.valuePath) {
          value = current(value, state);
          String selected = value.jsonUnknown ? "s:" + member : member;
          Value next = state.invalidated.contains(value.id) ? null : value.members.get(selected);
          if (next == null && !state.invalidated.contains(value.id))
            next = cachedJsonField(value, selected, state);
          if (next == null) {
            Value missing = unknown(expr);
            inherit(missing, value);
            reason(
                missing.reasons,
                "UNSUPPORTED",
                "VALUE_PROJECTION_UNRESOLVED",
                "The mapped output field cannot be resolved from the value on this path.");
            value = missing;
            break;
          }
          value = next;
        }
        projected.add(value);
      }
      data = projected;
    }
    if (!contract.requiresLabel.isEmpty()) {
      boolean relevant = false, unresolved = false;
      for (Value value : data) {
        relevant |= value.labels.contains(contract.requiresLabel);
        unresolved |= value.opaque || (!value.knownLiteral && value.labels.isEmpty());
      }
      if (!relevant && !unresolved) return;
      if (!relevant) {
        state = state.copy();
        state.uncertain = true;
      }
    }
    List<Value> scoped = new ArrayList<Value>();
    if (contract.identity >= 0) scoped.add(args.get(contract.identity));
    scoped.addAll(data);
    if ("egress".equals(contract.channel)) {
      egress(expr, data, state);
    } else if ("release".equals(contract.channel))
      check(BusinessPolicy.GUARD, "guard", expr, data, state, true);
    else if ("access".equals(contract.channel) || "retrieve".equals(contract.channel)) {
      if ("public".equals(contract.scope)) return;
      if (contract.identity < 0 || "unknown".equals(contract.scope)) {
        state = state.copy();
        if (contract.identity < 0)
          reason(
              state.reasons,
              "INSUFFICIENT_EVIDENCE",
              "IDENTITY_SLOT_MISSING",
              "The reviewed API mapping has no identity argument; determine whether upstream or"
                  + " storage enforcement binds the resource to a subject.");
        if ("unknown".equals(contract.scope))
          reason(
              state.reasons,
              "INSUFFICIENT_EVIDENCE",
              "RESOURCE_SCOPE_UNCLASSIFIED",
              "Whether the resource is public, user-scoped or tenant-scoped has not been"
                  + " established.");
        boolean unresolvedScope = "unknown".equals(contract.scope);
        record(BusinessPolicy.IAM, expr, scoped, state, false, null, unresolvedScope);
        if ("retrieve".equals(contract.channel))
          record(BusinessPolicy.ACL, expr, scoped, state, false, null, unresolvedScope);
      } else {
        check(
            BusinessPolicy.IAM, "scope", expr, scoped, state, args.get(contract.identity).trusted);
        if ("retrieve".equals(contract.channel))
          check(BusinessPolicy.ACL, "doc-acl", expr, scoped, state, true);
      }
    } else if ("recommend".equals(contract.channel)) {
      check(BusinessPolicy.FACTS, "facts", expr, data, state, true);
      check(
          BusinessPolicy.SUITABILITY,
          "suitability",
          expr,
          scoped,
          state,
          contract.identity >= 0 && args.get(contract.identity).trusted);
    } else if ("tool".equals(contract.channel))
      check(BusinessPolicy.CAPABILITY, "capability", expr, data, state, true);
  }

  private static boolean sameLiteral(Object actual, Object expected) {
    if (actual instanceof Number && expected instanceof Number) {
      try {
        return new java.math.BigDecimal(actual.toString())
                .compareTo(new java.math.BigDecimal(expected.toString()))
            == 0;
      } catch (NumberFormatException unsupported) {
        return false;
      }
    }
    return Objects.equals(actual, expected);
  }

  private void check(
      String id,
      String control,
      BusinessFlow.Expr expr,
      List<Value> values,
      State state,
      boolean extra) {
    Proof proof = state.proofs.get(key(control, values));
    Proof seenCheck = state.checks.get(key(control, values));
    state = state.copy();
    boolean identityUnknown =
        (BusinessPolicy.IAM.equals(id) || BusinessPolicy.SUITABILITY.equals(id))
            && (values.isEmpty() || !values.get(0).identityKnown);
    if (identityUnknown)
      reason(
          state.reasons,
          "INSUFFICIENT_EVIDENCE",
          "IDENTITY_TRUST_UNVERIFIED",
          "This subject value has no established trusted identity provenance across the analyzed"
              + " boundary.");
    if (seenCheck != null) {
      if (!seenCheck.assured)
        reason(
            state.reasons,
            "INSUFFICIENT_EVIDENCE",
            "CONTROL_ASSURANCE_UNVERIFIED",
            "The located check is only a candidate control; its security purpose and binding"
                + " require qualification.");
      if ("guard".equals(control) && seenCheck.failureOpen)
        reason(
            state.reasons,
            "INSUFFICIENT_EVIDENCE",
            "GUARD_FAILURE_OPEN",
            "The called check is mapped as allowing failures; an accepted result alone cannot"
                + " establish fail-closed behavior.");
      else if ("guard".equals(control) && seenCheck.failureUnknown)
        reason(
            state.reasons,
            "INSUFFICIENT_EVIDENCE",
            "GUARD_FAILURE_UNVERIFIED",
            "The called check has unverified rejection, exception or timeout behavior.");
    }
    boolean element = false;
    for (Value value : values) element |= value.iterationElement;
    if ("guard".equals(control) && element && proof == null)
      reason(
          state.reasons,
          "UNSUPPORTED",
          "STREAM_RELEASE_WITHOUT_BOUND_GUARD",
          "No accepted mapped Guard is bound to this iteration element before its release; later"
              + " checks cannot protect an earlier release.");
    record(
        id,
        expr,
        values,
        state,
        proof != null && extra && proof.assured && !proof.failureOpen && !proof.failureUnknown,
        proof == null ? seenCheck : proof,
        identityUnknown || (proof != null && (!proof.assured || proof.failureUnknown)));
  }

  private void record(
      String id,
      BusinessFlow.Expr expr,
      List<Value> values,
      State state,
      boolean covered,
      Proof proof,
      boolean noClassification) {
    Outcome outcome = outcomes.get(id);
    if (outcome == null) {
      outcome = new Outcome();
      outcomes.put(id, outcome);
    }
    boolean unknown = state.uncertain || opaque(values, state) || noClassification;
    String disposition = unknown ? "UNKNOWN" : covered ? "OBSERVED" : "VIOLATED";
    boolean newSite = outcome.seen.add(site(expr) + ":" + disposition);
    if (newSite) outcome.sites++;
    outcome.unknown |= unknown;
    List<Map<String, Object>> reasons = new ArrayList<Map<String, Object>>();
    if (unknown) {
      reasons.addAll(state.reasons);
      for (Value value : values)
        for (Map<String, Object> item : value.reasons)
          if (!reasons.contains(item)) reasons.add(item);
      if (state.uncertain || opaque(values, state))
        reason(
            reasons,
            "UNSUPPORTED",
            "LOCAL_FLOW_UNRESOLVED",
            "Dynamic binding, mutation, cross-function values or local control flow is not fully"
                + " modeled.");
      if (noClassification)
        reason(
            reasons,
            "INSUFFICIENT_EVIDENCE",
            "SEMANTIC_ASSURANCE_MISSING",
            "Trusted identity, data scope or control failure semantics is not established.");
      for (Map<String, Object> item : reasons)
        if (!outcome.reasons.contains(item)) outcome.reasons.add(item);
    }
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
    retainSemanticRepresentative(id, expr, values, disposition, reasons, chain);
    String siteKey = site(expr) + ":" + disposition;
    Map<String, Object> detail = outcome.siteAssessments.get(siteKey);
    if (detail == null && outcome.siteAssessments.size() < 128) {
      detail =
          Findings.map(
              "ruleId",
              id,
              "siteId",
              publicSiteId(expr),
              "path",
              expr.path,
              "line",
              expr.line,
              "disposition",
              disposition,
              "unknownReasons",
              new ArrayList<Map<String, Object>>(),
              "evidence",
              new ArrayList<Map<String, Object>>(),
              "valueLabels",
              new ArrayList<String>());
      outcome.siteAssessments.put(siteKey, detail);
    } else if (detail == null) outcome.sitesTruncated = true;
    if (detail != null) {
      mergeDetails(detail, "unknownReasons", reasons, false);
      mergeDetails(detail, "evidence", chain, true);
      @SuppressWarnings("unchecked")
      List<String> labels = (List<String>) detail.get("valueLabels");
      for (Value value : values)
        for (String label : value.labels) if (!labels.contains(label)) labels.add(label);
      Collections.sort(labels);
    }
    if ("VIOLATED".equals(disposition)) {
      chain.addAll(outcome.evidence);
      outcome.evidence.clear();
      for (Map<String, Object> e : chain) append(outcome.evidence, e);
    } else for (Map<String, Object> e : chain) append(outcome.evidence, e);
  }

  private void retainSemanticRepresentative(
      String id,
      BusinessFlow.Expr expr,
      List<Value> values,
      String disposition,
      List<Map<String, Object>> reasons,
      List<Map<String, Object>> chain) {
    String language =
        expr.path.endsWith(".java") ? "java" : expr.path.endsWith(".py") ? "python" : "";
    if (language.isEmpty()) return;
    if (BusinessPolicy.GUARD.equals(id)) {
      boolean model = false;
      for (Value value : values) model |= value.labels.contains("model-output");
      String key = language + ":guard:" + disposition;
      if (model && !semanticRepresentatives.containsKey(key))
        semanticRepresentatives.put(
            key, Arrays.asList(semanticSite(id, expr, values, disposition, reasons, chain)));
    } else if (BusinessPolicy.IAM.equals(id)) {
      // sink() records the subject result immediately before the ACL result for a retrieval.
      lastIdentitySite = semanticSite(id, expr, values, disposition, reasons, chain);
    } else if (BusinessPolicy.ACL.equals(id)) {
      if (lastIdentitySite != null && publicSiteId(expr).equals(lastIdentitySite.get("siteId"))) {
        String key =
            language + ":retrieve:" + lastIdentitySite.get("disposition") + ":" + disposition;
        if (!semanticRepresentatives.containsKey(key))
          semanticRepresentatives.put(
              key,
              Arrays.asList(
                  lastIdentitySite, semanticSite(id, expr, values, disposition, reasons, chain)));
      }
      lastIdentitySite = null;
    }
  }

  private static Map<String, Object> semanticSite(
      String id,
      BusinessFlow.Expr expr,
      List<Value> values,
      String disposition,
      List<Map<String, Object>> reasons,
      List<Map<String, Object>> chain) {
    Set<String> labels = new TreeSet<String>();
    for (Value value : values) labels.addAll(value.labels);
    return Findings.map(
        "ruleId",
        id,
        "siteId",
        publicSiteId(expr),
        "path",
        expr.path,
        "line",
        expr.line,
        "disposition",
        disposition,
        "unknownReasons",
        new ArrayList<Map<String, Object>>(reasons),
        "evidence",
        new ArrayList<Map<String, Object>>(chain),
        "valueLabels",
        new ArrayList<String>(labels));
  }

  /** Representatives come first so downstream bounds cannot discard a late, known outcome. */
  List<Map<String, Object>> semanticSites(String id) {
    List<Map<String, Object>> sites = new ArrayList<Map<String, Object>>();
    for (List<Map<String, Object>> pair : semanticRepresentatives.values())
      for (Map<String, Object> site : pair)
        if (id.equals(site.get("ruleId")) && !sites.contains(site)) sites.add(site);
    Outcome outcome = outcomes.get(id);
    if (outcome != null)
      for (Map<String, Object> site : outcome.siteAssessments.values())
        if (!sites.contains(site)) sites.add(site);
    return sites;
  }

  @SuppressWarnings("unchecked")
  private static void mergeDetails(
      Map<String, Object> detail, String key, List<Map<String, Object>> values, boolean bounded) {
    List<Map<String, Object>> target = (List<Map<String, Object>>) detail.get(key);
    for (Map<String, Object> value : values)
      if (!target.contains(value) && (!bounded || target.size() < 16)) target.add(value);
  }

  private static void append(List<Map<String, Object>> list, Map<String, Object> evidence) {
    if (list.size() < 16 && !list.contains(evidence)) list.add(evidence);
  }

  private static Map<String, Object> location(BusinessFlow.Expr expr, String role, String detail) {
    String path = expr == null ? "" : expr.path;
    int line = expr == null ? 1 : Math.max(1, expr.line);
    Map<String, Object> out = Findings.evidence(path, line, detail);
    out.put("role", role);
    out.put("nodeId", path + ":" + line + ":" + role);
    return out;
  }

  private void finish() {
    mappingCoverage.put("matchedCallSites", callSites.size());
    mappingCoverage.put("matchedModelSourceSites", modelSourceSites.size());
    mappingCoverage.put("matchedBoundarySites", boundarySites.size());
    mappingCoverage.put("candidateCallSites", candidateSites.size());
    mappingCoverage.put("argumentBindingFailures", bindingFailures.size());
    if (incomplete && diagnostics.isEmpty())
      diagnostics.add(
          Findings.diagnostic(
              "BANK_FLOW_INCOMPLETE",
              "",
              "Unsupported local control flow remains; bank coverage is incomplete."));
    for (String id : BusinessPolicy.semanticRuleIds()) {
      Outcome outcome = outcomes.get(id);
      String disposition =
          outcome != null && outcome.violated
              ? "VIOLATED"
              : outcome == null
                      || outcome.unknown
                      || limitedRules.contains(id)
                      || incompleteSourceRules.contains(id)
                      || bindingRules.contains(id)
                  ? "UNKNOWN"
                  : "OBSERVED";
      List<Map<String, Object>> evidence =
          outcome == null ? Collections.<Map<String, Object>>emptyList() : outcome.evidence;
      Map<String, Object> finding =
          Findings.assessment(
              id,
              BusinessPolicy.domain(id),
              disposition,
              "HIGH",
              BusinessPolicy.title(id),
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
              "Bounded uniquely bound source calls; independent entries, alias mutation and dynamic"
                  + " dispatch may remain unknown.",
              "No security certification or regulatory compliance determination.");
      if ("UNKNOWN".equals(disposition)) {
        if (!mappingFailure.isEmpty())
          Unknowns.set(
              finding,
              "MISSING_MAPPING",
              mappingFailure,
              "No valid operator mapping applies to this source snapshot.");
        else if (outcome == null && bindingRules.contains(id))
          Unknowns.set(
              finding,
              "UNSUPPORTED",
              "ARGUMENT_BINDING_UNRESOLVED",
              "A mapped API was located but its arguments could not be normalized unambiguously.");
        else if (outcome == null && limitedRules.contains(id))
          Unknowns.set(
              finding,
              "UNSUPPORTED",
              "BANK_ANALYSIS_BOUNDED",
              "A mapped analysis exceeded its budget before all relevant sites could be visited.");
        else if (outcome == null && incompleteSourceRules.contains(id))
          Unknowns.set(
              finding,
              "UNSUPPORTED",
              "SOURCE_FLOW_INCOMPLETE",
              "Source was discarded or left unvisited after a parse or adaptation failure;"
                  + " mapped rule coverage is incomplete.");
        else if (outcome == null)
          Unknowns.set(
              finding,
              "MISSING_MAPPING",
              "NO_RESOLVED_MAPPED_SINK",
              "No applicable sink or output boundary was resolved with a usable semantic mapping.");
        else {
          for (Map<String, Object> reason : outcome.reasons)
            Unknowns.set(
                finding,
                String.valueOf(reason.get("category")),
                String.valueOf(reason.get("code")),
                String.valueOf(reason.get("explanation")));
          if (bindingRules.contains(id))
            Unknowns.set(
                finding,
                "UNSUPPORTED",
                "ARGUMENT_BINDING_UNRESOLVED",
                "A mapped API was located but its arguments could not be normalized"
                    + " unambiguously.");
          if (limitedRules.contains(id))
            Unknowns.set(
                finding,
                "UNSUPPORTED",
                "BANK_ANALYSIS_BOUNDED",
                "An analysis budget was reached; unvisited mapped paths remain unknown.");
          if (incompleteSourceRules.contains(id))
            Unknowns.set(
                finding,
                "UNSUPPORTED",
                "SOURCE_FLOW_INCOMPLETE",
                "Source was discarded or left unvisited after a parse or adaptation failure;"
                    + " mapped rule coverage is incomplete.");
        }
      }
      finding.put("profile", policy.profile);
      finding.put("mappedPathOutcomes", outcome == null ? 0 : outcome.sites);
      finding.put(
          "siteAssessments",
          outcome == null
              ? Collections.<Map<String, Object>>emptyList()
              : new ArrayList<Map<String, Object>>(outcome.siteAssessments.values()));
      finding.put("siteAssessmentsTruncated", outcome != null && outcome.sitesTruncated);
      finding.put(
          "controlReviewSites",
          BusinessPolicy.GUARD.equals(id)
              ? new ArrayList<Map<String, Object>>(guardReviewSites.values())
              : Collections.<Map<String, Object>>emptyList());
      finding.put(
          "controlReviewSitesTruncated", BusinessPolicy.GUARD.equals(id) && guardReviewTruncated);
      finding.put(
          "callContextSites",
          BusinessPolicy.IAM.equals(id)
              ? new ArrayList<Map<String, Object>>(callContextSites)
              : Collections.<Map<String, Object>>emptyList());
      finding.put(
          "callContextSitesTruncated", BusinessPolicy.IAM.equals(id) && callContextSitesTruncated);
      finding.put(
          "streamTimingSites",
          BusinessPolicy.GUARD.equals(id)
              ? streamTimingSites
              : Collections.<Map<String, Object>>emptyList());
      finding.put(
          "streamTimingSitesTruncated",
          BusinessPolicy.GUARD.equals(id) && streamTimingSitesTruncated);
      finding.put(
          "collectionReviewSites",
          collectionReviewSites.containsKey(id)
              ? collectionReviewSites.get(id)
              : Collections.<Map<String, Object>>emptyList());
      finding.put("collectionReviewSitesTruncated", collectionReviewSitesTruncated);
      semanticAssessments.add(finding);
      if (policy.ruleIds().contains(id)) assessments.add(finding);
    }
  }
}
