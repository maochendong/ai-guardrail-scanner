package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import org.junit.Test;

/** First local release facts must not certify a complete stream or a candidate quality check. */
public class BusinessStreamTimingTest {
  private static final Cancel NEVER =
      new Cancel() {
        public void check() {}
      };

  private BusinessPolicy policy() throws Exception {
    List<Map<String, Object>> contracts = new ArrayList<Map<String, Object>>();
    contracts.add(
        Findings.map(
            "symbol", "edge.stream", "arity", 0, "kind", "source", "label", "model-output"));
    contracts.add(
        Findings.map("symbol", "edge.other", "arity", 0, "kind", "source", "label", "sensitive"));
    for (String name : Arrays.asList("check", "candidate", "open", "normal", "object", "quality")) {
      Map<String, Object> c =
          Findings.map(
              "symbol",
              "edge." + name,
              "arity",
              1,
              "kind",
              "check",
              "control",
              "guard",
              "args",
              Arrays.asList(0),
              "accept",
              true,
              "failureMode",
              "open".equals(name) || "quality".equals(name) ? "open" : "closed",
              "assurance",
              "candidate".equals(name) || "quality".equals(name) ? "candidate" : "reviewed");
      if ("normal".equals(name)) c.put("mode", "normal-return");
      if ("object".equals(name))
        c.put("decision", Findings.map("symbol", "edge.accepted", "arg", 0));
      contracts.add(c);
    }
    contracts.add(
        Findings.map(
            "symbol",
            "edge.release",
            "arity",
            1,
            "kind",
            "sink",
            "channel",
            "release",
            "args",
            Arrays.asList(0),
            "requiresLabel",
            "model-output"));
    contracts.add(
        Findings.map(
            "symbol",
            "edge.candidate_release",
            "arity",
            1,
            "kind",
            "sink",
            "channel",
            "release",
            "args",
            Arrays.asList(0),
            "requiresLabel",
            "model-output",
            "assurance",
            "candidate"));
    contracts.add(
        Findings.map(
            "symbol",
            "edge.dispatch",
            "arity",
            2,
            "kind",
            "sink",
            "channel",
            "release",
            "args",
            Arrays.asList(0),
            "requiresLabel",
            "model-output",
            "when",
            Findings.map("arg", 1, "equals", "emit")));
    contracts.add(
        Findings.map(
            "symbol",
            "edge.mask",
            "arity",
            1,
            "kind",
            "transform",
            "control",
            "redaction",
            "arg",
            0));
    contracts.add(
        Findings.map(
            "symbol",
            "edge.keep",
            "arity",
            1,
            "kind",
            "transform",
            "control",
            "preserve",
            "arg",
            0));
    contracts.add(
        Findings.map(
            "symbol",
            "edge.candidate_keep",
            "arity",
            1,
            "kind",
            "transform",
            "control",
            "preserve",
            "arg",
            0,
            "assurance",
            "candidate"));
    contracts.add(
        Findings.map(
            "symbol",
            "edge.bool_dispatch",
            "arity",
            2,
            "kind",
            "sink",
            "channel",
            "release",
            "args",
            Arrays.asList(0),
            "requiresLabel",
            "model-output",
            "when",
            Findings.map("arg", 1, "equals", false)));
    contracts.add(
        Findings.map(
            "symbol",
            "workflow.forward",
            "arity",
            0,
            "kind",
            "sink",
            "channel",
            "release",
            "boundary",
            "yield",
            "args",
            Arrays.asList(0),
            "valuePath",
            Arrays.asList("content"),
            "requiresLabel",
            "model-output"));
    contracts.add(
        Findings.map(
            "symbol",
            "workflow.answer",
            "arity",
            0,
            "kind",
            "sink",
            "channel",
            "release",
            "boundary",
            "return",
            "args",
            Arrays.asList(0),
            "requiresLabel",
            "model-output"));
    return BusinessPolicy.parse(
        "bank-common", Json.COMPACT.toJson(Findings.map("version", 2, "contracts", contracts)));
  }

  private BusinessFlow.Expr expr(String kind, int line) {
    BusinessFlow.Expr e = new BusinessFlow.Expr(kind);
    e.path = "workflow.py";
    e.line = line;
    return e;
  }

  private BusinessFlow.Expr name(String value) {
    BusinessFlow.Expr e = expr("NAME", 1);
    e.name = value;
    return e;
  }

  private BusinessFlow.Expr literal(Object value) {
    BusinessFlow.Expr e = expr("LITERAL", 1);
    e.literal = value;
    return e;
  }

  private BusinessFlow.Expr call(String symbol, int line, BusinessFlow.Expr... args) {
    BusinessFlow.Expr e = expr("CALL", line);
    e.symbol = symbol;
    e.args.addAll(Arrays.asList(args));
    return e;
  }

  private BusinessFlow.Stmt stmt(String kind, int line, BusinessFlow.Expr e) {
    BusinessFlow.Stmt s = new BusinessFlow.Stmt(kind);
    s.path = "workflow.py";
    s.line = line;
    s.expr = e;
    return s;
  }

  private BusinessFlow.Stmt assign(String target, BusinessFlow.Expr e) {
    BusinessFlow.Stmt s = stmt("ASSIGN", e.line, e);
    s.target = target;
    return s;
  }

  private BusinessFlow.Stmt release(int line, String value) {
    return stmt("EXPR", line, call("edge.release", line, name(value)));
  }

  private BusinessFlow.Stmt check(String symbol, int line, String value) {
    return stmt("EXPR", line, call(symbol, line, name(value)));
  }

  private BusinessFlow.Stmt branch(BusinessFlow.Expr test, BusinessFlow.Stmt... body) {
    BusinessFlow.Stmt s = stmt("IF", test.line, test);
    s.body.addAll(Arrays.asList(body));
    return s;
  }

  private BusinessFlow.Stmt loop(BusinessFlow.Stmt... body) {
    BusinessFlow.Stmt s = stmt("ITERATE", 3, name("stream"));
    s.target = "chunk";
    s.body.addAll(Arrays.asList(body));
    return s;
  }

  private BusinessFlow.Stmt emit(int line, BusinessFlow.Expr value) {
    BusinessFlow.Expr map = expr("MAP", line);
    map.members.put("content", value);
    return stmt("YIELD", line, map);
  }

  private BusinessFlow.Program program(String symbol, BusinessFlow.Stmt... body) {
    BusinessFlow.Program p = new BusinessFlow.Program();
    BusinessFlow.Function f = new BusinessFlow.Function();
    f.path = "workflow.py";
    f.symbol = symbol;
    f.body.addAll(Arrays.asList(body));
    p.functions.add(f);
    return p;
  }

  private BusinessStreamTiming analyze(BusinessFlow.Stmt... body) throws Exception {
    return BusinessStreamTiming.analyze(program("workflow.forward", body), policy(), NEVER);
  }

  private BusinessFlow.Stmt source() {
    return assign("stream", call("edge.stream", 2));
  }

  private boolean contains(
      BusinessStreamTiming result, int line, int checkLine, String ordering, String binding) {
    for (Map<String, Object> item : result.sites)
      if (Integer.valueOf(line).equals(item.get("line"))
          && Integer.valueOf(checkLine).equals(item.get("checkLine"))
          && ordering.equals(item.get("ordering"))
          && binding.equals(item.get("valueBinding"))) return true;
    return false;
  }

  private void has(
      BusinessStreamTiming result, int line, int checkLine, String ordering, String binding) {
    assertTrue(result.sites.toString(), contains(result, line, checkLine, ordering, binding));
  }

  private void noAccepted(BusinessStreamTiming result) {
    for (Map<String, Object> item : result.sites)
      assertNotEquals(item.toString(), "ACCEPTED_CHECK_PRECEDES_RELEASE", item.get("ordering"));
  }

  @Test
  public void laterCandidateCheckDescribesOrderWithoutQualifyingSafety() throws Exception {
    BusinessStreamTiming r =
        analyze(source(), loop(emit(4, name("chunk"))), check("edge.candidate", 8, "chunk"));
    has(r, 4, 8, "RELEASE_PRECEDES_MAPPED_CHECK", "same");
    noAccepted(r);
    assertEquals("candidate", r.sites.get(0).get("assurance"));
  }

  @Test
  public void acceptedSameChunkCanDescribeFirstLocalRelease() throws Exception {
    BusinessStreamTiming r =
        analyze(
            source(), loop(branch(call("edge.check", 4, name("chunk")), emit(5, name("chunk")))));
    has(r, 5, 4, "ACCEPTED_CHECK_PRECEDES_RELEASE", "same");
    assertTrue(((List<?>) r.sites.get(0).get("limits")).contains("ZERO_OR_ONE_ITERATION_ONLY"));
  }

  @Test
  public void wholeStreamCheckDoesNotCheckFreshElement() throws Exception {
    BusinessStreamTiming r =
        analyze(
            source(), branch(call("edge.check", 3, name("stream")), loop(emit(5, name("chunk")))));
    has(r, 5, 3, "ORDER_UNRESOLVED", "different");
    noAccepted(r);
  }

  @Test
  public void ignoredBooleanIsNotBlocking() throws Exception {
    BusinessStreamTiming r =
        analyze(source(), check("edge.check", 3, "stream"), release(4, "stream"));
    has(r, 4, 3, "ORDER_UNRESOLVED", "same");
    noAccepted(r);
  }

  @Test
  public void candidateAndFailureOpenNeverQualifyAccepted() throws Exception {
    for (String c : Arrays.asList("edge.candidate", "edge.open")) {
      BusinessStreamTiming r =
          analyze(source(), branch(call(c, 3, name("stream")), release(4, "stream")));
      has(r, 4, 3, "ORDER_UNRESOLVED", "same");
      noAccepted(r);
    }
  }

  @Test
  public void candidateReceiverNeverQualifiesAccepted() throws Exception {
    BusinessFlow.Expr c = call("edge.check", 3, name("stream"));
    c.bindingUncertain = true;
    BusinessStreamTiming r = analyze(source(), branch(c, release(4, "stream")));
    noAccepted(r);
    assertEquals("candidate", r.sites.get(0).get("assurance"));
  }

  @Test
  public void normalReturnCheckCanQualifySameValue() throws Exception {
    has(
        analyze(source(), check("edge.normal", 3, "stream"), release(4, "stream")),
        4,
        3,
        "ACCEPTED_CHECK_PRECEDES_RELEASE",
        "same");
  }

  @Test
  public void decisionObjectRequiresExactMappedProjectionAndBranch() throws Exception {
    BusinessStreamTiming r =
        analyze(
            source(),
            assign("decision", call("edge.object", 3, name("stream"))),
            branch(call("edge.accepted", 4, name("decision")), release(5, "stream")));
    has(r, 5, 3, "ACCEPTED_CHECK_PRECEDES_RELEASE", "same");
    noAccepted(
        analyze(source(), branch(call("edge.object", 3, name("stream")), release(5, "stream"))));
  }

  @Test
  public void falseGuardBranchHasIndependentUnresolvedFact() throws Exception {
    BusinessFlow.Stmt condition =
        branch(call("edge.check", 3, name("stream")), release(4, "stream"));
    condition.otherwise.add(release(4, "stream"));
    BusinessStreamTiming r = analyze(source(), condition);
    has(r, 4, 3, "ACCEPTED_CHECK_PRECEDES_RELEASE", "same");
    has(r, 4, 3, "ORDER_UNRESOLVED", "same");
  }

  @Test
  public void firstReleaseDoesNotAcquireLaterChecks() throws Exception {
    BusinessStreamTiming r =
        analyze(
            source(),
            release(3, "stream"),
            branch(call("edge.check", 4, name("stream")), release(5, "stream")));
    has(r, 3, 4, "RELEASE_PRECEDES_MAPPED_CHECK", "same");
    noAccepted(r);
    for (Map<String, Object> item : r.sites) assertNotEquals(5, item.get("line"));
  }

  @Test
  public void executionOrderDoesNotUseLineNumbers() throws Exception {
    has(
        analyze(source(), release(9, "stream"), check("edge.check", 3, "stream")),
        9,
        3,
        "RELEASE_PRECEDES_MAPPED_CHECK",
        "same");
  }

  @Test
  public void zeroIterationCannotBorrowPerElementProof() throws Exception {
    BusinessFlow.Stmt l = loop(check("edge.normal", 4, "chunk"));
    BusinessStreamTiming r = analyze(source(), l, release(8, "stream"));
    noAccepted(r);
    has(r, 8, 0, "ORDER_UNRESOLVED", "unknown");
  }

  @Test
  public void returnStopsLaterCheckAndForElseRemainsReachable() throws Exception {
    BusinessFlow.Stmt l = loop(emit(4, name("chunk")), stmt("RETURN", 5, literal(null)));
    l.otherwise.add(check("edge.check", 7, "stream"));
    BusinessStreamTiming r = analyze(source(), l, check("edge.check", 8, "stream"));
    has(r, 4, 0, "ORDER_UNRESOLVED", "unknown");
    for (Map<String, Object> item : r.sites) assertEquals(0, item.get("checkLine"));
  }

  @Test
  public void exceptionsBeforeSuccessfulCheckDoNotInheritItsProof() throws Exception {
    BusinessFlow.Stmt t = stmt("TRY", 3, null);
    t.body.add(check("edge.normal", 4, "stream"));
    t.body.add(release(5, "stream"));
    t.handlers.add(Arrays.asList(release(8, "stream")));
    BusinessStreamTiming r = analyze(source(), t);
    has(r, 5, 4, "ACCEPTED_CHECK_PRECEDES_RELEASE", "same");
    has(r, 8, 0, "ORDER_UNRESOLVED", "unknown");
  }

  @Test
  public void finallyReleasePrecedesDeferredReturnBoundary() throws Exception {
    BusinessFlow.Stmt t = stmt("TRY", 3, null);
    t.body.add(stmt("RETURN", 4, name("stream")));
    t.finalizer.add(release(6, "stream"));
    t.finalizer.add(check("edge.check", 7, "stream"));
    BusinessStreamTiming r =
        BusinessStreamTiming.analyze(program("workflow.answer", source(), t), policy(), NEVER);
    has(r, 6, 7, "RELEASE_PRECEDES_MAPPED_CHECK", "same");
  }

  @Test
  public void handlerExceptionRunsInnerFinallyBeforeOuterAcceptedRelease() throws Exception {
    BusinessFlow.Stmt inner = stmt("TRY", 3, null);
    inner.body.add(stmt("THROW", 4, literal(null)));
    inner.handlers.add(Arrays.asList(stmt("EXPR", 5, call("edge.other", 5))));
    inner.finalizer.add(emit(6, name("stream")));
    BusinessFlow.Stmt outer = stmt("TRY", 2, null);
    outer.body.add(inner);
    outer.handlers.add(Arrays.asList(check("edge.normal", 8, "stream"), emit(9, name("stream"))));
    BusinessStreamTiming r = analyze(source(), outer);
    has(r, 6, 8, "RELEASE_PRECEDES_MAPPED_CHECK", "same");
    noAccepted(r);
    for (Map<String, Object> item : r.sites) assertNotEquals(9, item.get("line"));
  }

  @Test
  public void elseExceptionRunsInnerFinallyBeforeOuterRelease() throws Exception {
    BusinessFlow.Stmt inner = stmt("TRY", 3, null);
    inner.otherwise.add(stmt("EXPR", 5, call("edge.other", 5)));
    inner.finalizer.add(emit(6, name("stream")));
    BusinessFlow.Stmt outer = stmt("TRY", 2, null);
    outer.body.add(inner);
    outer.handlers.add(Arrays.asList(check("edge.normal", 8, "stream"), emit(9, name("stream"))));
    BusinessStreamTiming r = analyze(source(), outer);
    has(r, 6, 8, "RELEASE_PRECEDES_MAPPED_CHECK", "same");
    noAccepted(r);
    for (Map<String, Object> item : r.sites) assertNotEquals(9, item.get("line"));
  }

  @Test
  public void unknownConstructCannotAssertCallbackOrdering() throws Exception {
    BusinessFlow.Stmt opaque = stmt("UNKNOWN", 3, null);
    opaque.body.add(release(4, "stream"));
    opaque.body.add(check("edge.check", 5, "stream"));
    BusinessStreamTiming r = analyze(source(), opaque);
    noAccepted(r);
    has(r, 4, 5, "ORDER_UNRESOLVED", "unknown");
  }

  @Test
  public void unknownMutationInvalidatesBindingAndAcceptance() throws Exception {
    BusinessStreamTiming r =
        analyze(
            source(),
            check("edge.normal", 3, "stream"),
            stmt("EXPR", 4, call("unknown.mutate", 4, name("stream"))),
            release(5, "stream"));
    noAccepted(r);
    has(r, 5, 3, "ORDER_UNRESOLVED", "unknown");
  }

  @Test
  public void knownIrrelevantDiscriminatorSkipsReleaseButTransformedOneDoesNot() throws Exception {
    BusinessFlow.Stmt skipped =
        stmt("EXPR", 3, call("edge.dispatch", 3, name("stream"), literal("skip")));
    assertTrue(analyze(source(), skipped).sites.isEmpty());
    BusinessStreamTiming r =
        analyze(
            source(),
            check("edge.normal", 3, "stream"),
            stmt(
                "EXPR",
                4,
                call("edge.dispatch", 4, name("stream"), call("edge.mask", 4, literal("skip")))));
    has(r, 4, 3, "ORDER_UNRESOLVED", "same");
    noAccepted(r);
  }

  @Test
  public void mapProjectionAndPreservedAliasUseSameTrackedValue() throws Exception {
    BusinessStreamTiming r =
        analyze(
            source(),
            assign("alias", call("edge.keep", 3, name("stream"))),
            branch(call("edge.check", 4, name("stream")), emit(5, name("alias"))));
    has(r, 5, 4, "ACCEPTED_CHECK_PRECEDES_RELEASE", "same");
  }

  @Test
  public void unrelatedInputGuardAndModelReleaseHaveDifferentValues() throws Exception {
    BusinessStreamTiming r =
        analyze(
            source(),
            assign("input", call("edge.other", 3)),
            branch(call("edge.check", 4, name("input")), release(5, "stream")));
    noAccepted(r);
    has(r, 5, 4, "ORDER_UNRESOLVED", "different");
  }

  @Test
  public void fixedLiteralAndNonOutputSourceDoNotInventModelOutputRelease() throws Exception {
    assertTrue(analyze(emit(3, literal("fixed"))).sites.isEmpty());
    assertTrue(
        analyze(assign("stream", call("edge.other", 2)), release(4, "stream")).sites.isEmpty());
  }

  @Test
  public void generatorCreationDoesNotExecuteAnyOtherFunctionBody() throws Exception {
    BusinessFlow.Program p = program("caller.run", source());
    BusinessFlow.Function f = new BusinessFlow.Function();
    f.symbol = "not_mapped.generator";
    f.path = "hidden.py";
    f.body.add(stmt("YIELD", 30, literal("hidden")));
    p.functions.add(f);
    assertTrue(BusinessStreamTiming.analyze(p, policy(), NEVER).sites.isEmpty());
  }

  @Test
  public void shortCircuitExpressionCannotInventSuccessfulCheck() throws Exception {
    BusinessFlow.Expr and = expr("BINARY", 3);
    and.operator = "and";
    and.args.add(literal(false));
    and.args.add(call("edge.normal", 3, name("stream")));
    BusinessStreamTiming r = analyze(source(), stmt("EXPR", 3, and), release(4, "stream"));
    has(r, 4, 0, "ORDER_UNRESOLVED", "unknown");
    noAccepted(r);
  }

  @Test
  public void unknownShortCircuitExpressionDoesNotImplyDefiniteOrder() throws Exception {
    BusinessFlow.Expr and = expr("BINARY", 3);
    and.operator = "and";
    and.args.add(name("flag"));
    and.args.add(call("edge.release", 3, name("stream")));
    BusinessStreamTiming r =
        analyze(source(), stmt("EXPR", 3, and), check("edge.check", 4, "stream"));
    has(r, 3, 4, "ORDER_UNRESOLVED", "same");
  }

  @Test
  public void nestedUnknownExpressionDoesNotEstablishCallbackOrder() throws Exception {
    BusinessFlow.Expr wrapper = expr("UNKNOWN", 3);
    wrapper.args.add(call("edge.release", 3, name("stream")));
    wrapper.args.add(call("edge.check", 4, name("stream")));
    BusinessStreamTiming r = analyze(source(), stmt("EXPR", 3, wrapper));
    has(r, 3, 4, "ORDER_UNRESOLVED", "same");
  }

  @Test
  public void unknownSinkDiscriminatorCannotAssertDefiniteReleaseBeforeCheck() throws Exception {
    BusinessStreamTiming r =
        analyze(
            source(),
            stmt("EXPR", 3, call("edge.dispatch", 3, name("stream"), name("operation"))),
            check("edge.check", 4, "stream"));
    has(r, 3, 4, "ORDER_UNRESOLVED", "same");
  }

  @Test
  public void candidateSinkCannotAssertDefiniteReleaseBeforeCheck() throws Exception {
    for (boolean receiver : Arrays.asList(true, false)) {
      BusinessFlow.Expr sink =
          call(receiver ? "edge.release" : "edge.candidate_release", 3, name("stream"));
      sink.bindingUncertain = receiver;
      has(
          analyze(source(), stmt("EXPR", 3, sink), check("edge.check", 4, "stream")),
          3,
          4,
          "ORDER_UNRESOLVED",
          "same");
    }
  }

  @Test
  public void missingProjectedMemberDoesNotEstablishReleaseBoundary() throws Exception {
    has(
        analyze(source(), stmt("YIELD", 3, expr("MAP", 3)), check("edge.check", 4, "stream")),
        3,
        4,
        "ORDER_UNRESOLVED",
        "unknown");
  }

  @Test
  public void knownEventsAfterEarlierOpaqueComputationStillHaveRelativeOrder() throws Exception {
    BusinessFlow.Stmt opaque = stmt("UNKNOWN", 3, expr("UNKNOWN", 3));
    opaque.orderUncertain = false;
    BusinessStreamTiming r =
        analyze(source(), opaque, release(4, "stream"), check("edge.quality", 5, "stream"));
    has(r, 4, 5, "RELEASE_PRECEDES_MAPPED_CHECK", "unknown");
  }

  @Test
  public void unknownConstructBetweenEventsDoesNotEstablishRelativeOrder() throws Exception {
    BusinessStreamTiming r =
        analyze(
            source(),
            release(3, "stream"),
            stmt("UNKNOWN", 4, null),
            check("edge.check", 5, "stream"));
    has(r, 3, 5, "ORDER_UNRESOLVED", "unknown");
  }

  @Test
  public void executionUncertainFunctionNeverEstablishesSynchronousOrder() throws Exception {
    BusinessFlow.Program p =
        program(
            "workflow.forward", source(), release(3, "stream"), check("edge.quality", 4, "stream"));
    p.functions.get(0).executionUncertain = true;
    has(BusinessStreamTiming.analyze(p, policy(), NEVER), 3, 4, "ORDER_UNRESOLVED", "same");
  }

  @Test
  public void pythonAccumulatorBeforeTokenDoesNotHideLaterQualityCheckOrder() throws Exception {
    String code =
        "import edge\n"
            + "def forward():\n"
            + "    full = ''\n"
            + "    for chunk in edge.stream():\n"
            + "        full += chunk\n"
            + "        yield {'content': chunk}\n"
            + "    result = edge.quality(full)\n";
    BusinessPolicy policy = policy();
    BusinessFlow.Program p =
        BusinessPythonAnalysis.adapt(
            Arrays.asList(new SourceFile("workflow.py", code)), NEVER, policy);
    BusinessStreamTiming r = BusinessStreamTiming.analyze(p, policy, NEVER);
    has(r, 6, 7, "RELEASE_PRECEDES_MAPPED_CHECK", "checked-value-derived-from-release");
    noAccepted(r);
    assertEquals("candidate", r.sites.get(0).get("assurance"));
    assertEquals("open", r.sites.get(0).get("failureMode"));
  }

  @Test
  public void candidateBooleanComparisonCannotBecomeKnownSinkDiscriminator() throws Exception {
    BusinessFlow.Expr equality = expr("BINARY", 3);
    equality.operator = "==";
    equality.args.add(literal(true));
    equality.args.add(call("edge.candidate_keep", 3, literal(false)));
    BusinessStreamTiming r =
        analyze(
            source(),
            stmt("EXPR", 3, call("edge.bool_dispatch", 3, name("stream"), equality)),
            check("edge.check", 4, "stream"));
    has(r, 3, 4, "ORDER_UNRESOLVED", "same");
  }

  @Test
  public void candidateMapTransformCannotExposeOriginalMemberForReleaseBinding() throws Exception {
    BusinessFlow.Expr map = expr("MAP", 3);
    map.members.put("content", name("stream"));
    BusinessStreamTiming r =
        analyze(
            source(),
            check("edge.normal", 3, "stream"),
            stmt("YIELD", 4, call("edge.candidate_keep", 4, map)));
    has(r, 4, 3, "ORDER_UNRESOLVED", "unknown");
    noAccepted(r);
  }

  @Test
  public void asyncAndDecoratedPythonFunctionsRemainExecutionUncertain() throws Exception {
    for (String definition : Arrays.asList("async def forward():", "@wrapper\ndef forward():")) {
      String code =
          "import edge\n"
              + definition
              + "\n    stream = edge.stream()\n"
              + "    yield {'content': stream}\n    edge.quality(stream)\n";
      BusinessPolicy policy = policy();
      BusinessFlow.Program p =
          BusinessPythonAnalysis.adapt(
              Arrays.asList(new SourceFile("workflow.py", code)), NEVER, policy);
      BusinessStreamTiming r = BusinessStreamTiming.analyze(p, policy, NEVER);
      assertFalse(r.sites.isEmpty());
      for (Map<String, Object> item : r.sites)
        assertEquals("ORDER_UNRESOLVED", item.get("ordering"));
    }
  }

  @Test
  public void failedGuardReturnBranchAllowsOnlySuccessfulContinuation() throws Exception {
    BusinessFlow.Expr not = expr("UNARY", 3);
    not.operator = "not";
    not.args.add(call("edge.check", 3, name("stream")));
    BusinessStreamTiming r =
        analyze(source(), branch(not, stmt("RETURN", 4, literal(null))), release(5, "stream"));
    has(r, 5, 3, "ACCEPTED_CHECK_PRECEDES_RELEASE", "same");
  }

  @Test
  public void newSourceValueCannotReusePreviousValueProof() throws Exception {
    BusinessStreamTiming r =
        analyze(
            source(),
            check("edge.normal", 3, "stream"),
            assign("stream", call("edge.stream", 4)),
            release(5, "stream"));
    has(r, 5, 3, "ORDER_UNRESOLVED", "different");
    noAccepted(r);
  }

  @Test
  public void finallyThrowCancelsReturnBoundary() throws Exception {
    BusinessFlow.Stmt t = stmt("TRY", 3, null);
    t.body.add(stmt("RETURN", 4, name("stream")));
    t.finalizer.add(stmt("THROW", 5, literal(null)));
    assertTrue(
        BusinessStreamTiming.analyze(program("workflow.answer", source(), t), policy(), NEVER)
            .sites
            .isEmpty());
  }

  @Test
  public void twoLoopElementsDoNotShareAcceptedProof() throws Exception {
    BusinessFlow.Stmt first = loop(check("edge.normal", 4, "chunk"));
    BusinessFlow.Stmt second = loop(emit(6, name("chunk")));
    BusinessStreamTiming r = analyze(source(), first, second);
    noAccepted(r);
    has(r, 6, 4, "ORDER_UNRESOLVED", "different");
  }

  @Test
  public void truncatedSourceCannotProduceAcceptedOrder() throws Exception {
    BusinessFlow.Program p =
        program(
            "workflow.forward", source(), check("edge.normal", 3, "stream"), release(4, "stream"));
    p.incompletePaths.add("workflow.py");
    noAccepted(BusinessStreamTiming.analyze(p, policy(), NEVER));
  }

  @Test
  public void reportIsBoundedAndContainsOnlyApprovedFields() throws Exception {
    BusinessFlow.Program p = new BusinessFlow.Program();
    for (int i = 0; i < 150; i++)
      p.functions.add(
          program("workflow.forward", source(), release(100 + i, "stream")).functions.get(0));
    BusinessStreamTiming r = BusinessStreamTiming.analyze(p, policy(), NEVER);
    assertEquals(128, r.sites.size());
    assertTrue(r.truncated);
    for (Map<String, Object> item : r.sites) {
      assertEquals(9, item.size());
      assertFalse(item.toString().contains("edge.stream"));
      assertFalse(item.toString().contains("model-output"));
      assertTrue(item.get("limits") instanceof List);
    }
  }

  @Test
  public void excessPathsRetainRepresentativeFactsWithoutJoiningOtherPathChecks() throws Exception {
    BusinessFlow.Program p = program("workflow.forward", source());
    for (int i = 0; i < 9; i++)
      p.functions.get(0).body.add(branch(name("flag" + i), assign("value" + i, literal(i))));
    p.functions.get(0).body.add(release(20, "stream"));
    p.functions.get(0).body.add(check("edge.quality", 21, "stream"));
    BusinessStreamTiming r = BusinessStreamTiming.analyze(p, policy(), NEVER);
    assertTrue(r.truncated);
    has(r, 20, 21, "RELEASE_PRECEDES_MAPPED_CHECK", "same");
    noAccepted(r);
  }

  @Test
  public void cappedPathsRetainDistinctPendingReturnBoundariesWithoutBorrowingChecks()
      throws Exception {
    BusinessFlow.Stmt guarded = stmt("TRY", 3, null);
    for (int i = 0; i < 9; i++)
      guarded.body.add(branch(name("flag" + i), assign("value" + i, literal(i))));
    guarded.body.add(check("edge.normal", 15, "stream"));
    guarded.body.add(stmt("RETURN", 20, name("stream")));
    guarded.handlers.add(Arrays.asList(stmt("RETURN", 30, name("stream"))));
    guarded.handlers.add(Arrays.asList(stmt("RETURN", 40, name("stream"))));
    BusinessStreamTiming result =
        BusinessStreamTiming.analyze(
            program("workflow.answer", source(), guarded), policy(), NEVER);
    assertTrue(result.truncated);
    has(result, 20, 15, "ACCEPTED_CHECK_PRECEDES_RELEASE", "same");
    for (int line : Arrays.asList(30, 40)) {
      boolean found = false;
      for (Map<String, Object> site : result.sites)
        if (Integer.valueOf(line).equals(site.get("line"))) {
          found = true;
          assertNotEquals("ACCEPTED_CHECK_PRECEDES_RELEASE", site.get("ordering"));
        }
      assertTrue("Missing exception return at " + line + ": " + result.sites, found);
    }
  }

  private BusinessFlow.Function expensiveFunction(String symbol) {
    BusinessFlow.Function f = program(symbol).functions.get(0);
    BusinessFlow.Stmt computation = stmt("EXPR", 1, literal(true));
    for (int i = 0; i < 60000; i++) f.body.add(computation);
    return f;
  }

  @Test
  public void unrelatedPrecedingFunctionsCannotConsumeLaterTimingBudget() throws Exception {
    BusinessFlow.Program p =
        program(
            "workflow.forward",
            source(),
            release(337, "stream"),
            check("edge.quality", 346, "stream"));
    p.functions.add(0, expensiveFunction("unmapped.background"));
    BusinessStreamTiming r = BusinessStreamTiming.analyze(p, policy(), NEVER);
    has(r, 337, 346, "RELEASE_PRECEDES_MAPPED_CHECK", "same");
  }

  @Test
  public void relevantFunctionBudgetExhaustionDoesNotAbortLaterFunctions() throws Exception {
    BusinessFlow.Program p =
        program(
            "workflow.forward",
            source(),
            release(337, "stream"),
            check("edge.quality", 346, "stream"));
    BusinessFlow.Function expensive = expensiveFunction("workflow.answer");
    expensive.body.add(stmt("RETURN", 60001, call("edge.stream", 60001)));
    p.functions.add(0, expensive);
    BusinessStreamTiming r = BusinessStreamTiming.analyze(p, policy(), NEVER);
    assertTrue(r.truncated);
    has(r, 337, 346, "RELEASE_PRECEDES_MAPPED_CHECK", "same");
  }

  @Test
  public void precedingDepthLimitDoesNotAbortLaterFunctions() throws Exception {
    BusinessFlow.Stmt root = branch(name("flag")), parent = root;
    for (int i = 0; i < 70; i++) {
      BusinessFlow.Stmt child = branch(name("flag"));
      parent.body.add(child);
      parent = child;
    }
    parent.body.add(release(100, "stream"));
    BusinessFlow.Program p =
        program(
            "workflow.forward",
            source(),
            release(337, "stream"),
            check("edge.quality", 346, "stream"));
    p.functions.add(0, program("unmapped.nested", source(), root).functions.get(0));
    BusinessStreamTiming r = BusinessStreamTiming.analyze(p, policy(), NEVER);
    assertTrue(r.truncated);
    has(r, 337, 346, "RELEASE_PRECEDES_MAPPED_CHECK", "same");
  }

  @Test
  public void relevanceFilterRetainsEveryStatementAndExpressionContainer() throws Exception {
    List<BusinessFlow.Stmt> wrappers = new ArrayList<BusinessFlow.Stmt>();
    wrappers.add(branch(literal(true), release(6, "stream")));
    BusinessFlow.Stmt otherwise = branch(literal(false));
    otherwise.otherwise.add(release(6, "stream"));
    wrappers.add(otherwise);
    BusinessFlow.Stmt handler = stmt("TRY", 4, null);
    handler.body.add(stmt("THROW", 5, literal(null)));
    handler.handlers.add(Arrays.asList(release(6, "stream")));
    wrappers.add(handler);
    BusinessFlow.Stmt finalizer = stmt("TRY", 4, null);
    finalizer.finalizer.add(release(6, "stream"));
    wrappers.add(finalizer);
    BusinessFlow.Stmt body = stmt("TRY", 4, null);
    body.body.add(release(6, "stream"));
    wrappers.add(body);
    BusinessFlow.Expr args = call("unmapped.consume", 6, call("edge.release", 6, name("stream")));
    wrappers.add(stmt("EXPR", 6, args));
    BusinessFlow.Expr receiver = call("unmapped.consume", 6);
    receiver.receiver = call("edge.release", 6, name("stream"));
    wrappers.add(stmt("EXPR", 6, receiver));
    BusinessFlow.Expr map = expr("MAP", 6);
    map.members.put("nested", call("edge.release", 6, name("stream")));
    wrappers.add(stmt("EXPR", 6, map));
    for (BusinessFlow.Stmt wrapper : wrappers) {
      BusinessFlow.Program p =
          program("unmapped.entry", source(), wrapper, check("edge.quality", 7, "stream"));
      BusinessStreamTiming r = BusinessStreamTiming.analyze(p, policy(), NEVER);
      has(r, 6, 7, "RELEASE_PRECEDES_MAPPED_CHECK", "same");
    }
  }

  @Test
  public void relevanceTraversalLimitKeepsCandidateRatherThanSilentlySkippingIt() throws Exception {
    BusinessFlow.Program p =
        program(
            "unmapped.large", source(), release(3, "stream"), check("edge.quality", 4, "stream"));
    for (int i = 0; i < 10001; i++) p.functions.get(0).body.add(stmt("EXPR", i + 10, literal(i)));
    BusinessStreamTiming r = BusinessStreamTiming.analyze(p, policy(), NEVER);
    assertTrue(r.truncated);
    has(r, 3, 4, "RELEASE_PRECEDES_MAPPED_CHECK", "same");
  }

  @Test(expected = CancellationException.class)
  public void cancellationPropagates() throws Exception {
    BusinessStreamTiming.analyze(
        program("workflow.forward", source(), release(3, "stream")),
        policy(),
        new Cancel() {
          public void check() {
            throw new CancellationException();
          }
        });
  }
}
