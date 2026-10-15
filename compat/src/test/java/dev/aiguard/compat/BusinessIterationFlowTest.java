package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import org.junit.Test;

/** Independent regressions for bounded iteration, causal site detail and conditional boundaries. */
public class BusinessIterationFlowTest {
  private static final Cancel NEVER =
      new Cancel() {
        public void check() {}
      };

  private BusinessPolicy policy() throws Exception {
    List<Map<String, Object>> contracts = new ArrayList<Map<String, Object>>();
    contracts.add(Findings.map("symbol", "edge.stream", "arity", 0, "kind", "source",
        "label", "model-output"));
    contracts.add(Findings.map("symbol", "edge.candidate", "arity", 0, "kind", "source",
        "label", "model-output", "assurance", "candidate"));
    contracts.add(Findings.map("symbol", "edge.alter", "arity", 1, "kind", "transform",
        "control", "preserve", "arg", 0, "assurance", "candidate"));
    contracts.add(Findings.map("symbol", "edge.mask", "arity", 1, "kind", "transform",
        "control", "redaction", "arg", 0));
    contracts.add(Findings.map("symbol", "edge.keep", "arity", 1, "kind", "transform",
        "control", "preserve", "arg", 0));
    contracts.add(Findings.map("symbol", "edge.check", "arity", 1, "kind", "check",
        "control", "guard", "args", Arrays.asList(0), "accept", true, "failureMode", "closed"));
    contracts.add(Findings.map("symbol", "edge.candidate_check", "arity", 1, "kind", "check",
        "control", "guard", "args", Arrays.asList(0), "accept", true, "failureMode", "closed",
        "assurance", "candidate"));
    contracts.add(Findings.map("symbol", "edge.release", "arity", 1, "kind", "sink",
        "channel", "release", "args", Arrays.asList(0), "requiresLabel", "model-output"));
    contracts.add(Findings.map("symbol", "edge.dispatch", "arity", 2, "kind", "sink",
        "channel", "release", "args", Arrays.asList(0), "requiresLabel", "model-output",
        "when", Findings.map("arg", 1, "equals", "emit")));
    contracts.add(Findings.map("symbol", "edge.bool_dispatch", "arity", 2, "kind", "sink",
        "channel", "release", "args", Arrays.asList(0), "requiresLabel", "model-output",
        "when", Findings.map("arg", 1, "equals", false)));
    contracts.add(Findings.map("symbol", "workflow.forward", "arity", 1, "kind", "sink",
        "channel", "release", "boundary", "yield", "args", Arrays.asList(0),
        "valuePath", Arrays.asList("content"), "requiresLabel", "model-output"));
    return BusinessPolicy.parse("bank-common",
        Json.COMPACT.toJson(Findings.map("version", 2, "contracts", contracts)));
  }

  private String source(String body) {
    return "import edge\ndef forward(flag):\n" + body;
  }

  private BusinessFlow.Program program(String body, BusinessPolicy policy) {
    return BusinessPythonAnalysis.adapt(
        Arrays.asList(new SourceFile("workflow.py", source(body))), NEVER, policy);
  }

  private Map<String, Object> guard(String body) throws Exception {
    BusinessPolicy policy = policy();
    BusinessAnalysis analysis = BusinessAnalysis.analyze(program(body, policy), policy, NEVER);
    for (Map<String, Object> finding : analysis.assessments)
      if (BusinessPolicy.GUARD.equals(finding.get("ruleId"))) return finding;
    throw new AssertionError("Missing Guard assessment");
  }

  @SuppressWarnings("unchecked")
  private List<Map<String, Object>> items(Map<String, Object> map, String key) {
    return (List<Map<String, Object>>) map.get(key);
  }

  private boolean reason(Map<String, Object> map, String code) {
    for (Map<String, Object> reason : items(map, "unknownReasons"))
      if (code.equals(reason.get("code"))) return true;
    return false;
  }

  private boolean evidence(Map<String, Object> map, String role, int line) {
    for (Map<String, Object> evidence : items(map, "evidence"))
      if (role.equals(evidence.get("role")) && Integer.valueOf(line).equals(evidence.get("line")))
        return true;
    return false;
  }

  private Map<String, Object> site(Map<String, Object> finding, int line) {
    for (Map<String, Object> item : items(finding, "siteAssessments"))
      if (Integer.valueOf(line).equals(item.get("line"))) return item;
    throw new AssertionError("Missing site at " + line + ": " + finding);
  }

  private void unknown(Map<String, Object> finding) {
    assertEquals(finding.toString(), "UNKNOWN", finding.get("disposition"));
    for (Map<String, Object> item : items(finding, "siteAssessments"))
      assertNotEquals(item.toString(), "OBSERVED", item.get("disposition"));
  }

  @Test
  public void mappedStreamElementRetainsSourceAndBoundedUnknownReason() throws Exception {
    Map<String, Object> finding = guard(
        "    for part in edge.stream():\n        yield {'content': part}\n");
    unknown(finding);
    assertEquals(1, finding.get("mappedPathOutcomes"));
    assertTrue(evidence(site(finding, 4), "source", 3));
    assertTrue(reason(site(finding, 4), "ITERATION_FLOW_BOUNDED"));
    assertTrue(reason(site(finding, 4), "STREAM_RELEASE_WITHOUT_BOUND_GUARD"));
  }

  @Test
  public void guardOnWholeStreamCannotBecomeAChunkProof() throws Exception {
    Map<String, Object> finding = guard(
        "    stream = edge.stream()\n"
            + "    if edge.check(stream):\n"
            + "        for part in stream:\n"
            + "            yield {'content': part}\n");
    unknown(finding);
    assertTrue(reason(site(finding, 6), "STREAM_RELEASE_WITHOUT_BOUND_GUARD"));
    assertFalse(evidence(site(finding, 6), "control", 4));
  }

  @Test
  public void perChunkGuardRecordsEvidenceButDoesNotCertifyAllIterations() throws Exception {
    Map<String, Object> finding = guard(
        "    for part in edge.stream():\n"
            + "        if edge.check(part):\n"
            + "            yield {'content': part}\n");
    unknown(finding);
    assertTrue(evidence(site(finding, 5), "control", 4));
    assertTrue(reason(site(finding, 5), "ITERATION_FLOW_BOUNDED"));
    assertFalse(reason(site(finding, 5), "STREAM_RELEASE_WITHOUT_BOUND_GUARD"));
  }

  @Test
  public void unknownAugmentedAssignmentDoesNotDisappearBeforeYield() throws Exception {
    Map<String, Object> finding = guard(
        "    full = ''\n"
            + "    for part in edge.stream():\n"
            + "        full += part\n"
            + "        yield {'content': part}\n");
    unknown(finding);
    assertTrue(reason(site(finding, 6), "LOCAL_FLOW_UNRESOLVED"));
    assertTrue(evidence(site(finding, 6), "source", 4));
  }

  @Test
  public void laterGuardCannotRetroactivelyProtectAnEarlierYield() throws Exception {
    Map<String, Object> finding = guard(
        "    for part in edge.stream():\n"
            + "        yield {'content': part}\n"
            + "        if edge.check(part):\n"
            + "            yield {'content': part}\n");
    unknown(finding);
    assertTrue(reason(site(finding, 4), "STREAM_RELEASE_WITHOUT_BOUND_GUARD"));
    assertFalse(evidence(site(finding, 4), "control", 5));
    assertTrue(evidence(site(finding, 6), "control", 5));
    assertFalse(reason(site(finding, 6), "STREAM_RELEASE_WITHOUT_BOUND_GUARD"));
  }

  @Test
  public void candidateStreamPreservesUnresolvedElementAndSourceReasons() throws Exception {
    Map<String, Object> finding = guard(
        "    for part in edge.candidate():\n        yield {'content': part}\n");
    unknown(finding);
    assertTrue(reason(site(finding, 4), "SOURCE_NOT_QUALIFIED"));
    assertTrue(reason(site(finding, 4), "STREAM_ELEMENT_UNRESOLVED"));
  }

  @Test
  public void unclassifiedIterableParameterHasAnExplicitUnresolvedElementReason() throws Exception {
    Map<String, Object> finding = guard(
        "    for part in flag:\n        yield {'content': part}\n");
    unknown(finding);
    assertTrue(reason(site(finding, 4), "STREAM_ELEMENT_UNRESOLVED"));
  }

  @Test
  public void loopExitCannotReuseTheRepresentativeElementProof() throws Exception {
    Map<String, Object> finding = guard(
        "    part = edge.stream()\n"
            + "    for part in edge.stream():\n"
            + "        if not edge.check(part):\n"
            + "            return\n"
            + "    edge.release(part)\n");
    unknown(finding);
    assertTrue(reason(site(finding, 7), "ITERATION_FLOW_BOUNDED"));
  }

  @Test
  public void zeroIterationPreservesPreLoopValueAndExecutesElse() throws Exception {
    Map<String, Object> finding = guard(
        "    part = edge.candidate()\n"
            + "    for part in edge.stream():\n"
            + "        return\n"
            + "    else:\n"
            + "        yield {'content': part}\n");
    unknown(finding);
    assertEquals(1, finding.get("mappedPathOutcomes"));
    assertTrue(evidence(site(finding, 7), "source", 3));
    assertFalse(evidence(site(finding, 7), "source", 4));
    assertTrue(reason(site(finding, 7), "SOURCE_NOT_QUALIFIED"));
  }

  @Test
  public void returnStopsTheRepresentativeBodyBeforeLaterYield() throws Exception {
    Map<String, Object> finding = guard(
        "    for part in edge.stream():\n"
            + "        return\n"
            + "        yield {'content': part}\n"
            + "    yield {'content': edge.stream()}\n");
    unknown(finding);
    assertEquals(1, finding.get("mappedPathOutcomes"));
    assertEquals(6, items(finding, "siteAssessments").get(0).get("line"));
  }

  @Test
  public void throwStopsBodyButRetainsReachableHandler() throws Exception {
    Map<String, Object> finding = guard(
        "    try:\n"
            + "        for part in edge.stream():\n"
            + "            raise\n"
            + "            yield {'content': part}\n"
            + "    except:\n"
            + "        yield {'content': edge.stream()}\n");
    // The source call can throw before iteration, and the body can throw after entering it.
    assertEquals(2, finding.get("mappedPathOutcomes"));
    for (Map<String, Object> item : items(finding, "siteAssessments"))
      assertEquals(8, item.get("line"));
    assertFalse(evidence(finding, "sink", 6));
  }

  @Test
  public void cancellationDuringInterpretationIsPropagated() throws Exception {
    BusinessPolicy policy = policy();
    BusinessFlow.Program program = program(
        "    for part in edge.stream():\n        yield {'content': part}\n", policy);
    final int[] checks = {0};
    try {
      BusinessAnalysis.analyze(program, policy, new Cancel() {
        public void check() {
          if (++checks[0] == 5) throw new CancellationException("cancel iteration");
        }
      });
      fail("Cancellation must escape analysis");
    } catch (CancellationException expected) {
      assertEquals("cancel iteration", expected.getMessage());
    }
  }

  @Test
  public void sameSiteUnknownPathsMergeTheirDistinctCausalReasons() throws Exception {
    Map<String, Object> finding = guard(
        "    if flag:\n"
            + "        value = edge.candidate()\n"
            + "    else:\n"
            + "        value = edge.alter(edge.stream())\n"
            + "    yield {'content': value}\n");
    unknown(finding);
    assertEquals(1, finding.get("mappedPathOutcomes"));
    assertEquals(1, items(finding, "siteAssessments").size());
    assertTrue(reason(site(finding, 7), "SOURCE_NOT_QUALIFIED"));
    assertTrue(reason(site(finding, 7), "TRANSFORM_NOT_QUALIFIED"));
    assertTrue(evidence(site(finding, 7), "source", 4));
    assertTrue(evidence(site(finding, 7), "source", 6));
  }

  @Test
  public void sameSiteKeepsObservedAndUnknownPathsSeparate() throws Exception {
    Map<String, Object> finding = guard(
        "    value = edge.stream()\n"
            + "    if flag:\n"
            + "        if not edge.check(value):\n            return\n"
            + "    else:\n"
            + "        if not edge.candidate_check(value):\n            return\n"
            + "    edge.release(value)\n");
    assertEquals("UNKNOWN", finding.get("disposition"));
    assertEquals(2, finding.get("mappedPathOutcomes"));
    assertEquals(2, items(finding, "siteAssessments").size());
    List<String> dispositions = new ArrayList<String>();
    for (Map<String, Object> item : items(finding, "siteAssessments"))
      dispositions.add(String.valueOf(item.get("disposition")));
    assertTrue(dispositions.contains("OBSERVED"));
    assertTrue(dispositions.contains("UNKNOWN"));
  }

  @Test
  public void knownNonMatchingSinkDiscriminatorIsSkipped() throws Exception {
    Map<String, Object> finding = guard(
        "    value = edge.stream()\n    edge.dispatch(value, 'buffer')\n");
    assertEquals(0, finding.get("mappedPathOutcomes"));
    assertTrue(items(finding, "siteAssessments").isEmpty());
  }

  @Test
  public void matchingSinkDiscriminatorKeepsTheUnguardedBoundary() throws Exception {
    Map<String, Object> finding = guard(
        "    value = edge.stream()\n    edge.dispatch(value, 'emit')\n");
    assertEquals("VIOLATED", finding.get("disposition"));
    assertEquals(1, finding.get("mappedPathOutcomes"));
  }

  @Test
  public void unknownSinkDiscriminatorIsNotSilentlySkipped() throws Exception {
    Map<String, Object> finding = guard(
        "    value = edge.stream()\n    edge.dispatch(value, flag)\n");
    unknown(finding);
    assertTrue(reason(site(finding, 4), "SINK_CONDITION_UNRESOLVED"));
  }

  @Test
  public void completingSiteDetailsKeepsPrimaryCategoryWithoutInventingFallbackReason()
      throws Exception {
    Map<String, Object> finding = guard(
        "    for part in edge.stream():\n        yield {'content': part}\n");
    Unknowns.complete(Arrays.asList(finding), new ArrayList<Map<String, Object>>());
    Map<String, Object> detail = site(finding, 4);
    assertEquals(detail.toString(), "UNSUPPORTED", detail.get("unknownCategory"));
    assertFalse(reason(detail, "CONTROL_SEMANTICS_UNVERIFIED"));
  }

  @Test
  public void aggregateViolationDoesNotEraseUnknownAtTheSameSite() throws Exception {
    Map<String, Object> finding = guard(
        "    if flag:\n"
            + "        value = edge.candidate()\n"
            + "    else:\n"
            + "        value = edge.stream()\n"
            + "    edge.release(value)\n");
    assertEquals("VIOLATED", finding.get("disposition"));
    assertEquals(2, finding.get("mappedPathOutcomes"));
    Unknowns.complete(Arrays.asList(finding), new ArrayList<Map<String, Object>>());
    boolean unknownRetained = false, violationRetained = false;
    for (Map<String, Object> detail : items(finding, "siteAssessments")) {
      if ("UNKNOWN".equals(detail.get("disposition"))) {
        unknownRetained = true;
        assertTrue(reason(detail, "SOURCE_NOT_QUALIFIED"));
        assertEquals("INSUFFICIENT_EVIDENCE", detail.get("unknownCategory"));
      } else if ("VIOLATED".equals(detail.get("disposition"))) violationRetained = true;
    }
    assertTrue(unknownRetained);
    assertTrue(violationRetained);
  }

  @Test
  public void invalidatedDiscriminatorCannotUseItsOldConstantToSkipBoundary() throws Exception {
    Map<String, Object> finding = guard(
        "    mode = 'buffer'\n"
            + "    mutate(mode)\n"
            + "    edge.dispatch(edge.stream(), mode)\n");
    unknown(finding);
    assertEquals(1, finding.get("mappedPathOutcomes"));
    assertTrue(reason(site(finding, 5), "SINK_CONDITION_UNRESOLVED"));
  }

  @Test
  public void booleanDiscriminatorUsesEvaluatedValueRatherThanCopiedLiteral() throws Exception {
    for (String expression : Arrays.asList("not True", "True == False")) {
      Map<String, Object> finding = guard(
          "    value = edge.stream()\n    edge.bool_dispatch(value, " + expression + ")\n");
      assertEquals(expression + ": " + finding, "VIOLATED", finding.get("disposition"));
      assertEquals(1, finding.get("mappedPathOutcomes"));
    }
    for (String expression : Arrays.asList("not False", "False == False")) {
      Map<String, Object> finding = guard(
          "    value = edge.stream()\n    edge.bool_dispatch(value, " + expression + ")\n");
      assertEquals(expression + ": " + finding, 0, finding.get("mappedPathOutcomes"));
    }
  }

  @Test
  public void unresolvedTruthConversionCannotReuseTheOperandLiteralToSkipBoundary()
      throws Exception {
    for (String expression : Arrays.asList("not 1", "not 'text'", "1 == False", "None == False")) {
      Map<String, Object> finding = guard(
          "    value = edge.stream()\n    edge.bool_dispatch(value, " + expression + ")\n");
      assertEquals(expression + ": " + finding, 1, finding.get("mappedPathOutcomes"));
      assertNotEquals(expression + ": " + finding, "OBSERVED", finding.get("disposition"));
    }
  }

  @Test
  public void exceptionHandlerDoesNotInheritAStreamElementMarkerFromTheLoopState()
      throws Exception {
    for (String handlerValue : Arrays.asList("'fixed error'", "edge.stream()")) {
      Map<String, Object> finding = guard(
          "    try:\n"
              + "        for part in edge.stream():\n"
              + "            yield {'content': part}\n"
              + "            raise\n"
              + "    except:\n"
              + "        yield {'content': " + handlerValue + "}\n");
      assertTrue(reason(site(finding, 5), "STREAM_RELEASE_WITHOUT_BOUND_GUARD"));
      boolean handlerLocated = false;
      for (Map<String, Object> detail : items(finding, "siteAssessments")) {
        if (!Integer.valueOf(8).equals(detail.get("line"))) continue;
        handlerLocated = true;
        assertFalse(detail.toString(), reason(detail, "STREAM_RELEASE_WITHOUT_BOUND_GUARD"));
      }
      // A constant fallback has no model-output label; a separately generated fallback does.
      assertEquals("edge.stream()".equals(handlerValue), handlerLocated);
    }
  }

  @Test
  public void independentControlReviewDoesNotCreateSinkOutcomesOrChangeDisposition()
      throws Exception {
    Map<String, Object> controlOnly = guard(
        "    value = edge.stream()\n    edge.candidate_check(value)\n");
    assertEquals("UNKNOWN", controlOnly.get("disposition"));
    assertEquals(0, controlOnly.get("mappedPathOutcomes"));
    assertTrue(items(controlOnly, "siteAssessments").isEmpty());
    assertEquals(1, items(controlOnly, "controlReviewSites").size());

    Map<String, Object> withViolation = guard(
        "    value = edge.stream()\n"
            + "    edge.release(value)\n"
            + "    edge.candidate_check(value)\n");
    assertEquals("VIOLATED", withViolation.get("disposition"));
    assertEquals(1, withViolation.get("mappedPathOutcomes"));
    assertEquals(1, items(withViolation, "siteAssessments").size());
    assertEquals(1, items(withViolation, "controlReviewSites").size());
  }

  @Test
  public void redactedDiscriminatorDoesNotTurnMixedBoundaryCoverageIntoObserved()
      throws Exception {
    Map<String, Object> finding = guard(
        "    value = edge.stream()\n"
            + "    if edge.check(value):\n"
            + "        edge.dispatch(value, 'emit')\n"
            + "    mode = edge.mask('buffer')\n"
            + "    edge.dispatch(edge.stream(), mode)\n");
    assertEquals("UNKNOWN", finding.get("disposition"));
    assertEquals(2, finding.get("mappedPathOutcomes"));
    assertEquals("OBSERVED", site(finding, 5).get("disposition"));
    assertEquals("UNKNOWN", site(finding, 7).get("disposition"));
    assertTrue(reason(site(finding, 7), "SINK_CONDITION_UNRESOLVED"));
  }

  @Test
  public void redactionDoesNotRetainEitherBooleanDiscriminatorConstant() throws Exception {
    for (String literal : Arrays.asList("True", "False")) {
      Map<String, Object> finding = guard(
          "    mode = edge.mask(" + literal + ")\n"
              + "    edge.bool_dispatch(edge.stream(), mode)\n");
      unknown(finding);
      assertEquals(1, finding.get("mappedPathOutcomes"));
      assertTrue(reason(site(finding, 4), "SINK_CONDITION_UNRESOLVED"));
    }
  }

  @Test
  public void redactedMapCannotExposeItsOriginalMemberAsAConstantDiscriminator()
      throws Exception {
    Map<String, Object> finding = guard(
        "    event = edge.mask({'kind': 'buffer'})\n"
            + "    edge.dispatch(edge.stream(), event['kind'])\n");
    unknown(finding);
    assertEquals(1, finding.get("mappedPathOutcomes"));
    assertTrue(reason(site(finding, 4), "SINK_CONDITION_UNRESOLVED"));
  }

  @Test
  public void explicitPreserveKeepsScalarAndMemberDiscriminatorValues() throws Exception {
    for (String expression : Arrays.asList(
        "edge.keep('buffer')", "edge.keep({'kind': 'buffer'})['kind']")) {
      Map<String, Object> finding = guard(
          "    mode = " + expression + "\n    edge.dispatch(edge.stream(), mode)\n");
      assertEquals(expression + ": " + finding, 0, finding.get("mappedPathOutcomes"));
    }
    for (String expression : Arrays.asList(
        "edge.keep('emit')", "edge.keep({'kind': 'emit'})['kind']")) {
      Map<String, Object> finding = guard(
          "    mode = " + expression + "\n    edge.dispatch(edge.stream(), mode)\n");
      assertEquals(expression + ": " + finding, "VIOLATED", finding.get("disposition"));
      assertEquals(1, finding.get("mappedPathOutcomes"));
    }
    assertEquals(0, guard("    edge.bool_dispatch(edge.stream(), edge.keep(True))\n")
        .get("mappedPathOutcomes"));
    assertEquals("VIOLATED", guard("    edge.bool_dispatch(edge.stream(), edge.keep(False))\n")
        .get("disposition"));
  }
}
