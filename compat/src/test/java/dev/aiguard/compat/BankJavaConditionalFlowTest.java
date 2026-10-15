package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.Test;

public class BankJavaConditionalFlowTest {
  private static final Cancel NONE =
      new Cancel() {
        public void check() {}
      };

  private BankAnalysis analyze(String source) throws Exception {
    List<Map<String, Object>> contracts = new ArrayList<Map<String, Object>>();
    contracts.add(
        Findings.map(
            "symbol", "edge.Port#make", "arity", 0, "kind", "source", "label", "model-output"));
    contracts.add(
        Findings.map(
            "symbol",
            "edge.Port#check",
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
            "closed"));
    contracts.add(
        Findings.map(
            "symbol",
            "edge.Port#release",
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
            "sample.Example#answer",
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
    contracts.add(
        Findings.map(
            "symbol",
            "sample.Example#virtualOutput",
            "arity",
            0,
            "kind",
            "source",
            "label",
            "model-output"));
    BankPolicy policy =
        BankPolicy.parse(
            "bank-common", Json.COMPACT.toJson(Findings.map("version", 2, "contracts", contracts)));
    BankFlow.Program program =
        BankJavaAnalysis.adapt(
            Arrays.asList(
                new SourceFile("src/Example.java", "package sample;import edge.Port;" + source)),
            NONE,
            policy);
    return BankAnalysis.analyze(program, policy, NONE);
  }

  private Map<String, Object> guard(BankAnalysis analysis) {
    for (Map<String, Object> finding : analysis.assessments)
      if (BankPolicy.GUARD.equals(finding.get("ruleId"))) return finding;
    throw new AssertionError("Missing Guard assessment");
  }

  private void disposition(String expected, String source) throws Exception {
    Map<String, Object> finding = guard(analyze(source));
    assertEquals(finding.toString(), expected, finding.get("disposition"));
  }

  @Test
  public void conditionalInitializerPreservesTheCheckedBranch() throws Exception {
    disposition(
        "OBSERVED",
        "class Example {void f(){Object v=Port.make();Object"
            + " output=Port.check(v)?v:\"blocked\";Port.release(output);}}");
  }

  @Test
  public void implicitVirtualCallRetainsCandidateMappingWithoutEstablishingTrust()
      throws Exception {
    BankAnalysis analysis =
        analyze(
            "class Example {Object virtualOutput(){return null;}void f(){Object"
                + " v=virtualOutput();if(Port.check(v))Port.release(v);}}");
    assertEquals("UNKNOWN", guard(analysis).get("disposition"));
    assertTrue(
        analysis.mappingCoverage.toString(),
        ((Number) analysis.mappingCoverage.get("candidateCallSites")).intValue() > 0);
    assertTrue(
        guard(analysis).toString(),
        guard(analysis).toString().contains("RECEIVER_BINDING_UNRESOLVED"));
  }

  @Test
  public void conditionalAssignmentAndReturnKeepTheirSelectedValue() throws Exception {
    disposition(
        "OBSERVED",
        "class Example {void f(){Object v=Port.make();Object"
            + " output;output=(Port.check(v)?v:\"blocked\");Port.release(output);}}");
    disposition(
        "OBSERVED",
        "class Example {Object answer(){Object v=Port.make();return"
            + " Port.check(v)?v:\"blocked\";}}");
  }

  @Test
  public void nestedArmsAndShortCircuitChecksDoNotExecuteUnselectedSinks() throws Exception {
    disposition(
        "OBSERVED",
        "class Example {void f(){Object v=Port.make();Object"
            + " output=Port.check(v)&&true?(true?v:Port.release(Port.make())):\"blocked\";Port.release(output);}}");
    disposition(
        "OBSERVED",
        "class Example {void f(){Object v=Port.make();Object"
            + " output=false&&Port.check(Port.make())?Port.release(Port.make()):(Port.check(v)?v:\"blocked\");Port.release(output);}}");
  }

  @Test
  public void uncheckedSelectedValueStillViolates() throws Exception {
    disposition(
        "VIOLATED",
        "class Example {void f(){Object v=Port.make();Object"
            + " output=Port.check(v)?Port.make():\"blocked\";Port.release(output);}}");
    disposition(
        "VIOLATED",
        "class Example {Object answer(){Object v=Port.make();return"
            + " Port.check(v)?v:Port.make();}}");
  }

  @Test
  public void conditionalInsideCallArgumentsRemainsUnknownWithoutReordering() throws Exception {
    disposition(
        "UNKNOWN",
        "class Example {void f(){Object"
            + " v=Port.make();Port.release(Port.check(v)?v:\"blocked\");}}");
  }

  @Test
  public void fixedLocalDispatchDoesNotAcquireCandidateUncertainty() throws Exception {
    disposition(
        "OBSERVED",
        "class Example {private Object virtualOutput(){return null;}void f(){Object"
            + " v=virtualOutput();if(Port.check(v))Port.release(v);}}");
    disposition(
        "OBSERVED",
        "final class Example {Object virtualOutput(){return null;}void f(){Object"
            + " v=virtualOutput();if(Port.check(v))Port.release(v);}}");
  }

  @Test
  public void ambiguousImplicitOverridesDoNotSelectOneContract() throws Exception {
    BankAnalysis analysis =
        analyze(
            "class Example {Object virtualOutput(){return null;}void f(){Object"
                + " v=virtualOutput();if(Port.check(v))Port.release(v);}}class Child extends"
                + " Example {Object virtualOutput(){return null;}}");
    assertEquals("UNKNOWN", guard(analysis).get("disposition"));
    assertEquals(0, ((Number) analysis.mappingCoverage.get("candidateCallSites")).intValue());
  }
}
