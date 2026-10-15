package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.Test;

/** Focused regressions for evaluation order, branch reachability and value-bound proofs. */
public class BusinessFlowEdgeTest {
  private static final Cancel NONE =
      new Cancel() {
        public void check() {}
      };

  private BusinessPolicy policy() throws Exception {
    List<Map<String, Object>> contracts = new ArrayList<Map<String, Object>>();
    contracts.add(
        Findings.map(
            "symbol", "edge.Port#data", "arity", 0, "kind", "source", "label", "sensitive"));
    contracts.add(
        Findings.map(
            "symbol",
            "edge.Port#identity",
            "arity",
            0,
            "kind",
            "source",
            "label",
            "trusted-identity"));
    contracts.add(
        Findings.map(
            "symbol",
            "edge.Port#mask",
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
            true));
    contracts.add(
        Findings.map(
            "symbol",
            "edge.Port#scope",
            "arity",
            2,
            "kind",
            "check",
            "control",
            "scope",
            "args",
            Arrays.asList(0, 1),
            "accept",
            true));
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
            Arrays.asList(0)));
    contracts.add(
        Findings.map(
            "symbol",
            "edge.Port#read",
            "arity",
            2,
            "kind",
            "sink",
            "channel",
            "access",
            "identity",
            0,
            "args",
            Arrays.asList(1)));
    for (int arity : Arrays.asList(1, 2))
      contracts.add(
          Findings.map(
              "symbol",
              "edge.Port#send",
              "arity",
              arity,
              "kind",
              "sink",
              "channel",
              "egress",
              "args",
              Arrays.asList(0)));
    return BusinessPolicy.parse(
        "bank-common", Json.COMPACT.toJson(Findings.map("version", 1, "contracts", contracts)));
  }

  private Map<String, Object> result(String body, String rule) throws Exception {
    String source = "import edge.Port; class Example {void run(boolean flag){" + body + "}}";
    BusinessFlow.Program program =
        BusinessJavaAnalysis.adapt(Arrays.asList(new SourceFile("Example.java", source)), NONE);
    assertTrue(program.diagnostics.toString(), program.diagnostics.isEmpty());
    for (Map<String, Object> item : BusinessAnalysis.analyze(program, policy(), NONE).assessments)
      if (rule.equals(item.get("ruleId"))) return item;
    throw new AssertionError("Missing rule " + rule);
  }

  private void disposition(String expected, String body, String rule) throws Exception {
    Map<String, Object> item = result(body, rule);
    assertEquals(item.toString(), expected, item.get("disposition"));
  }

  @Test
  public void staticQualifierDoesNotEraseKnownGuard() throws Exception {
    disposition(
        "OBSERVED",
        "Object v=Port.data();if(!Port.check(v))return;Port.release(v);",
        BusinessPolicy.GUARD);
    disposition("VIOLATED", "Object v=Port.data();Port.release(v);", BusinessPolicy.GUARD);
  }

  @Test
  public void nonThrowingReturnTryDoesNotInventAnUnprotectedFinallyPath() throws Exception {
    disposition(
        "OBSERVED",
        "Object v=Port.data();if(!Port.check(v))return;" + "try{return;}finally{Port.release(v);}",
        BusinessPolicy.GUARD);
  }

  @Test
  public void unreachableCatchHasNoSinkPath() throws Exception {
    Map<String, Object> item =
        result(
            "Object v=Port.data();try{return;}" + "catch(RuntimeException error){Port.release(v);}",
            BusinessPolicy.GUARD);
    assertEquals("UNKNOWN", item.get("disposition"));
    assertEquals(0, item.get("mappedPathOutcomes"));
  }

  @Test
  public void unreachableTryCallMustNotCreateADefiniteViolation() throws Exception {
    Map<String, Object> item =
        result(
            "Object v=Port.data();if(!Port.check(v))return;"
                + "try{if(false){Port.other();}}finally{Port.release(v);}",
            BusinessPolicy.GUARD);
    assertFalse(item.toString(), "VIOLATED".equals(item.get("disposition")));
  }

  @Test
  public void booleanDecisionAliasPreservesNeutralShortCircuitOperand() throws Exception {
    for (String expression : Arrays.asList("Port.check(v)&&true", "Port.check(v)||false"))
      disposition(
          "OBSERVED",
          "Object v=Port.data();boolean accepted=" + expression + ";if(accepted)Port.release(v);",
          BusinessPolicy.GUARD);
  }

  @Test
  public void constantShortCircuitDoesNotEvaluateUnreachableSink() throws Exception {
    for (String expression : Arrays.asList("false&&Port.release(v)", "true||Port.release(v)")) {
      Map<String, Object> item =
          result("Object v=Port.data();boolean result=" + expression + ";", BusinessPolicy.GUARD);
      assertEquals("UNKNOWN", item.get("disposition"));
      assertEquals(0, item.get("mappedPathOutcomes"));
    }
  }

  @Test
  public void identicalConstantResourceArgumentsUseTheSameValueIdentity() throws Exception {
    disposition(
        "OBSERVED",
        "Object user=Port.identity();"
            + "if(!Port.scope(user,\"resource-a\"))return;Port.read(user,\"resource-a\");",
        BusinessPolicy.IAM);
  }

  @Test
  public void recomputedExpressionIsUnknownRatherThanAnInventedMissingCheck() throws Exception {
    disposition(
        "UNKNOWN",
        "String value=\"data\";if(!Port.check(value+\"!\"))return;" + "Port.release(value+\"!\");",
        BusinessPolicy.GUARD);
  }

  @Test
  public void mutationInLaterArgumentInvalidatesEarlierEvaluatedValue() throws Exception {
    disposition(
        "UNKNOWN", "Object v=Port.mask(Port.data());Port.send(v,Port.modify(v));", BusinessPolicy.DATA);
  }

  @Test
  public void unknownReceiverMethodInvalidatesTheReceiverValue() throws Exception {
    disposition(
        "UNKNOWN", "Object v=Port.mask(Port.data());v.modify();Port.send(v);", BusinessPolicy.DATA);
  }

  @Test
  public void unrelatedObjectInitializationDoesNotPolluteExistingLocalProof() throws Exception {
    disposition(
        "OBSERVED",
        "Object v=Port.mask(Port.data());Object unused=new Object();" + "Port.send(v);",
        BusinessPolicy.DATA);
  }

  @Test
  public void staleBooleanDecisionCannotRestoreProofAfterUnknownCall() throws Exception {
    disposition(
        "UNKNOWN",
        "Object v=Port.data();boolean accepted=Port.check(v);Port.other();"
            + "if(accepted)Port.release(v);",
        BusinessPolicy.GUARD);
  }

  @Test
  public void contradictoryBranchConditionsDoNotInventAnUnprotectedPath() throws Exception {
    disposition(
        "OBSERVED",
        "Object v=Port.data();if(flag){if(!Port.check(v))return;}"
            + "if(!flag)return;Port.release(v);",
        BusinessPolicy.GUARD);
  }
}
