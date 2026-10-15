package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import org.junit.Test;

/** Structural relevance must be bounded independently from execution of a mapped path. */
public class BankRelevanceScopeTest {
  private static final Cancel NONE =
      new Cancel() {
        public void check() {}
      };

  private BankPolicy policy() throws Exception {
    List<Map<String, Object>> contracts = new ArrayList<Map<String, Object>>();
    contracts.add(
        Findings.map(
            "symbol", "scope.Port#output", "arity", 0, "kind", "source", "label", "model-output"));
    contracts.add(
        Findings.map(
            "symbol",
            "scope.Port#identity",
            "arity",
            0,
            "kind",
            "source",
            "label",
            "trusted-identity"));
    for (String control : Arrays.asList("guard", "scope", "doc-acl")) {
      int arity = "guard".equals(control) ? 1 : 2;
      contracts.add(
          Findings.map(
              "symbol",
              "scope.Port#" + ("doc-acl".equals(control) ? "document" : control),
              "arity",
              arity,
              "kind",
              "check",
              "control",
              control,
              "args",
              arity == 1 ? Arrays.asList(0) : Arrays.asList(0, 1),
              "accept",
              true,
              "failureMode",
              "closed"));
    }
    contracts.add(
        Findings.map(
            "symbol",
            "scope.Port#release",
            "arity",
            1,
            "kind",
            "sink",
            "channel",
            "release",
            "args",
            Arrays.asList(0)));
    for (String channel : Arrays.asList("access", "retrieve"))
      contracts.add(
          Findings.map(
              "symbol",
              "scope.Port#" + channel,
              "arity",
              2,
              "kind",
              "sink",
              "channel",
              channel,
              "identity",
              0,
              "args",
              Arrays.asList(1),
              "scope",
              "restricted"));
    return BankPolicy.parse(
        "bank-all", Json.COMPACT.toJson(Findings.map("version", 2, "contracts", contracts)));
  }

  private BankFlow.Program protectedProgram(BankPolicy policy) {
    String source =
        "package sample;import scope.Port;class Protected {void guarded(){Object"
            + " value=Port.output();if(Port.guard(value))Port.release(value);}void"
            + " isolated(){Object user=Port.identity();Object"
            + " resource=\"account\";if(Port.scope(user,resource))Port.access(user,resource);}void"
            + " documents(){Object user=Port.identity();Object"
            + " resource=\"document\";if(Port.scope(user,resource)&&Port.document(user,resource))Port.retrieve(user,resource);}"
            + "}";
    return BankJavaAnalysis.adapt(
        Arrays.asList(new SourceFile("Protected.java", source)), NONE, policy);
  }

  private BankFlow.Function deepHelper(int depth, boolean mappedRelease) {
    BankFlow.Expr value = new BankFlow.Expr("LITERAL");
    value.literal = Boolean.TRUE;
    if (mappedRelease) {
      BankFlow.Expr sink = new BankFlow.Expr("CALL");
      sink.symbol = "scope.Port#release";
      sink.path = "Deep.java";
      sink.line = 100;
      sink.args.add(value);
      sink.argNames.add("");
      value = sink;
    }
    for (int i = 0; i < depth; i++) {
      BankFlow.Expr parent = new BankFlow.Expr("UNARY");
      parent.operator = "!";
      parent.args.add(value);
      value = parent;
    }
    BankFlow.Stmt statement = new BankFlow.Stmt("EXPR");
    statement.expr = value;
    BankFlow.Function helper = new BankFlow.Function();
    helper.path = "Deep.java";
    helper.symbol = "sample.Deep#helper";
    helper.body.add(statement);
    return helper;
  }

  private Map<String, Object> finding(BankAnalysis analysis, String rule) {
    for (Map<String, Object> finding : analysis.assessments)
      if (rule.equals(finding.get("ruleId"))) return finding;
    throw new AssertionError("Missing assessment " + rule);
  }

  private void disposition(BankAnalysis analysis, String rule, String expected) {
    Map<String, Object> finding = finding(analysis, rule);
    assertEquals(finding.toString(), expected, finding.get("disposition"));
  }

  @SuppressWarnings("unchecked")
  private boolean bounded(BankAnalysis analysis, String rule) {
    Object reasons = finding(analysis, rule).get("unknownReasons");
    if (reasons == null) return false;
    for (Map<String, Object> reason : (List<Map<String, Object>>) reasons)
      if ("BANK_ANALYSIS_BOUNDED".equals(reason.get("code"))) return true;
    return false;
  }

  @Test
  public void deepUnmappedHelperCannotDowngradeIndependentProtectedRules() throws Exception {
    BankPolicy policy = policy();
    BankFlow.Program program = protectedProgram(policy);
    program.functions.add(0, deepHelper(90, false));
    BankAnalysis analysis = BankAnalysis.analyze(program, policy, NONE);
    for (String rule : Arrays.asList(BankPolicy.GUARD, BankPolicy.IAM, BankPolicy.ACL)) {
      disposition(analysis, rule, "OBSERVED");
      assertFalse(bounded(analysis, rule));
    }
    assertEquals(3, analysis.mappingCoverage.get("analyzedFunctions"));
    for (Map<String, Object> diagnostic : analysis.diagnostics)
      assertNotEquals(diagnostic.toString(), "BANK_FLOW_LIMIT", diagnostic.get("code"));
  }

  @Test
  public void deepMappedSinkLimitsOnlyItsRelatedRule() throws Exception {
    BankPolicy policy = policy();
    BankFlow.Program program = protectedProgram(policy);
    program.functions.add(0, deepHelper(90, true));
    BankAnalysis analysis = BankAnalysis.analyze(program, policy, NONE);
    disposition(analysis, BankPolicy.GUARD, "UNKNOWN");
    assertTrue(bounded(analysis, BankPolicy.GUARD));
    for (String rule : Arrays.asList(BankPolicy.IAM, BankPolicy.ACL)) {
      disposition(analysis, rule, "OBSERVED");
      assertFalse(bounded(analysis, rule));
    }
    assertEquals(4, analysis.mappingCoverage.get("analyzedFunctions"));
  }

  @Test
  public void exhaustedStructuralInspectionRemainsConservative() throws Exception {
    BankPolicy policy = policy();
    BankFlow.Program program = protectedProgram(policy);
    program.functions.add(0, deepHelper(280, false));
    BankAnalysis analysis = BankAnalysis.analyze(program, policy, NONE);
    for (String rule : Arrays.asList(BankPolicy.GUARD, BankPolicy.IAM, BankPolicy.ACL)) {
      disposition(analysis, rule, "UNKNOWN");
      assertTrue(bounded(analysis, rule));
    }
  }

  @Test
  public void cancellationDuringStructuralInspectionPropagatesUnchanged() throws Exception {
    BankFlow.Program program = new BankFlow.Program();
    program.functions.add(deepHelper(220, false));
    final CancellationException cancellation = new CancellationException("cancel relevance scan");
    Cancel cancel =
        new Cancel() {
          int checks;

          public void check() {
            if (++checks == 100) throw cancellation;
          }
        };
    try {
      BankAnalysis.analyze(program, policy(), cancel);
      fail("A deep structural precheck must remain cancellable even when no API is mapped");
    } catch (CancellationException actual) {
      assertSame(cancellation, actual);
    }
  }
}
