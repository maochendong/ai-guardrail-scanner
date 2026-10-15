package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.util.*;
import org.junit.Test;

public class BusinessInterproceduralTest {
  private static final Cancel NONE =
      new Cancel() {
        public void check() {}
      };

  private BusinessAnalysis analyze(String source) throws Exception {
    return analyze(source, "");
  }

  private BusinessAnalysis analyze(String source, String uncertainFunction) throws Exception {
    List<Map<String, Object>> contracts = new ArrayList<Map<String, Object>>();
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
            "edge.Port#other",
            "arity",
            0,
            "kind",
            "source",
            "label",
            "trusted-identity"));
    contracts.add(
        Findings.map(
            "symbol",
            "edge.Port#untrusted",
            "arity",
            0,
            "kind",
            "source",
            "label",
            "untrusted-identity"));
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
            "mode",
            "normal-return",
            "failureMode",
            "closed"));
    contracts.add(
        Findings.map(
            "symbol",
            "edge.Port#access",
            "arity",
            2,
            "kind",
            "sink",
            "channel",
            "access",
            "identity",
            0,
            "args",
            Arrays.asList(1),
            "scope",
            "restricted"));
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
    BusinessPolicy policy =
        BusinessPolicy.parse(
            "bank-common", Json.COMPACT.toJson(Findings.map("version", 2, "contracts", contracts)));
    BusinessFlow.Program program =
        BusinessJavaAnalysis.adapt(
            Arrays.asList(
                new SourceFile("src/Example.java", "package sample;import edge.Port;" + source)),
            NONE,
            policy);
    for (BusinessFlow.Function function : program.functions)
      if (function.symbol.equals(uncertainFunction)) function.executionUncertain = true;
    return BusinessAnalysis.analyze(program, policy, NONE);
  }

  private Map<String, Object> finding(BusinessAnalysis analysis, String rule) {
    for (Map<String, Object> item : analysis.assessments)
      if (rule.equals(item.get("ruleId"))) return item;
    throw new AssertionError(rule);
  }

  private boolean siteDisposition(Map<String, Object> finding, String disposition) {
    for (Object item : (List<?>) finding.get("siteAssessments"))
      if (disposition.equals(((Map<?, ?>) item).get("disposition"))) return true;
    return false;
  }

  @Test
  public void exactReturnAliasRetainsTrustedIdentity() throws Exception {
    Map<String, Object> f =
        finding(
            analyze(
                "class Example {private static String relay(String id){return id;} void"
                    + " run(){String id=relay(Port.identity());String"
                    + " resource=\"resource\";Port.scope(id,resource);Port.access(id,resource);}}"),
            BusinessPolicy.IAM);
    assertEquals(f.toString(), "OBSERVED", f.get("disposition"));
  }

  @Test
  public void callerContextDoesNotReplaceIndependentEntry() throws Exception {
    Map<String, Object> f =
        finding(
            analyze(
                "class Example {private static void use(String id,String"
                    + " r){Port.scope(id,r);Port.access(id,r);} void"
                    + " run(){use(Port.identity(),\"resource\");}}"),
            BusinessPolicy.IAM);
    assertEquals(f.toString(), "UNKNOWN", f.get("disposition"));
    assertTrue(f.toString(), siteDisposition(f, "OBSERVED"));
    assertTrue(f.toString(), siteDisposition(f, "UNKNOWN"));
  }

  @Test
  public void differentSubjectsDoNotShareProofsOrCallState() throws Exception {
    Map<String, Object> f =
        finding(
            analyze(
                "class Example {private static void use(String checked,String actual,String"
                    + " r){Port.scope(checked,r);Port.access(actual,r);} void run(){String"
                    + " a=Port.identity();use(a,a,\"r\");use(a,Port.other(),\"r\");}}"),
            BusinessPolicy.IAM);
    assertEquals(f.toString(), "VIOLATED", f.get("disposition"));
    assertTrue(f.toString(), siteDisposition(f, "OBSERVED"));
  }

  @Test
  public void sameArityOverloadsHaveDifferentDefinitionIdentity() throws Exception {
    Map<String, Object> f =
        finding(
            analyze(
                "class Example {private static String relay(String id){return id;} private static"
                    + " String relay(int n){return Port.untrusted();} void run(){String"
                    + " id=Port.identity();String"
                    + " v=relay(id);Port.scope(v,\"r\");Port.access(v,\"r\");}}"),
            BusinessPolicy.IAM);
    assertEquals(f.toString(), "OBSERVED", f.get("disposition"));
  }

  @Test
  public void recursionAndVirtualDispatchRemainUnknown() throws Exception {
    for (String helper :
        Arrays.asList(
            "private static String relay(String id){return relay(id);}",
            "String relay(String id){return id;}")) {
      Map<String, Object> f =
          finding(
              analyze(
                  "class Example {"
                      + helper
                      + " void run(){String"
                      + " v=relay(Port.identity());Port.scope(v,\"r\");Port.access(v,\"r\");}}"),
              BusinessPolicy.IAM);
      assertEquals(f.toString(), "UNKNOWN", f.get("disposition"));
    }
  }

  @Test
  public void exceptionFallbackCannotBecomeTrustedReturn() throws Exception {
    Map<String, Object> f =
        finding(
            analyze(
                "class Example {private static String relay(){try{return"
                    + " Port.identity();}catch(Exception e){return Port.untrusted();}} void"
                    + " run(){String v=relay();Port.scope(v,\"r\");Port.access(v,\"r\");}}"),
            BusinessPolicy.IAM);
    assertFalse(f.toString(), "OBSERVED".equals(f.get("disposition")));
  }

  @Test
  public void allNormalPathsMustKeepTheGuardProof() throws Exception {
    Map<String, Object> good =
        finding(
            analyze(
                "class Example {private static void guard(Object v){if(!Port.check(v))throw new"
                    + " RuntimeException();} void run(){Object"
                    + " v=Port.make();guard(v);Port.release(v);}}"),
            BusinessPolicy.GUARD);
    assertEquals(good.toString(), "OBSERVED", good.get("disposition"));
    Map<String, Object> bad =
        finding(
            analyze(
                "class Example {private static void guard(Object v,boolean"
                    + " skip){if(skip)return;if(!Port.check(v))throw new RuntimeException();} void"
                    + " run(boolean skip){Object v=Port.make();guard(v,skip);Port.release(v);}}"),
            BusinessPolicy.GUARD);
    assertFalse(bad.toString(), "OBSERVED".equals(bad.get("disposition")));
  }

  @Test
  public void finallyAndAlwaysThrowDoNotPermitNormalContinuation() throws Exception {
    Map<String, Object> f =
        finding(
            analyze(
                "class Example {private static String relay(String id){try{return"
                    + " id;}finally{return Port.untrusted();}} void run(){String"
                    + " v=relay(Port.identity());Port.scope(v,\"r\");Port.access(v,\"r\");}}"),
            BusinessPolicy.IAM);
    assertFalse(f.toString(), "OBSERVED".equals(f.get("disposition")));
    Map<String, Object> stopped =
        finding(
            analyze(
                "class Example {private static void stop(){throw new RuntimeException();} void"
                    + " run(){Object v=Port.make();stop();Port.release(v);}}"),
            BusinessPolicy.GUARD);
    assertFalse(stopped.toString(), siteDisposition(stopped, "VIOLATED"));
  }

  @Test
  public void calleeMutationInvalidatesCallerProofAndReturn() throws Exception {
    Map<String, Object> f =
        finding(
            analyze(
                "class Example {private static Object change(Object v){Port.mutate(v);return v;}"
                    + " void run(){Object"
                    + " v=Port.make();if(Port.check(v)){change(v);Port.release(v);}}}"),
            BusinessPolicy.GUARD);
    assertEquals(f.toString(), "UNKNOWN", f.get("disposition"));
  }

  @Test
  public void separateGuardedReturnsCannotBorrowOneBranchProof() throws Exception {
    Map<String, Object> f =
        finding(
            analyze(
                "class Example {private static Object choose(boolean b){Object a=Port.make();Object"
                    + " c=Port.make();if(b){if(!Port.check(a))throw new RuntimeException();return"
                    + " a;}if(!Port.check(c))throw new RuntimeException();return c;} void"
                    + " run(boolean b){Port.release(choose(b));}}"),
            BusinessPolicy.GUARD);
    assertEquals(f.toString(), "UNKNOWN", f.get("disposition"));
  }

  @Test
  public void callerCatchSeesExceptionBeforeCalleeControlExists() throws Exception {
    Map<String, Object> f =
        finding(
            analyze(
                "class Example {private static void guard(Object v){if(!Port.check(v))throw new"
                    + " RuntimeException();} void run(){Object"
                    + " v=Port.make();try{guard(v);}catch(Exception e){Port.release(v);}}}"),
            BusinessPolicy.GUARD);
    assertEquals(f.toString(), "VIOLATED", f.get("disposition"));
  }

  @Test
  public void returnedDecisionIsConsumedByTheCaller() throws Exception {
    Map<String, Object> f =
        finding(
            analyze(
                "class Example {private static boolean allow(Object v){return Port.check(v);} void"
                    + " run(){Object v=Port.make();if(allow(v))Port.release(v);}}"),
            BusinessPolicy.GUARD);
    assertEquals(f.toString(), "OBSERVED", f.get("disposition"));
  }

  @Test
  public void explicitVirtualReceiverRemainsCandidate() throws Exception {
    Map<String, Object> f =
        finding(
            analyze(
                "class Example {String relay(String id){return id;} void run(Example"
                    + " injected){String"
                    + " v=injected.relay(Port.identity());Port.scope(v,\"r\");Port.access(v,\"r\");}}"),
            BusinessPolicy.IAM);
    assertEquals(f.toString(), "UNKNOWN", f.get("disposition"));
    assertTrue(f.toString(), f.get("callContextSites").toString().contains("binding=candidate"));
    assertFalse(f.toString(), f.get("callContextSites").toString().contains("sample.Example"));
  }

  @Test
  public void ambiguousSameArityOverloadDoesNotSelectAnImplementation() throws Exception {
    Map<String, Object> f =
        finding(
            analyze(
                "class Example {private static String relay(String id){return Port.identity();}"
                    + " private static String relay(Integer id){return Port.untrusted();} void"
                    + " run(){String v=relay(null);Port.scope(v,\"r\");Port.access(v,\"r\");}}"),
            BusinessPolicy.IAM);
    assertEquals(f.toString(), "UNKNOWN", f.get("disposition"));
  }

  @Test
  public void callerVariableNamesDoNotAliasCalleeLocalAssignments() throws Exception {
    Map<String, Object> f =
        finding(
            analyze(
                "class Example {private static void helper(String id){id=Port.untrusted();} void"
                    + " run(){String"
                    + " id=Port.identity();helper(id);Port.scope(id,\"r\");Port.access(id,\"r\");}}"),
            BusinessPolicy.IAM);
    assertEquals(f.toString(), "OBSERVED", f.get("disposition"));
  }

  @Test
  public void alwaysThrowInNestedArgumentDoesNotEvaluateLaterArgumentsOrRelease() throws Exception {
    Map<String, Object> f =
        finding(
            analyze(
                "class Example {private static Object stop(){throw new RuntimeException();} void"
                    + " run(){Port.unknown(stop(),Port.release(Port.make()));}}"),
            BusinessPolicy.GUARD);
    assertFalse(f.toString(), siteDisposition(f, "VIOLATED"));
  }

  @Test
  public void callDepthLimitRetainsAnExplicitUnknownReason() throws Exception {
    StringBuilder source = new StringBuilder("class Example {");
    for (int i = 0; i < 12; i++)
      source
          .append("private static String h")
          .append(i)
          .append("(String id){return ")
          .append(i == 11 ? "id" : "h" + (i + 1) + "(id)")
          .append(";}");
    source.append(
        "void run(){String id=h0(Port.identity());Port.scope(id,\"r\");Port.access(id,\"r\");}}");
    Map<String, Object> f = finding(analyze(source.toString()), BusinessPolicy.IAM);
    assertEquals(f.toString(), "UNKNOWN", f.get("disposition"));
    assertTrue(f.toString(), f.toString().contains("INTERPROCEDURAL_FLOW_BOUNDED"));
  }

  @Test
  public void cancellationIsNotConvertedToAnUnknownReturn() throws Exception {
    BusinessFlow.Program p = new BusinessFlow.Program();
    BusinessFlow.Function entry = new BusinessFlow.Function();
    entry.id = "entry";
    for (int i = 0; i < 200; i++) {
      BusinessFlow.Stmt s = new BusinessFlow.Stmt("EXPR");
      s.expr = new BusinessFlow.Expr("CALL");
      s.expr.localTargetId = "helper";
      entry.body.add(s);
    }
    BusinessFlow.Function helper = new BusinessFlow.Function();
    helper.id = "helper";
    BusinessFlow.Stmt s = new BusinessFlow.Stmt("EXPR");
    s.expr = new BusinessFlow.Expr("CALL");
    s.expr.symbol = "edge.Port#identity";
    helper.body.add(s);
    p.functions.add(entry);
    p.functions.add(helper);
    BusinessPolicy policy =
        BusinessPolicy.parse(
            "bank-common",
            Json.COMPACT.toJson(
                Findings.map(
                    "version",
                    2,
                    "contracts",
                    Arrays.asList(
                        Findings.map(
                            "symbol",
                            "edge.Port#identity",
                            "arity",
                            0,
                            "kind",
                            "source",
                            "label",
                            "trusted-identity")))));
    final java.util.concurrent.CancellationException stop =
        new java.util.concurrent.CancellationException("stop");
    try {
      BusinessAnalysis.analyze(
          p,
          policy,
          new Cancel() {
            int checks;

            public void check() {
              if (++checks == 100) throw stop;
            }
          });
      fail("Cancellation must escape source-call interpretation");
    } catch (java.util.concurrent.CancellationException actual) {
      assertSame(stop, actual);
    }
  }

  @Test
  public void oppositeDecisionReturnsDoNotMergeIntoAnAcceptedGuard() throws Exception {
    for (String arms :
        Arrays.asList("if(invert)return !ok;return ok;", "if(invert)return ok;return !ok;")) {
      Map<String, Object> f =
          finding(
              analyze(
                  "class Example {private static boolean allow(Object v,boolean invert){boolean"
                      + " ok=Port.check(v);"
                      + arms
                      + "} void run(boolean"
                      + " b){Object v=Port.make();if(allow(v,b))Port.release(v);}}"),
              BusinessPolicy.GUARD);
      assertEquals(f.toString(), "UNKNOWN", f.get("disposition"));
    }
  }

  @Test
  public void alwaysThrowDoesNotBecomeReturnSinkGuardOrCondition() throws Exception {
    for (String body :
        Arrays.asList(
            "return stop();",
            "Port.release(stop());",
            "if(Port.check(stop()))Port.release(Port.make());",
            "if(stop())Port.release(Port.make());")) {
      Map<String, Object> f =
          finding(
              analyze(
                  "class Example {private static Object stop(){throw new RuntimeException();}"
                      + " Object run(){"
                      + body
                      + "}}"),
              BusinessPolicy.GUARD);
      assertFalse(f.toString(), siteDisposition(f, "VIOLATED"));
      assertFalse(f.toString(), siteDisposition(f, "OBSERVED"));
    }
  }

  @Test
  public void finallyCallDoesNotInheritTheCallersPendingReturn() throws Exception {
    List<Map<String, Object>> contracts =
        Arrays.asList(
            Findings.map(
                "symbol",
                "edge.identity",
                "arity",
                0,
                "kind",
                "source",
                "label",
                "trusted-identity"),
            Findings.map(
                "symbol",
                "edge.scope",
                "arity",
                2,
                "kind",
                "check",
                "control",
                "scope",
                "args",
                Arrays.asList(0, 1),
                "mode",
                "normal-return",
                "failureMode",
                "closed"),
            Findings.map(
                "symbol",
                "edge.access",
                "arity",
                2,
                "kind",
                "sink",
                "channel",
                "access",
                "identity",
                0,
                "args",
                Arrays.asList(1),
                "scope",
                "restricted"));
    BusinessPolicy policy =
        BusinessPolicy.parse(
            "bank-common", Json.COMPACT.toJson(Findings.map("version", 2, "contracts", contracts)));
    for (String noop : Arrays.asList("    pass\n", "    return\n")) {
      String source =
          "import edge\ndef noop():\n"
              + noop
              + "def entry():\n"
              + "    try:\n"
              + "        return edge.identity()\n"
              + "    finally:\n"
              + "        v = noop()\n"
              + "        edge.scope(v, 'r')\n"
              + "        edge.access(v, 'r')\n";
      BusinessFlow.Program program =
          BusinessPythonAnalysis.adapt(
              Arrays.asList(new SourceFile("flow.py", source)), NONE, policy);
      Map<String, Object> f =
          finding(BusinessAnalysis.analyze(program, policy, NONE), BusinessPolicy.IAM);
      assertFalse(f.toString(), siteDisposition(f, "OBSERVED"));
    }
  }

  @Test
  public void uncertainExecutionCannotTransferAnOtherwiseExactIdentity() throws Exception {
    Map<String, Object> f =
        finding(
            analyze(
                "class Example {private static String pass(String id){return id;} void run(){String"
                    + " id=pass(Port.identity());Port.scope(id,\"r\");Port.access(id,\"r\");}}",
                "sample.Example#pass"),
            BusinessPolicy.IAM);
    assertEquals(f.toString(), "UNKNOWN", f.get("disposition"));
    assertFalse(f.toString(), siteDisposition(f, "OBSERVED"));
    assertTrue(f.toString(), f.get("callContextSites").toString().contains("candidate"));
  }

  @Test
  public void boundedCallChainRetainsTheRulesOfItsUnvisitedTarget() throws Exception {
    StringBuilder source = new StringBuilder("class Example {");
    for (int i = 0; i < 12; i++)
      source
          .append("private static void h")
          .append(i)
          .append("(){")
          .append(
              i == 11
                  ? "Object v=Port.make();if(Port.check(v))Port.release(v);"
                  : "h" + (i + 1) + "();")
          .append("}");
    source.append("void run(){h0();}}");
    Map<String, Object> f = finding(analyze(source.toString()), BusinessPolicy.GUARD);
    assertEquals(f.toString(), "UNKNOWN", f.get("disposition"));
    assertTrue(f.toString(), f.toString().contains("BANK_ANALYSIS_BOUNDED"));
  }

  @Test
  public void exceptionFromHandlerStillRunsItsFinallyBeforeOuterCatch() throws Exception {
    Map<String, Object> f =
        finding(
            analyze(
                "class Example {private static String source(){return Port.other();} void"
                    + " run(){Object v=Port.make();if(Port.check(v)){try{try{throw"
                    + " null;}catch(Exception e){source();}finally{Port.mutate(v);}}catch(Exception"
                    + " e){Port.release(v);}}}}"),
            BusinessPolicy.GUARD);
    assertFalse(f.toString(), siteDisposition(f, "OBSERVED"));
  }

  @Test
  public void exceptionFromPythonElseStillRunsItsFinallyBeforeOuterCatch() throws Exception {
    BusinessPolicy policy =
        BusinessPolicy.parse(
            "bank-common",
            Json.COMPACT.toJson(
                Findings.map(
                    "version",
                    2,
                    "contracts",
                    Arrays.asList(
                        Findings.map(
                            "symbol",
                            "edge.make",
                            "arity",
                            0,
                            "kind",
                            "source",
                            "label",
                            "model-output"),
                        Findings.map(
                            "symbol",
                            "edge.other",
                            "arity",
                            0,
                            "kind",
                            "source",
                            "label",
                            "trusted-identity"),
                        Findings.map(
                            "symbol",
                            "edge.check",
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
                            "closed"),
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
                            "model-output")))));
    String source =
        "import edge\n"
            + "def source():\n"
            + "    return edge.other()\n"
            + "def run():\n"
            + "    v = edge.make()\n"
            + "    if edge.check(v):\n"
            + "        try:\n"
            + "            try:\n"
            + "                pass\n"
            + "            except Exception:\n"
            + "                pass\n"
            + "            else:\n"
            + "                source()\n"
            + "            finally:\n"
            + "                edge.mutate(v)\n"
            + "        except Exception:\n"
            + "            edge.release(v)\n";
    BusinessFlow.Program program =
        BusinessPythonAnalysis.adapt(
            Arrays.asList(new SourceFile("flow.py", source)), NONE, policy);
    Map<String, Object> f =
        finding(BusinessAnalysis.analyze(program, policy, NONE), BusinessPolicy.GUARD);
    assertFalse(f.toString(), siteDisposition(f, "OBSERVED"));
  }

  @Test
  public void unrelatedSharedCallGraphIsVisitedInBoundedWork() throws Exception {
    BusinessFlow.Program program = new BusinessFlow.Program();
    for (int i = 0; i < 26; i++) {
      BusinessFlow.Function function = new BusinessFlow.Function();
      function.id = "h" + i;
      if (i < 25)
        for (int call = 0; call < 2; call++) {
          BusinessFlow.Stmt statement = new BusinessFlow.Stmt("EXPR");
          statement.expr = new BusinessFlow.Expr("CALL");
          statement.expr.localTargetId = "h" + (i + 1);
          function.body.add(statement);
        }
      program.functions.add(function);
    }
    BusinessPolicy policy =
        BusinessPolicy.parse(
            "bank-common",
            Json.COMPACT.toJson(
                Findings.map(
                    "version",
                    2,
                    "contracts",
                    Arrays.asList(
                        Findings.map(
                            "symbol",
                            "edge.Port#identity",
                            "arity",
                            0,
                            "kind",
                            "source",
                            "label",
                            "trusted-identity")))));
    BusinessAnalysis.analyze(
        program,
        policy,
        new Cancel() {
          int checks;

          public void check() {
            if (++checks > 5000)
              throw new AssertionError("Repeated traversal of a shared source-call graph");
          }
        });
  }

  @Test
  public void expensiveSourceCallsCannotConsumeLaterIndependentEntryBudget() throws Exception {
    StringBuilder source = new StringBuilder("class Example {void expensive(){");
    for (int i = 0; i < 1000; i++) source.append("helper();");
    source.append("} private static int helper(){Port.identity();int n=0;");
    for (int i = 0; i < 300; i++) source.append("n=1;");
    source.append(
        "return n;} void safe(){Object v=Port.make();if(Port.check(v))Port.release(v);}}");
    Map<String, Object> f = finding(analyze(source.toString()), BusinessPolicy.GUARD);
    assertTrue(f.toString(), siteDisposition(f, "OBSERVED"));
    assertEquals(f.toString(), "OBSERVED", f.get("disposition"));
  }

  @Test
  public void boundedCalleeCannotReturnPartialProofAndItsExceptionRemainsReachable()
      throws Exception {
    StringBuilder source =
        new StringBuilder(
            "class Example {void run(){Object v=Port.make();try{outer(v);}catch(Exception"
                + " e){Port.release(v);}} private static void outer(Object v){if(Port.check(v)){");
    for (int i = 0; i < 1000; i++) source.append("helper();");
    source.append("}} private static int helper(){int n=0;");
    for (int i = 0; i < 300; i++) source.append("n=1;");
    source.append("return n;}}");
    Map<String, Object> f = finding(analyze(source.toString()), BusinessPolicy.GUARD);
    assertFalse(f.toString(), siteDisposition(f, "OBSERVED"));
    assertTrue(f.toString(), siteDisposition(f, "UNKNOWN"));
    assertTrue(f.toString(), f.toString().contains("INTERPROCEDURAL_FLOW_BOUNDED"));
  }
}
