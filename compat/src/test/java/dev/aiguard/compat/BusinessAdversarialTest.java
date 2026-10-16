package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.Test;

/** Actual syntax adapters feed the shared interpreter; synthetic APIs have no security keywords. */
public class BusinessAdversarialTest {
  private static final Cancel NEVER =
      new Cancel() {
        public void check() {}
      };

  private BusinessPolicy policy(boolean java, boolean accepted) throws Exception {
    List<Map<String, Object>> contracts = new ArrayList<Map<String, Object>>();
    String prefix = java ? "rivet.Port#" : "rivet.";
    String[] labels = {
      "sensitive",
      "trusted-identity",
      "untrusted-identity",
      "model-output",
      "knowledge",
      "recommendation",
      "tool-input"
    };
    for (int i = 0; i < labels.length; i++)
      contracts.add(
          Findings.map(
              "symbol", prefix + "s" + (i + 1), "arity", 0, "kind", "source", "label", labels[i]));
    contracts.add(
        Findings.map(
            "symbol",
            prefix + "r1",
            "arity",
            1,
            "kind",
            "transform",
            "control",
            "redaction",
            "arg",
            0));
    String[] controls = {"guard", "scope", "facts", "suitability", "doc-acl", "capability"};
    for (int i = 0; i < controls.length; i++) {
      boolean scoped = i == 1 || i == 3 || i == 4;
      contracts.add(
          Findings.map(
              "symbol",
              prefix + "c" + (i + 1),
              "arity",
              scoped ? 2 : 1,
              "kind",
              "check",
              "control",
              controls[i],
              "args",
              scoped ? Arrays.asList(0, 1) : Arrays.asList(0),
              "accept",
              i == 0 ? accepted : true));
    }
    String[] channels = {"egress", "access", "release", "recommend", "retrieve", "tool"};
    for (int i = 0; i < channels.length; i++) {
      boolean scoped = i == 1 || i == 3 || i == 4;
      Map<String, Object> sink =
          Findings.map(
              "symbol",
              prefix + "t" + (i + 1),
              "arity",
              scoped ? 2 : 1,
              "kind",
              "sink",
              "channel",
              channels[i],
              "args",
              scoped ? Arrays.asList(1) : Arrays.asList(0));
      if (scoped) sink.put("identity", 0);
      contracts.add(sink);
    }
    return BusinessPolicy.parse(
        "bank-all", Json.COMPACT.toJson(Findings.map("version", 1, "contracts", contracts)));
  }

  private BusinessAnalysis analyze(boolean java, String body, boolean accepted) throws Exception {
    String source =
        java
            ? "import rivet.Port; class Probe { void run(boolean flag) {"
                + body.replace("@", "Port.")
                + "} }"
            : "import rivet\ndef run(flag):\n" + indent(body.replace("@", "rivet."));
    List<SourceFile> files =
        Arrays.asList(new SourceFile(java ? "Probe.java" : "probe.py", source));
    BusinessFlow.Program program =
        java ? BusinessJavaAnalysis.adapt(files, NEVER) : BusinessPythonAnalysis.adapt(files, NEVER);
    return BusinessAnalysis.analyze(program, policy(java, accepted), NEVER);
  }

  private static String indent(String body) {
    StringBuilder out = new StringBuilder();
    for (String line : body.split("\n")) out.append("    ").append(line).append('\n');
    return out.toString();
  }

  private void paired(String id, String python, String java, String expected) throws Exception {
    paired(id, python, java, expected, true);
  }

  private void paired(String id, String python, String java, String expected, boolean accepted)
      throws Exception {
    for (boolean isJava : Arrays.asList(false, true)) {
      BusinessAnalysis result = analyze(isJava, isJava ? java : python, accepted);
      Map<String, Object> assessment = null;
      for (Map<String, Object> item : result.assessments)
        if (id.equals(item.get("ruleId"))) assessment = item;
      assertNotNull(id, assessment);
      assertEquals(
          (isJava ? "Java " : "Python ")
              + id
              + " diagnostics="
              + result.diagnostics
              + " finding="
              + assessment,
          expected,
          assessment.get("disposition"));
    }
  }

  @Test
  public void sensitiveEgressHasObservedViolatedAndUnknownCases() throws Exception {
    paired(BusinessPolicy.DATA, "v=@s1()\n@t1(@r1(v))", "Object v=@s1();@t1(@r1(v));", "OBSERVED");
    paired(BusinessPolicy.DATA, "v=@s1()\n@t1(v)", "Object v=@s1();@t1(v);", "VIOLATED");
    paired(BusinessPolicy.DATA, "v=@other()\n@t1(v)", "Object v=@other();@t1(v);", "UNKNOWN");
  }

  @Test
  public void identityScopeHasObservedViolatedAndUnknownCases() throws Exception {
    paired(
        BusinessPolicy.IAM,
        "i=@s2()\nv=@s5()\nif @c2(i,v):\n    @t2(i,v)",
        "Object i=@s2();Object v=@s5();if(@c2(i,v)){@t2(i,v);}",
        "OBSERVED");
    paired(
        BusinessPolicy.IAM,
        "i=@s2()\nv=@s5()\n@t2(i,v)",
        "Object i=@s2();Object v=@s5();@t2(i,v);",
        "VIOLATED");
    paired(
        BusinessPolicy.IAM,
        "i=@other()\nv=@s5()\nif @c2(i,v):\n    @t2(i,v)",
        "Object i=@other();Object v=@s5();if(@c2(i,v)){@t2(i,v);}",
        "UNKNOWN");
  }

  @Test
  public void outputGuardHasObservedViolatedAndUnknownCases() throws Exception {
    paired(
        BusinessPolicy.GUARD,
        "v=@s4()\nif @c1(v):\n    @t3(v)",
        "Object v=@s4();if(@c1(v)){@t3(v);}",
        "OBSERVED");
    paired(BusinessPolicy.GUARD, "v=@s4()\n@t3(v)", "Object v=@s4();@t3(v);", "VIOLATED");
    paired(
        BusinessPolicy.GUARD,
        "v=@other()\nif @c1(v):\n    @t3(v)",
        "Object v=@other();if(@c1(v)){@t3(v);}",
        "UNKNOWN");
  }

  @Test
  public void customerFactsHaveObservedViolatedAndUnknownCases() throws Exception {
    paired(
        BusinessPolicy.FACTS,
        "i=@s2()\nv=@s6()\nif @c3(v):\n    @t4(i,v)",
        "Object i=@s2();Object v=@s6();if(@c3(v)){@t4(i,v);}",
        "OBSERVED");
    paired(
        BusinessPolicy.FACTS,
        "i=@s2()\nv=@s6()\n@t4(i,v)",
        "Object i=@s2();Object v=@s6();@t4(i,v);",
        "VIOLATED");
    paired(
        BusinessPolicy.FACTS,
        "i=@s2()\nv=@other()\n@t4(i,v)",
        "Object i=@s2();Object v=@other();@t4(i,v);",
        "UNKNOWN");
  }

  @Test
  public void customerSuitabilityHasObservedViolatedAndUnknownCases() throws Exception {
    paired(
        BusinessPolicy.SUITABILITY,
        "i=@s2()\nv=@s6()\nif @c4(i,v):\n    @t4(i,v)",
        "Object i=@s2();Object v=@s6();if(@c4(i,v)){@t4(i,v);}",
        "OBSERVED");
    paired(
        BusinessPolicy.SUITABILITY,
        "i=@s2()\nv=@s6()\n@t4(i,v)",
        "Object i=@s2();Object v=@s6();@t4(i,v);",
        "VIOLATED");
    paired(
        BusinessPolicy.SUITABILITY,
        "i=@other()\nv=@s6()\n@t4(i,v)",
        "Object i=@other();Object v=@s6();@t4(i,v);",
        "UNKNOWN");
  }

  @Test
  public void documentAclHasObservedViolatedAndUnknownCases() throws Exception {
    paired(
        BusinessPolicy.ACL,
        "i=@s2()\nv=@s5()\nif @c5(i,v):\n    @t5(i,v)",
        "Object i=@s2();Object v=@s5();if(@c5(i,v)){@t5(i,v);}",
        "OBSERVED");
    paired(
        BusinessPolicy.ACL,
        "i=@s2()\nv=@s5()\n@t5(i,v)",
        "Object i=@s2();Object v=@s5();@t5(i,v);",
        "VIOLATED");
    paired(
        BusinessPolicy.ACL,
        "i=@s2()\nv=@other()\n@t5(i,v)",
        "Object i=@s2();Object v=@other();@t5(i,v);",
        "UNKNOWN");
  }

  @Test
  public void toolCapabilityHasObservedViolatedAndUnknownCases() throws Exception {
    paired(
        BusinessPolicy.CAPABILITY,
        "v=@s7()\nif @c6(v):\n    @t6(v)",
        "Object v=@s7();if(@c6(v)){@t6(v);}",
        "OBSERVED");
    paired(BusinessPolicy.CAPABILITY, "v=@s7()\n@t6(v)", "Object v=@s7();@t6(v);", "VIOLATED");
    paired(BusinessPolicy.CAPABILITY, "v=@other()\n@t6(v)", "Object v=@other();@t6(v);", "UNKNOWN");
  }

  @Test
  public void renamingEverySecurityApiDoesNotChangeContractSemantics() throws Exception {
    String original = "import rivet\ndef run():\n    v=rivet.s1()\n    rivet.t1(v)\n";
    BusinessPolicy declared = policy(false, true);
    String json =
        "{\"version\":1,\"contracts\":[{\"symbol\":\"arbitrary.z19\",\"arity\":0,\"kind\":\"source\",\"label\":\"sensitive\"},{\"symbol\":\"arbitrary.q72\",\"arity\":1,\"kind\":\"sink\",\"channel\":\"egress\",\"args\":[0]}]}";
    BusinessAnalysis before =
        BusinessAnalysis.analyze(
            BusinessPythonAnalysis.adapt(Arrays.asList(new SourceFile("a.py", original)), NEVER),
            declared,
            NEVER);
    BusinessAnalysis after =
        BusinessAnalysis.analyze(
            BusinessPythonAnalysis.adapt(
                Arrays.asList(
                    new SourceFile(
                        "b.py",
                        original
                            .replace("rivet", "arbitrary")
                            .replace("s1", "z19")
                            .replace("t1", "q72"))),
                NEVER),
            BusinessPolicy.parse("bank-all", json),
            NEVER);
    assertEquals(
        before.assessments.get(0).get("disposition"), after.assessments.get(0).get("disposition"));
    assertEquals("VIOLATED", after.assessments.get(0).get("disposition"));
  }

  @Test
  public void checkingOneValueCannotProtectAnotherValue() throws Exception {
    paired(
        BusinessPolicy.GUARD,
        "v=@s4()\nw=@s4()\nif @c1(v):\n    @t3(w)",
        "Object v=@s4();Object w=@s4();if(@c1(v)){@t3(w);}",
        "VIOLATED");
  }

  @Test
  public void discardedAndOverwrittenDecisionsDoNotAuthorizeRelease() throws Exception {
    paired(
        BusinessPolicy.GUARD, "v=@s4()\n@c1(v)\n@t3(v)", "Object v=@s4();@c1(v);@t3(v);", "VIOLATED");
    paired(
        BusinessPolicy.GUARD,
        "v=@s4()\nok=@c1(v)\nok=True\nif ok:\n    @t3(v)",
        "Object v=@s4();boolean ok=@c1(v);ok=true;if(ok){@t3(v);}",
        "VIOLATED");
  }

  @Test
  public void reassignmentAfterAcceptedGuardInvalidatesThatValueBinding() throws Exception {
    paired(
        BusinessPolicy.GUARD,
        "v=@s4()\nif not @c1(v):\n    return\nv=@s4()\n@t3(v)",
        "Object v=@s4();if(!@c1(v))return;v=@s4();@t3(v);",
        "VIOLATED");
  }

  @Test
  public void rejectedBranchMustStopBeforeUnconditionalRelease() throws Exception {
    paired(
        BusinessPolicy.GUARD,
        "v=@s4()\nif not @c1(v):\n    return\n@t3(v)",
        "Object v=@s4();if(!@c1(v))return;@t3(v);",
        "OBSERVED");
    paired(
        BusinessPolicy.GUARD,
        "v=@s4()\nif not @c1(v):\n    pass\n@t3(v)",
        "Object v=@s4();if(!@c1(v)){}@t3(v);",
        "VIOLATED");
  }

  @Test
  public void falseAcceptingContractRequiresTheFalseBranch() throws Exception {
    paired(
        BusinessPolicy.GUARD,
        "v=@s4()\nif @c1(v):\n    return\n@t3(v)",
        "Object v=@s4();if(@c1(v))return;@t3(v);",
        "OBSERVED",
        false);
    paired(
        BusinessPolicy.GUARD,
        "v=@s4()\nif @c1(v):\n    @t3(v)",
        "Object v=@s4();if(@c1(v)){@t3(v);}",
        "VIOLATED",
        false);
  }

  @Test
  public void booleanEqualityAndInequalityPreserveGuardPolarity() throws Exception {
    paired(
        BusinessPolicy.GUARD,
        "v=@s4()\nif @c1(v) == True:\n    @t3(v)",
        "Object v=@s4();if(@c1(v)==true){@t3(v);}",
        "OBSERVED");
    paired(
        BusinessPolicy.GUARD,
        "v=@s4()\nif @c1(v) != True:\n    @t3(v)",
        "Object v=@s4();if(@c1(v)!=true){@t3(v);}",
        "VIOLATED");
  }

  @Test
  public void shortCircuitAndRequiresAcceptedGuardButOrCanBypassIt() throws Exception {
    paired(
        BusinessPolicy.GUARD,
        "v=@s4()\nif flag and @c1(v):\n    @t3(v)",
        "Object v=@s4();if(flag&&@c1(v)){@t3(v);}",
        "OBSERVED");
    paired(
        BusinessPolicy.GUARD,
        "v=@s4()\nif flag or @c1(v):\n    @t3(v)",
        "Object v=@s4();if(flag||@c1(v)){@t3(v);}",
        "VIOLATED");
  }

  @Test
  public void releaseBeforeGuardCannotBeRetroactivelyApproved() throws Exception {
    paired(
        BusinessPolicy.GUARD,
        "v=@s4()\n@t3(v)\nif @c1(v):\n    return",
        "Object v=@s4();@t3(v);if(@c1(v))return;",
        "VIOLATED");
  }

  @Test
  public void catchFallbackReleasesAnUncheckedValue() throws Exception {
    paired(
        BusinessPolicy.GUARD,
        "v=@s4()\n"
            + "try:\n"
            + "    if not @c1(v):\n"
            + "        return\n"
            + "    @t3(v)\n"
            + "except Exception:\n"
            + "    @t3(v)",
        "Object v=@s4();try{if(!@c1(v))return;@t3(v);}catch(Exception e){@t3(v);}",
        "VIOLATED");
  }

  @Test
  public void exceptionPathThatReturnsDoesNotReleaseFallback() throws Exception {
    paired(
        BusinessPolicy.GUARD,
        "v=@s4()\ntry:\n    if not @c1(v):\n        return\nexcept Exception:\n    return\n@t3(v)",
        "Object v=@s4();try{if(!@c1(v))return;}catch(Exception e){return;}@t3(v);",
        "OBSERVED");
  }

  @Test
  public void finallyReleaseRunsEvenAfterGuardRejectReturn() throws Exception {
    paired(
        BusinessPolicy.GUARD,
        "v=@s4()\ntry:\n    if not @c1(v):\n        return\nfinally:\n    @t3(v)",
        "Object v=@s4();try{if(!@c1(v))return;}finally{@t3(v);}",
        "VIOLATED");
  }

  @Test
  public void finallyReturnCanSuppressPostTryRelease() throws Exception {
    paired(
        BusinessPolicy.GUARD,
        "v=@s4()\ntry:\n    pass\nfinally:\n    return\n@t3(v)",
        "Object v=@s4();try{}finally{return;}@t3(v);",
        "UNKNOWN");
  }

  @Test
  public void callingRedactorButSendingOriginalStillViolates() throws Exception {
    paired(BusinessPolicy.DATA, "v=@s1()\n@r1(v)\n@t1(v)", "Object v=@s1();@r1(v);@t1(v);", "VIOLATED");
    paired(
        BusinessPolicy.DATA,
        "v=@s1()\nw=@r1(v)\n@t1(v)",
        "Object v=@s1();Object w=@r1(v);@t1(v);",
        "VIOLATED");
  }

  @Test
  public void redactedAndRawCompositeCannotBeTreatedAsFullyRedacted() throws Exception {
    // Native Python lists retain each element's data provenance. Java array
    // construction is not modeled here, so it must still retain UNKNOWN.
    for (boolean isJava : Arrays.asList(false, true)) {
      BusinessAnalysis result = analyze(isJava, isJava
          ? "Object v=@s1();Object w=@r1(v);@t1(new Object[]{w,v});"
          : "v=@s1()\nw=@r1(v)\n@t1([w,v])", true);
      boolean found = false;
      for (Map<String, Object> item : result.assessments)
        if (BusinessPolicy.DATA.equals(item.get("ruleId"))) {
          found = true;
          assertEquals(item.toString(), isJava ? "UNKNOWN" : "VIOLATED", item.get("disposition"));
          assertNotEquals("OBSERVED", item.get("disposition"));
        }
      assertTrue("Missing DATA assessment", found);
    }
    BusinessAnalysis fullyRedacted = analyze(false, "v=@s1()\nw=@r1(v)\n@t1([w,w])", true);
    Map<String, Object> redactedAssessment = null;
    for (Map<String, Object> item : fullyRedacted.assessments)
      if (BusinessPolicy.DATA.equals(item.get("ruleId"))) redactedAssessment = item;
    assertNotNull(redactedAssessment);
    assertEquals(redactedAssessment.toString(), "OBSERVED", redactedAssessment.get("disposition"));
  }

  @Test
  public void requestIdentityIsNotTrustedEvenWhenScopeAcceptsIt() throws Exception {
    paired(
        BusinessPolicy.IAM,
        "i=@s3()\nv=@s5()\nif @c2(i,v):\n    @t2(i,v)",
        "Object i=@s3();Object v=@s5();if(@c2(i,v)){@t2(i,v);}",
        "VIOLATED");
    paired(
        BusinessPolicy.SUITABILITY,
        "i=@s3()\nv=@s6()\nif @c4(i,v):\n    @t4(i,v)",
        "Object i=@s3();Object v=@s6();if(@c4(i,v)){@t4(i,v);}",
        "VIOLATED");
  }

  @Test
  public void modelOrRequestReplacementCannotReuseTheTrustedIdentityProof() throws Exception {
    paired(
        BusinessPolicy.IAM,
        "i=@s2()\nv=@s5()\nif not @c2(i,v):\n    return\ni=@s3()\n@t2(i,v)",
        "Object i=@s2();Object v=@s5();if(!@c2(i,v))return;i=@s3();@t2(i,v);",
        "VIOLATED");
  }

  @Test
  public void scopeArgumentsMustBindIdentityAndResourceInDeclaredOrder() throws Exception {
    paired(
        BusinessPolicy.IAM,
        "i=@s2()\nv=@s5()\nif @c2(v,i):\n    @t2(i,v)",
        "Object i=@s2();Object v=@s5();if(@c2(v,i)){@t2(i,v);}",
        "VIOLATED");
  }

  @Test
  public void documentAclForOneResourceCannotCoverAnother() throws Exception {
    paired(
        BusinessPolicy.ACL,
        "i=@s2()\nv=@s5()\nw=@s5()\nif @c5(i,v):\n    @t5(i,w)",
        "Object i=@s2();Object v=@s5();Object w=@s5();if(@c5(i,v)){@t5(i,w);}",
        "VIOLATED");
  }

  @Test
  public void factsAndSuitabilityRequireTheActualRecommendation() throws Exception {
    paired(
        BusinessPolicy.FACTS,
        "i=@s2()\nv=@s6()\nw=@s6()\nif @c3(v):\n    @t4(i,w)",
        "Object i=@s2();Object v=@s6();Object w=@s6();if(@c3(v)){@t4(i,w);}",
        "VIOLATED");
    paired(
        BusinessPolicy.SUITABILITY,
        "i=@s2()\nv=@s6()\nw=@s6()\nif @c4(i,v):\n    @t4(i,w)",
        "Object i=@s2();Object v=@s6();Object w=@s6();if(@c4(i,v)){@t4(i,w);}",
        "VIOLATED");
  }

  @Test
  public void toolCapabilityCannotBeCheckedAgainstDifferentArguments() throws Exception {
    paired(
        BusinessPolicy.CAPABILITY,
        "v=@s7()\nw=@s7()\nif @c6(v):\n    @t6(w)",
        "Object v=@s7();Object w=@s7();if(@c6(v)){@t6(w);}",
        "VIOLATED");
  }

  @Test
  public void localLoopsCannotCertifyWhetherAControlDominatesTheSink() throws Exception {
    paired(
        BusinessPolicy.GUARD,
        "v=@s4()\nwhile flag:\n    if not @c1(v):\n        return\n    break\n@t3(v)",
        "Object v=@s4();while(flag){if(!@c1(v))return;break;}@t3(v);",
        "UNKNOWN");
  }

  @Test
  public void sameSimpleApiNameInADifferentNamespaceDoesNotMatchTheContract() throws Exception {
    String source = "import unrelated\ndef run():\n    v=unrelated.s1()\n    unrelated.t1(v)\n";
    BusinessAnalysis result =
        BusinessAnalysis.analyze(
            BusinessPythonAnalysis.adapt(Arrays.asList(new SourceFile("probe.py", source)), NEVER),
            policy(false, true),
            NEVER);
    for (Map<String, Object> item : result.assessments)
      assertEquals("UNKNOWN", item.get("disposition"));
  }
}
