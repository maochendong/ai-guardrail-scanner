package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.*;
import org.junit.Test;

/** Conjunctive decisions belong to one returned object, never a method name or argument tuple. */
public class BusinessCompoundDecisionTest {
  private static final Cancel NONE =
      new Cancel() {
        public void check() {}
      };

  private List<Map<String, Object>> contracts(boolean python) {
    String prefix = python ? "vendor." : "nova.Port#";
    String result = python ? "vendor." : "nova.Decision#";
    int slot = python ? 0 : -1;
    List<Map<String, Object>> contracts = new ArrayList<Map<String, Object>>();
    contracts.add(
        Findings.map(
            "symbol", prefix + "make", "arity", 0, "kind", "source", "label", "model-output"));
    contracts.add(
        Findings.map(
            "symbol",
            prefix + "inspect",
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
            "closed",
            "decision",
            Findings.map(
                "all",
                Arrays.asList(
                    Findings.map("symbol", result + "allowed", "arg", slot, "accept", true),
                    Findings.map(
                        "symbol", result + "needsReview", "arg", slot, "accept", false)))));
    contracts.add(
        Findings.map(
            "symbol",
            prefix + "release",
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
    return contracts;
  }

  private BusinessPolicy policy(List<Map<String, Object>> contracts) throws Exception {
    return BusinessPolicy.parse(
        "bank-all", Json.COMPACT.toJson(Findings.map("version", 2, "contracts", contracts)));
  }

  private String scan(String body, boolean python, List<Map<String, Object>> contracts)
      throws Exception {
    BusinessPolicy policy = policy(contracts);
    String source =
        python
            ? "import vendor\ndef run():\n" + body
            : "import nova.Port; import nova.Decision; class Runner { void run(){" + body + "}}";
    List<SourceFile> files =
        Arrays.asList(new SourceFile(python ? "flow.py" : "Runner.java", source));
    BusinessFlow.Program program =
        python
            ? BusinessPythonAnalysis.adapt(files, NONE, policy)
            : BusinessJavaAnalysis.adapt(files, NONE, policy);
    BusinessAnalysis analysis = BusinessAnalysis.analyze(program, policy, NONE);
    for (Map<String, Object> finding : analysis.assessments)
      if (BusinessPolicy.GUARD.equals(finding.get("ruleId")))
        return String.valueOf(finding.get("disposition"));
    throw new AssertionError(analysis.assessments);
  }

  private String java(String body) throws Exception {
    return scan(
        "String text=Port.make();Decision a=Port.inspect(text);" + body, false, contracts(false));
  }

  @Test
  public void completeConjunctionAndRejectingDisjunctionAcceptTheSameObject() throws Exception {
    for (String body :
        Arrays.asList(
            "if(a.allowed() && !a.needsReview()) Port.release(text);",
            "if(!a.allowed() || a.needsReview()) return; Port.release(text);",
            "if(a.needsReview())return; if(!a.allowed())return;Port.release(text);",
            "if(a.allowed()==false || a.needsReview()!=false)return;Port.release(text);"))
      assertEquals(body, "OBSERVED", java(body));
  }

  @Test
  public void MissingWrongOrAlternativeClauseCannotAuthorize() throws Exception {
    for (String body :
        Arrays.asList(
            "if(a.allowed())Port.release(text);",
            "if(!a.needsReview())Port.release(text);",
            "if(a.allowed() || !a.needsReview())Port.release(text);",
            "if(a.allowed() && a.needsReview())Port.release(text);",
            "a.allowed();a.needsReview();Port.release(text);"))
      assertNotEquals(body, "OBSERVED", java(body));
  }

  @Test
  public void twoDecisionsForIdenticalInputsCannotDonateClausesToEachOther() throws Exception {
    assertNotEquals(
        "OBSERVED",
        java("Decision b=Port.inspect(text);if(a.allowed()&&!b.needsReview())Port.release(text);"));
    assertNotEquals(
        "OBSERVED",
        java("if(a.allowed()){a=Port.inspect(text);if(!a.needsReview())Port.release(text);}"));
  }

  @Test
  public void decisionAliasesPreserveIdentityButWrongOutputDoesNot() throws Exception {
    assertEquals(
        "OBSERVED", java("Decision b=a;if(a.allowed()&&!b.needsReview())Port.release(text);"));
    assertEquals(
        "VIOLATED",
        java("String other=Port.make();if(a.allowed()&&!a.needsReview())Port.release(other);"));
  }

  @Test
  public void oppositeSecondReadCannotReachRelease() throws Exception {
    String result = java("if(a.allowed()&&!a.needsReview()&&a.needsReview())Port.release(text);");
    assertNotEquals("VIOLATED", result);
  }

  @Test
  public void mutationExceptionAndEarlyReleaseNeverAcquireProtection() throws Exception {
    assertNotEquals(
        "OBSERVED",
        java("if(a.allowed()){Port.mutate(a);if(!a.needsReview())Port.release(text);}"));
    assertNotEquals(
        "OBSERVED",
        java(
            "try{if(a.allowed()&&!a.needsReview())Port.release(text);}catch(Exception"
                + " e){Port.release(text);}"));
    assertEquals("VIOLATED", java("Port.release(text);if(!a.allowed()||a.needsReview())return;"));
  }

  @Test
  public void pythonConjunctionAndEarlyRejectionAreEquivalent() throws Exception {
    for (String body :
        Arrays.asList(
            "    if vendor.allowed(a) and not vendor.needsReview(a):\n"
                + "        vendor.release(text)\n",
            "    if not vendor.allowed(a) or vendor.needsReview(a):\n"
                + "        return\n"
                + "    vendor.release(text)\n"))
      assertEquals(
          "OBSERVED",
          scan(
              "    text=vendor.make()\n    a=vendor.inspect(text)\n" + body,
              true,
              contracts(true)));
  }

  @Test
  public void pythonSeparateObjectsAndOrDoNotCompleteConjunction() throws Exception {
    for (String body :
        Arrays.asList(
            "    b=vendor.inspect(text)\n"
                + "    if vendor.allowed(a) and not vendor.needsReview(b):\n"
                + "        vendor.release(text)\n",
            "    if vendor.allowed(a) or not vendor.needsReview(a):\n"
                + "        vendor.release(text)\n"))
      assertNotEquals(
          "OBSERVED",
          scan(
              "    text=vendor.make()\n    a=vendor.inspect(text)\n" + body,
              true,
              contracts(true)));
  }

  @Test
  public void candidateAndOpenFailureAreNotElevatedByCompleteDecision() throws Exception {
    String body =
        "String text=Port.make();Decision"
            + " a=Port.inspect(text);if(a.allowed()&&!a.needsReview())Port.release(text);";
    List<Map<String, Object>> contracts = contracts(false);
    contracts.get(1).put("assurance", "candidate");
    assertEquals("UNKNOWN", scan(body, false, contracts));
    contracts = contracts(false);
    contracts.get(1).put("failureMode", "open");
    assertEquals("VIOLATED", scan(body, false, contracts));
  }

  @Test
  public void policyNormalizesLegacyAndCompoundDecisions() throws Exception {
    List<Map<String, Object>> contracts = contracts(false);
    BusinessPolicy.Contract check = policy(contracts).contract("nova.Port#inspect", 1);
    assertEquals(2, check.decisionPredicates.size());
    assertTrue(check.decisionPredicates.get(0).accept);
    assertFalse(check.decisionPredicates.get(1).accept);
    assertEquals("", check.decisionSymbol);
    contracts.get(1).put("accept", false);
    contracts.get(1).put("decision", Findings.map("symbol", "nova.Decision#allowed", "arg", -1));
    check = policy(contracts).contract("nova.Port#inspect", 1);
    assertEquals(1, check.decisionPredicates.size());
    assertFalse(check.decisionPredicates.get(0).accept);
    assertEquals("nova.Decision#allowed", check.decisionSymbol);
  }

  @Test
  public void malformedOrAmbiguousConjunctionsAreRejected() throws Exception {
    Map<String, Object> leaf =
        Findings.map("symbol", "nova.Decision#allowed", "arg", -1, "accept", true);
    for (Object decision :
        Arrays.asList(
            Findings.map("all", Collections.emptyList()),
            Findings.map("all", Arrays.asList(leaf, leaf)),
            Findings.map("all", Collections.nCopies(9, leaf)),
            Findings.map("all", Arrays.asList(leaf), "symbol", "nova.Decision#allowed", "arg", -1),
            Findings.map(
                "all", Arrays.asList(Findings.map("symbol", "nova.Decision#allowed", "arg", -1))),
            Findings.map(
                "all",
                Arrays.asList(
                    Findings.map("symbol", "nova.Decision#allowed", "arg", 1, "accept", true))),
            Findings.map(
                "all",
                Arrays.asList(
                    Findings.map(
                        "symbol", "nova.Decision#allowed", "arg", -1, "accept", "true"))))) {
      List<Map<String, Object>> contracts = contracts(false);
      contracts.get(1).put("decision", decision);
      try {
        policy(contracts);
        fail(String.valueOf(decision));
      } catch (IOException expected) {
      }
    }
    List<Map<String, Object>> contracts = contracts(false);
    contracts.get(1).put("accept", false);
    try {
      policy(contracts);
      fail("Outer negation is not a conjunctive acceptance contract");
    } catch (IOException expected) {
    }
  }
}
