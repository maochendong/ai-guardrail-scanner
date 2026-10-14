package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.util.*;
import org.junit.Test;

/**
 * Renamed synthetic APIs exercise semantics without any project-specific selector in the engine.
 */
public class BankSemanticFlowTest {
  private static final Cancel NONE =
      new Cancel() {
        public void check() {}
      };

  private List<Map<String, Object>> contracts() {
    List<Map<String, Object>> items = new ArrayList<Map<String, Object>>();
    items.add(
        Findings.map(
            "symbol", "nova.Port#make", "arity", 0, "kind", "source", "label", "model-output"));
    items.add(
        Findings.map(
            "symbol",
            "nova.Port#inspect",
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
            Findings.map("symbol", "nova.Decision#accepted", "arg", -1)));
    items.add(
        Findings.map(
            "symbol",
            "sample.Handler#run",
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
    return items;
  }

  private BankPolicy policy(List<Map<String, Object>> items) throws Exception {
    return BankPolicy.parse(
        "bank-all", Json.COMPACT.toJson(Findings.map("version", 2, "contracts", items)));
  }

  private BankAnalysis java(String body, List<Map<String, Object>> items) throws Exception {
    BankPolicy policy = policy(items);
    String source =
        "package sample; import nova.Port; import nova.Decision; class Handler { String run(){"
            + body
            + "}}";
    BankFlow.Program program =
        BankJavaAnalysis.adapt(Arrays.asList(new SourceFile("Handler.java", source)), NONE, policy);
    return BankAnalysis.analyze(program, policy, NONE);
  }

  private Map<String, Object> finding(BankAnalysis result, String id) {
    for (Map<String, Object> item : result.assessments)
      if (id.equals(item.get("ruleId"))) return item;
    throw new AssertionError(id);
  }

  private String guarded() {
    return "String text=Port.make();Decision result=Port.inspect(text);if(!result.accepted())return"
        + " \"blocked\";return text;";
  }

  @Test
  public void objectDecisionIsBoundToOriginalOutputAndReturnBoundary() throws Exception {
    BankAnalysis result = java(guarded(), contracts());
    assertEquals(
        result.assessments.toString(),
        "OBSERVED",
        finding(result, BankPolicy.GUARD).get("disposition"));
    assertEquals(3, result.mappingCoverage.get("matchedCallSites"));
    assertEquals(1, result.mappingCoverage.get("matchedDefinitions"));
  }

  @Test
  public void ignoredResultAndWrongOutputRemainViolations() throws Exception {
    for (String body :
        Arrays.asList(
            "String text=Port.make();Port.inspect(text);return text;",
            "String text=Port.make();Decision"
                + " result=Port.inspect(text);if(!result.accepted())return \"blocked\";return"
                + " Port.make();"))
      assertEquals(
          "VIOLATED", finding(java(body, contracts()), BankPolicy.GUARD).get("disposition"));
  }

  @Test
  public void failureOpenIsNotPromotedByAcceptedAccessor() throws Exception {
    List<Map<String, Object>> items = contracts();
    items.get(1).put("failureMode", "open");
    assertEquals("VIOLATED", finding(java(guarded(), items), BankPolicy.GUARD).get("disposition"));
    items.get(1).put("failureMode", "unknown");
    Map<String, Object> unknown = finding(java(guarded(), items), BankPolicy.GUARD);
    assertEquals("UNKNOWN", unknown.get("disposition"));
    assertEquals("INSUFFICIENT_EVIDENCE", unknown.get("unknownCategory"));
  }

  @Test
  public void qualityCandidateCannotEstablishBankGuardCoverage() throws Exception {
    List<Map<String, Object>> items = contracts();
    items.get(1).put("assurance", "candidate");
    Map<String, Object> unknown = finding(java(guarded(), items), BankPolicy.GUARD);
    assertEquals("UNKNOWN", unknown.get("disposition"));
    assertEquals("INSUFFICIENT_EVIDENCE", unknown.get("unknownCategory"));
  }

  @Test
  public void assertionOnlyProvesNormalPathAndCatchCanStillRelease() throws Exception {
    List<Map<String, Object>> items = contracts();
    items.get(1).remove("decision");
    items.get(1).put("mode", "normal-return");
    assertEquals(
        "OBSERVED",
        finding(
                java("String text=Port.make();Port.inspect(text);return text;", items),
                BankPolicy.GUARD)
            .get("disposition"));
    assertEquals(
        "VIOLATED",
        finding(
                java(
                    "String text=Port.make();try{Port.inspect(text);}catch(Exception e){return"
                        + " text;}return text;",
                    items),
                BankPolicy.GUARD)
            .get("disposition"));
  }

  @Test
  public void receiverPreserveIsExplicitAndDoesNotDropGuard() throws Exception {
    List<Map<String, Object>> items = contracts();
    items.add(
        Findings.map(
            "symbol",
            "java.lang.String#trim",
            "arity",
            0,
            "kind",
            "transform",
            "control",
            "preserve",
            "arg",
            -1));
    assertEquals(
        "OBSERVED",
        finding(
                java(guarded().replace("return text;", "return text.trim();"), items),
                BankPolicy.GUARD)
            .get("disposition"));
  }

  @Test
  public void unrelatedUnsupportedFunctionDoesNotEraseMappedEvidence() throws Exception {
    List<Map<String, Object>> items = contracts();
    BankPolicy policy = policy(items);
    String source =
        "package sample; import nova.Port; import nova.Decision; class Handler {String run(){"
            + guarded()
            + "} void other(){while(true){System.out.println(1);}}}";
    BankAnalysis result =
        BankAnalysis.analyze(
            BankJavaAnalysis.adapt(
                Arrays.asList(new SourceFile("Handler.java", source)), NONE, policy),
            policy,
            NONE);
    assertEquals("OBSERVED", finding(result, BankPolicy.GUARD).get("disposition"));
    assertEquals(1, result.mappingCoverage.get("analyzedFunctions"));
  }

  @Test
  public void noIdentitySlotDoesNotInventRestrictedDocumentScope() throws Exception {
    List<Map<String, Object>> items = contracts();
    items.add(
        Findings.map(
            "symbol",
            "nova.Port#lookup",
            "arity",
            0,
            "kind",
            "sink",
            "channel",
            "retrieve",
            "args",
            Collections.emptyList(),
            "identity",
            -1));
    Map<String, Object> unknown =
        finding(java("Port.lookup();return \"fixed\";", items), BankPolicy.ACL);
    assertEquals("UNKNOWN", unknown.get("disposition"));
    assertEquals("INSUFFICIENT_EVIDENCE", unknown.get("unknownCategory"));
    items.get(3).put("scope", "restricted");
    assertEquals(
        "VIOLATED",
        finding(java("Port.lookup();return \"fixed\";", items), BankPolicy.ACL).get("disposition"));
  }

  @Test
  public void keywordArgumentsNormalizeByDeclaredNamesAndDefaults() throws Exception {
    List<Map<String, Object>> items = contracts();
    Map<String, Object> check = items.get(1);
    check.remove("decision");
    check.put("symbol", "nova.inspect");
    check.put("arity", 2);
    check.put("parameterNames", Arrays.asList("text", "limit"));
    check.put("defaults", Findings.map("limit", 5));
    items.get(0).put("symbol", "nova.make");
    items.get(2).put("symbol", "handler.run");
    BankPolicy policy = policy(items);
    String source =
        "import nova\n"
            + "def run():\n"
            + "    text=nova.make()\n"
            + "    if not nova.inspect(limit=3, text=text):\n"
            + "        return 'blocked'\n"
            + "    return text\n";
    BankAnalysis result =
        BankAnalysis.analyze(
            BankPythonAnalysis.adapt(
                Arrays.asList(new SourceFile("handler.py", source)), NONE, policy),
            policy,
            NONE);
    assertEquals(
        result.assessments.toString(),
        "OBSERVED",
        finding(result, BankPolicy.GUARD).get("disposition"));
  }

  @Test
  public void finallyCanReplaceOrInvalidatePendingReturn() throws Exception {
    String mutated =
        "String text=Port.make();Decision result=Port.inspect(text);if(!result.accepted())return"
            + " \"blocked\";try{return text;}finally{Port.modify(text);}";
    assertEquals(
        "UNKNOWN", finding(java(mutated, contracts()), BankPolicy.GUARD).get("disposition"));
    BankAnalysis replaced =
        java("String text=Port.make();try{return text;}finally{return \"blocked\";}", contracts());
    assertEquals("UNKNOWN", finding(replaced, BankPolicy.GUARD).get("disposition"));
    assertEquals(0, finding(replaced, BankPolicy.GUARD).get("mappedPathOutcomes"));
  }

  @Test
  public void mapEnvelopePreservesRedactionOfEverySensitiveMember() throws Exception {
    List<Map<String, Object>> items = contracts();
    items.get(0).put("label", "sensitive");
    items.add(
        Findings.map(
            "symbol",
            "nova.Port#mask",
            "arity",
            1,
            "kind",
            "transform",
            "control",
            "redaction",
            "arg",
            0));
    items.add(
        Findings.map(
            "symbol",
            "nova.Port#send",
            "arity",
            1,
            "kind",
            "sink",
            "channel",
            "egress",
            "args",
            Arrays.asList(0)));
    assertEquals(
        "OBSERVED",
        finding(
                java(
                    "String v=Port.make();Port.send(java.util.Map.of(\"text\",Port.mask(v)));return"
                        + " \"fixed\";",
                    items),
                BankPolicy.DATA)
            .get("disposition"));
    assertEquals(
        "VIOLATED",
        finding(
                java(
                    "String"
                        + " v=Port.make();Port.send(java.util.Map.of(\"text\",Port.mask(v),\"original\",v));return"
                        + " \"fixed\";",
                    items),
                BankPolicy.DATA)
            .get("disposition"));
  }

  @Test
  public void escapedMapInvalidatesNestedAliases() throws Exception {
    List<Map<String, Object>> items = contracts();
    items.get(0).put("label", "sensitive");
    items.add(
        Findings.map(
            "symbol",
            "nova.Port#mask",
            "arity",
            1,
            "kind",
            "transform",
            "control",
            "redaction",
            "arg",
            0));
    items.add(
        Findings.map(
            "symbol",
            "nova.Port#send",
            "arity",
            1,
            "kind",
            "sink",
            "channel",
            "egress",
            "args",
            Arrays.asList(0)));
    assertEquals(
        "UNKNOWN",
        finding(
                java(
                    "Object v=Port.mask(Port.make());Object"
                        + " map=java.util.Map.of(\"value\",v);Port.modify(map);Port.send(v);return"
                        + " \"fixed\";",
                    items),
                BankPolicy.DATA)
            .get("disposition"));
  }

  @Test
  public void scalarDefaultsAndExplicitNumericArgumentsShareValueIdentity() throws Exception {
    List<Map<String, Object>> items = new ArrayList<Map<String, Object>>();
    items.add(
        Findings.map("symbol", "nova.data", "arity", 0, "kind", "source", "label", "model-output"));
    items.add(
        Findings.map(
            "symbol",
            "nova.check",
            "arity",
            2,
            "parameterNames",
            Arrays.asList("value", "version"),
            "defaults",
            Findings.map("version", 1),
            "kind",
            "check",
            "control",
            "guard",
            "args",
            Arrays.asList(0, 1),
            "accept",
            true,
            "failureMode",
            "closed"));
    items.add(
        Findings.map(
            "symbol",
            "nova.release",
            "arity",
            2,
            "kind",
            "sink",
            "channel",
            "release",
            "args",
            Arrays.asList(0, 1)));
    BankPolicy policy = policy(items);
    for (String call : Arrays.asList("nova.check(v)", "nova.check(v,1)")) {
      String source =
          "import nova\ndef run():\n    v=nova.data()\n    if not "
              + call
              + ":\n        return\n    nova.release(v,1)\n";
      BankAnalysis result =
          BankAnalysis.analyze(
              BankPythonAnalysis.adapt(
                  Arrays.asList(new SourceFile("demo.py", source)), NONE, policy),
              policy,
              NONE);
      assertEquals(
          result.assessments.toString(),
          "OBSERVED",
          finding(result, BankPolicy.GUARD).get("disposition"));
    }
  }

  @Test
  public void excessPathsKeepLaterMappedSitesUnknownInsteadOfDroppingThem() throws Exception {
    StringBuilder body = new StringBuilder();
    for (int i = 0; i < 9; i++)
      body.append("if(Port.condition").append(i).append("()){Port.other();}");
    body.append("return Port.make();");
    BankAnalysis result = java(body.toString(), contracts());
    assertEquals("UNKNOWN", finding(result, BankPolicy.GUARD).get("disposition"));
    assertTrue(((Number) result.mappingCoverage.get("matchedBoundarySites")).intValue() > 0);
    boolean merged = false;
    for (Map<String, Object> diagnostic : result.diagnostics)
      merged |= "BANK_PATHS_MERGED".equals(diagnostic.get("code"));
    assertTrue(result.diagnostics.toString(), merged);
  }

  @Test
  public void unknownConstructorCannotRetainGuardProof() throws Exception {
    String body = guarded().replace("return text;", "new nova.ExternalMutation();return text;");
    assertEquals("UNKNOWN", finding(java(body, contracts()), BankPolicy.GUARD).get("disposition"));
  }

  @Test
  public void knownApiWithUnboundKeywordsIsUnsupportedRatherThanMissingMapping() throws Exception {
    List<Map<String, Object>> items = new ArrayList<Map<String, Object>>();
    items.add(
        Findings.map(
            "symbol",
            "nova.release",
            "arity",
            1,
            "kind",
            "sink",
            "channel",
            "release",
            "args",
            Arrays.asList(0)));
    BankPolicy policy = policy(items);
    String source = "import nova\ndef run():\n    nova.release(text='sample')\n";
    BankAnalysis result =
        BankAnalysis.analyze(
            BankPythonAnalysis.adapt(
                Arrays.asList(new SourceFile("demo.py", source)), NONE, policy),
            policy,
            NONE);
    assertEquals("UNSUPPORTED", finding(result, BankPolicy.GUARD).get("unknownCategory"));
    assertEquals(1, result.mappingCoverage.get("argumentBindingFailures"));
  }

  @Test
  public void deepMappedFlowDoesNotReclassifyRulesWithNoContracts() throws Exception {
    BankPolicy policy = policy(contracts());
    BankFlow.Program program = new BankFlow.Program();
    BankFlow.Function function = new BankFlow.Function();
    function.symbol = "sample.Handler#run";
    program.functions.add(function);
    List<BankFlow.Stmt> block = function.body;
    for (int i = 0; i < 80; i++) {
      BankFlow.Stmt node = new BankFlow.Stmt("UNKNOWN");
      block.add(node);
      block = node.body;
    }
    BankAnalysis result = BankAnalysis.analyze(program, policy, NONE);
    assertEquals("UNSUPPORTED", finding(result, BankPolicy.GUARD).get("unknownCategory"));
    assertEquals("MISSING_MAPPING", finding(result, BankPolicy.FACTS).get("unknownCategory"));
  }

  @Test
  public void emptyMappingHasExplicitMissingReason() throws Exception {
    Map<String, Object> unknown = finding(java("return \"fixed\";", contracts()), BankPolicy.ACL);
    assertEquals("MISSING_MAPPING", unknown.get("unknownCategory"));
  }
}
