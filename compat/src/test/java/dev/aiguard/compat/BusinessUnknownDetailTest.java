package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.util.*;
import org.junit.Test;

public class BusinessUnknownDetailTest {
  private static final Cancel NONE =
      new Cancel() {
        public void check() {}
      };

  private Map<String, Object> check(String name, String failure, String assurance) {
    return Findings.map(
        "symbol",
        "port.Control#" + name,
        "arity",
        1,
        "kind",
        "check",
        "control",
        "guard",
        "args",
        Arrays.asList(0),
        "mode",
        "normal-return",
        "failureMode",
        failure,
        "assurance",
        assurance);
  }

  private BusinessAnalysis scan(String body, List<Map<String, Object>> extra) throws Exception {
    List<Map<String, Object>> contracts = new ArrayList<Map<String, Object>>(extra);
    contracts.add(
        Findings.map(
            "symbol", "port.Model#make", "arity", 0, "kind", "source", "label", "model-output"));
    contracts.add(
        Findings.map(
            "symbol",
            "port.Output#send",
            "arity",
            1,
            "kind",
            "sink",
            "channel",
            "release",
            "args",
            Arrays.asList(0)));
    BusinessPolicy policy =
        BusinessPolicy.parse(
            "bank-all", Json.COMPACT.toJson(Findings.map("version", 2, "contracts", contracts)));
    return BusinessAnalysis.analyze(
        BusinessJavaAnalysis.adapt(
            Arrays.asList(
                new SourceFile(
                    "Sample.java",
                    "import port.Model; import port.Output; import port.Control; import port.Store;"
                        + " class Sample {void run(boolean flag,String subject){\n"
                        + body
                        + "\n}}")),
            NONE,
            policy),
        policy,
        NONE);
  }

  private Map<String, Object> finding(BusinessAnalysis analysis, String rule) {
    for (Map<String, Object> item : analysis.assessments)
      if (rule.equals(item.get("ruleId"))) return item;
    throw new AssertionError(rule);
  }

  @SuppressWarnings("unchecked")
  private List<Map<String, Object>> sites(Map<String, Object> finding) {
    return (List<Map<String, Object>>) finding.get("siteAssessments");
  }

  @Test
  public void sameSiteMergesDifferentUnknownPathReasonsBeforeDeduplication() throws Exception {
    Map<String, Object> result =
        finding(
            scan(
                "String x=Model.make();\n"
                    + "if(flag)Control.quality(x);else Control.unverified(x);\nOutput.send(x);",
                Arrays.asList(
                    check("quality", "open", "candidate"),
                    check("unverified", "unknown", "reviewed"))),
            BusinessPolicy.GUARD);
    assertEquals("UNKNOWN", result.get("disposition"));
    assertEquals(1, sites(result).size());
    String reasons = sites(result).get(0).get("unknownReasons").toString();
    assertTrue(reasons, reasons.contains("CONTROL_ASSURANCE_UNVERIFIED"));
    assertTrue(reasons, reasons.contains("GUARD_FAILURE_OPEN"));
    assertTrue(reasons, reasons.contains("GUARD_FAILURE_UNVERIFIED"));
  }

  @Test
  public void violatedAggregateRetainsOtherUnknownSitesForReview() throws Exception {
    Map<String, Object> result =
        finding(
            scan(
                "Output.send(Model.make());\n"
                    + "String x=Model.make();Control.quality(x);Output.send(x);",
                Arrays.asList(check("quality", "unknown", "candidate"))),
            BusinessPolicy.GUARD);
    assertEquals("VIOLATED", result.get("disposition"));
    assertEquals(2, sites(result).size());
    Unknowns.complete(Arrays.asList(result), Collections.<Map<String, Object>>emptyList());
    assertEquals(Boolean.TRUE, result.get("manualReviewRequired"));
    assertFalse(((List<?>) result.get("reviewActions")).isEmpty());
  }

  @Test
  public void noIdentityAndUnclassifiedDocumentsKeepIndependentReasons() throws Exception {
    Map<String, Object> retrieve =
        Findings.map(
            "symbol",
            "port.Store#retrieve",
            "arity",
            1,
            "kind",
            "sink",
            "channel",
            "retrieve",
            "args",
            Arrays.asList(0),
            "identity",
            -1,
            "scope",
            "unknown");
    BusinessAnalysis analysis = scan("Store.retrieve(subject);", Arrays.asList(retrieve));
    for (String rule : Arrays.asList(BusinessPolicy.IAM, BusinessPolicy.ACL)) {
      Map<String, Object> result = finding(analysis, rule);
      assertEquals("UNKNOWN", result.get("disposition"));
      String reasons = sites(result).get(0).get("unknownReasons").toString();
      assertTrue(reasons.contains("IDENTITY_SLOT_MISSING"));
      assertTrue(reasons.contains("RESOURCE_SCOPE_UNCLASSIFIED"));
    }
  }

  @Test
  public void identityParameterDoesNotBecomeTrustedFromItsName() throws Exception {
    Map<String, Object> access =
        Findings.map(
            "symbol",
            "port.Store#read",
            "arity",
            2,
            "kind",
            "sink",
            "channel",
            "access",
            "args",
            Arrays.asList(1),
            "identity",
            0,
            "scope",
            "restricted");
    Map<String, Object> result =
        finding(scan("Store.read(subject,\"item\");", Arrays.asList(access)), BusinessPolicy.IAM);
    assertEquals("UNKNOWN", result.get("disposition"));
    assertTrue(result.get("unknownReasons").toString().contains("IDENTITY_TRUST_UNVERIFIED"));
  }

  @Test
  public void actuallyCalledFailureOpenGuardRemainsVisibleWithoutInventingOutputReachability()
      throws Exception {
    BusinessAnalysis analysis =
        scan("Control.quality(subject);", Arrays.asList(check("quality", "open", "candidate")));
    Map<String, Object> result = finding(analysis, BusinessPolicy.GUARD);
    assertEquals("UNKNOWN", result.get("disposition"));
    assertEquals(0, result.get("mappedPathOutcomes"));
    assertTrue(sites(result).isEmpty());
    Unknowns.complete(analysis.assessments, analysis.diagnostics);
    String controls = result.get("controlReviewSites").toString();
    assertTrue(controls.contains("GUARD_FAILURE_OPEN"));
    assertTrue(controls.contains("CONTROL_ASSURANCE_UNVERIFIED"));
    assertEquals(Boolean.TRUE, result.get("manualReviewRequired"));
    assertTrue(result.get("unknownReasons").toString().contains("NO_RESOLVED_MAPPED_SINK"));
  }

  @Test
  public void siteLimitIsExplicitAndDoesNotStopAssessmentOfLaterViolation() throws Exception {
    StringBuilder body = new StringBuilder();
    for (int i = 0; i < 130; i++) body.append("Output.send(subject);\n");
    // Unknown external input does not need a model-output label for this unconditional sink.
    body.append("Output.send(Model.make());\n");
    Map<String, Object> result =
        finding(
            scan(body.toString(), Collections.<Map<String, Object>>emptyList()), BusinessPolicy.GUARD);
    assertEquals("VIOLATED", result.get("disposition"));
    assertEquals(128, sites(result).size());
    assertEquals(Boolean.TRUE, result.get("siteAssessmentsTruncated"));
    assertEquals(131, result.get("mappedPathOutcomes"));
  }
}
