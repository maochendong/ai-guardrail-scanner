package dev.aiguard.compat;

import static org.junit.Assert.*;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class UnknownReviewTest {
  @Rule public TemporaryFolder temporary = new TemporaryFolder();

  private static Map<String, Object> finding(String rule, String disposition, int line) {
    return Findings.assessment(
        rule,
        "L2",
        disposition,
        "HIGH",
        "Synthetic control",
        "Synthetic evidence",
        "Locate the relevant control",
        line > 0
            ? Arrays.asList(Findings.evidence("src/Flow.java", line, "Controlled evidence"))
            : Collections.<Map<String, Object>>emptyList());
  }

  @SuppressWarnings("unchecked")
  private static List<Map<String, Object>> items(Map<String, Object> item, String key) {
    return (List<Map<String, Object>>) item.get(key);
  }

  private static Map<String, Object> action(Map<String, Object> item, String code) {
    for (Map<String, Object> action : items(item, "reviewActions"))
      if (code.equals(action.get("code"))) return action;
    return null;
  }

  @Test
  public void legacyUnknownsRequireEvidenceTriageWithoutBlanketManualReview() {
    for (int line : Arrays.asList(0, 12)) {
      Map<String, Object> item = finding("LEGACY", "UNKNOWN", line);
      assertEquals(Boolean.FALSE, item.get("manualReviewRequired"));
      assertEquals(1, items(item, "reviewActions").size());
      assertEquals("TRIAGE_EVIDENCE", action(item, "LOCATE_CONTROL_EVIDENCE").get("kind"));
      assertEquals("OPEN", action(item, "LOCATE_CONTROL_EVIDENCE").get("status"));
    }
  }

  @Test
  public void externalGenerationConfigurationRequiresBuildEvidence() {
    Map<String, Object> item = finding("GENERIC", "UNKNOWN", 12);
    Unknowns.set(
        item,
        Unknowns.INSUFFICIENT_EVIDENCE,
        "GENERATED_METHOD_CONFIGURATION_UNVERIFIED",
        "Inherited configuration is outside scope.");
    Map<String, Object> review = action(item, "VERIFY_GENERATED_METHOD_CONFIGURATION");
    assertNotNull(review);
    assertEquals("VERIFY_RUNTIME", review.get("kind"));
    assertEquals(Boolean.TRUE, item.get("manualReviewRequired"));
    assertEquals("UNKNOWN", item.get("disposition"));
  }

  @Test
  public void mappingReasonsReplaceDefaultsAndPostponeRuntimeAcceptance() {
    Map<String, Object> item = finding("BANK-IAM-001", "UNKNOWN", 12);
    Unknowns.set(item, Unknowns.MISSING_MAPPING, "SOURCE_UNMAPPED", "Map source.");
    assertEquals(1, items(item, "reviewActions").size());
    assertNotNull(action(item, "MAP_CONTROL_API"));
    assertNull(action(item, "LOCATE_CONTROL_EVIDENCE"));
    assertNull(action(item, "VERIFY_IDENTITY_ISOLATION"));
    assertEquals(Boolean.FALSE, item.get("manualReviewRequired"));
  }

  @Test
  public void unsupportedCausesHaveTechnicalActionsAndDoNotAutomaticallyRequireHumans() {
    Map<String, Object> item = finding("GENERIC", "UNKNOWN", 12);
    Unknowns.set(item, Unknowns.UNSUPPORTED, "RECEIVER_BINDING_UNRESOLVED", "Unbound target.");
    Unknowns.set(item, Unknowns.UNSUPPORTED, "STREAM_ELEMENT_UNRESOLVED", "Unbound element.");
    Unknowns.set(item, Unknowns.UNSUPPORTED, "INTERPROCEDURAL_FLOW_BOUNDED", "Bounded call.");
    assertNotNull(action(item, "RESOLVE_RECEIVER_BINDING"));
    assertNotNull(action(item, "RESOLVE_STREAM_ELEMENT_FLOW"));
    assertNotNull(action(item, "EXTEND_CALL_CONTEXT"));
    assertEquals(3, items(item, "reviewActions").size());
    assertEquals(Boolean.FALSE, item.get("manualReviewRequired"));
  }

  @Test
  public void preciseSemanticReasonsRequireSpecificEvidenceAndStayUnknown() {
    String[][] reasons = {
      {"IDENTITY_TRUST_UNVERIFIED", "CONFIRM_TRUSTED_IDENTITY"},
      {"RESOURCE_SCOPE_UNCLASSIFIED", "CONFIRM_RESOURCE_SCOPE"},
      {"CONTROL_ASSURANCE_UNVERIFIED", "CONFIRM_CONTROL_SEMANTICS"},
      {"GUARD_FAILURE_UNVERIFIED", "VERIFY_GUARD_FAIL_CLOSED"},
      {"GUARD_FAILURE_OPEN", "VERIFY_GUARD_FAIL_CLOSED"}
    };
    for (String[] reason : reasons) {
      Map<String, Object> item = finding("GENERIC", "UNKNOWN", 12);
      Unknowns.set(item, Unknowns.INSUFFICIENT_EVIDENCE, reason[0], "Specific semantic gap.");
      assertEquals(reason[0], Boolean.TRUE, item.get("manualReviewRequired"));
      Map<String, Object> review = action(item, reason[1]);
      assertNotNull(review);
      assertEquals(Arrays.asList(reason[0]), review.get("reasonCodes"));
      assertFalse(((List<?>) review.get("requiredEvidence")).isEmpty());
      assertEquals("UNKNOWN", item.get("disposition"));
    }
  }

  @Test
  public void coreRuleRuntimeAcceptanceRequiresLocatedEvidenceAndPreservesTechnicalWork() {
    String[][] rules = {
      {"BANK-GUARD-001", "VERIFY_GUARD_FAIL_CLOSED"},
      {"BANK-IAM-001", "VERIFY_IDENTITY_ISOLATION"},
      {"BANK-INTERNAL-001", "VERIFY_DOCUMENT_AUTHORIZATION"}
    };
    for (String[] rule : rules) {
      Map<String, Object> unlocated = finding(rule[0], "UNKNOWN", 0);
      assertNull(action(unlocated, rule[1]));
      assertEquals(Boolean.FALSE, unlocated.get("manualReviewRequired"));
      Map<String, Object> located = finding(rule[0], "UNKNOWN", 12);
      Unknowns.set(located, Unknowns.UNSUPPORTED, "LOCAL_FLOW_UNRESOLVED", "Expand flow.");
      assertNotNull(action(located, "EXTEND_FLOW_ANALYSIS"));
      assertNotNull(action(located, rule[1]));
      assertEquals(Boolean.TRUE, located.get("manualReviewRequired"));
    }
  }

  @Test
  public void identitySlotIsMappingWorkNotAnAssumedTrustConfirmation() {
    Map<String, Object> item = finding("BANK-IAM-001", "UNKNOWN", 12);
    Unknowns.set(
        item, Unknowns.INSUFFICIENT_EVIDENCE, "IDENTITY_SLOT_MISSING", "No identity slot.");
    assertEquals("MAP_API", action(item, "BIND_IDENTITY_ARGUMENT").get("kind"));
    assertEquals(Boolean.FALSE, item.get("manualReviewRequired"));
    assertNull(action(item, "VERIFY_IDENTITY_ISOLATION"));
  }

  @Test
  public void duplicateReasonsDoNotDuplicateActionsOrLocations() {
    Map<String, Object> item = finding("BANK-GUARD-001", "UNKNOWN", 12);
    Unknowns.set(item, Unknowns.INSUFFICIENT_EVIDENCE, "GUARD_FAILURE_UNVERIFIED", "Failure gap.");
    Unknowns.set(item, Unknowns.INSUFFICIENT_EVIDENCE, "GUARD_FAILURE_UNVERIFIED", "Failure gap.");
    Unknowns.complete(Arrays.asList(item), Collections.<Map<String, Object>>emptyList());
    assertEquals(1, items(item, "reviewActions").size());
    assertEquals(1, items(action(item, "VERIFY_GUARD_FAIL_CLOSED"), "locations").size());
  }

  @Test
  public void mixedSiteReasonsKeepTheirOwnLocationsEvenUnderViolatedParent() {
    Map<String, Object> parent = finding("BANK-INTERNAL-001", "VIOLATED", 5);
    Map<String, Object> missing = finding("BANK-INTERNAL-001", "UNKNOWN", 20);
    Map<String, Object> scope = finding("BANK-INTERNAL-001", "UNKNOWN", 40);
    Unknowns.set(missing, Unknowns.MISSING_MAPPING, "ACL_UNMAPPED", "Map ACL.");
    Unknowns.set(
        scope, Unknowns.INSUFFICIENT_EVIDENCE, "RESOURCE_SCOPE_UNCLASSIFIED", "Classify docs.");
    parent.put("siteAssessments", Arrays.asList(missing, scope));
    Unknowns.complete(Arrays.asList(parent), Collections.<Map<String, Object>>emptyList());
    assertEquals("VIOLATED", parent.get("disposition"));
    assertFalse(parent.containsKey("unknownReasons"));
    assertEquals(Boolean.TRUE, parent.get("manualReviewRequired"));
    assertEquals(Boolean.FALSE, missing.get("manualReviewRequired"));
    assertEquals(20, items(action(parent, "MAP_CONTROL_API"), "locations").get(0).get("line"));
    assertEquals(
        40, items(action(parent, "CONFIRM_RESOURCE_SCOPE"), "locations").get(0).get("line"));
    assertEquals(1, items(action(parent, "VERIFY_DOCUMENT_AUTHORIZATION"), "locations").size());
    assertEquals(
        40, items(action(parent, "VERIFY_DOCUMENT_AUTHORIZATION"), "locations").get(0).get("line"));
  }

  @Test
  public void aggregateCoverageGapIsNotLostWhenLocatedSiteActionsExist() {
    Map<String, Object> parent = finding("BANK-GUARD-001", "UNKNOWN", 10);
    Unknowns.set(parent, Unknowns.UNSUPPORTED, "BANK_ANALYSIS_BOUNDED", "Unvisited paths.");
    Map<String, Object> site = finding("BANK-GUARD-001", "UNKNOWN", 20);
    Unknowns.set(
        site, Unknowns.INSUFFICIENT_EVIDENCE, "GUARD_FAILURE_OPEN", "Failure allows output.");
    parent.put("siteAssessments", Arrays.asList(site));
    Unknowns.complete(Arrays.asList(parent), Collections.<Map<String, Object>>emptyList());
    Map<String, Object> gap = action(parent, "EXTEND_FLOW_ANALYSIS");
    assertNotNull(gap);
    assertTrue(((List<?>) gap.get("reasonCodes")).contains("BANK_ANALYSIS_BOUNDED"));
    assertTrue(items(gap, "locations").isEmpty());
    assertEquals(
        20, items(action(parent, "VERIFY_GUARD_FAIL_CLOSED"), "locations").get(0).get("line"));
  }

  @Test
  public void allFormatsPreserveActionsSitesAndUnchangedSafetyAssertions() throws Exception {
    Map<String, Object> unknown = finding("BANK-GUARD-001", "UNKNOWN", 12);
    Unknowns.set(
        unknown,
        Unknowns.INSUFFICIENT_EVIDENCE,
        "GUARD_FAILURE_UNVERIFIED",
        "Confirm failure semantics.");
    Map<String, Object> violated = finding("BANK-INTERNAL-001", "VIOLATED", 5);
    Map<String, Object> site = finding("BANK-INTERNAL-001", "UNKNOWN", 40);
    site.put("path", "src/Flow.java");
    site.put("line", 40);
    Unknowns.set(
        site, Unknowns.INSUFFICIENT_EVIDENCE, "RESOURCE_SCOPE_UNCLASSIFIED", "Classify docs.");
    violated.put("siteAssessments", Arrays.asList(site));
    violated.put("siteAssessmentsTruncated", true);
    Map<String, Object> control =
        Findings.map(
            "ruleId",
            "BANK-GUARD-001",
            "disposition",
            "UNKNOWN",
            "evidence",
            Arrays.asList(Findings.evidence("src/Flow.java", 60, "Located check.")));
    control.put("path", "src/Flow.java");
    control.put("line", 60);
    Unknowns.set(
        control,
        Unknowns.INSUFFICIENT_EVIDENCE,
        "GUARD_FAILURE_OPEN",
        "Review check independently.");
    unknown.put("controlReviewSites", Arrays.asList(control));
    unknown.put("controlReviewSitesTruncated", true);
    List<Map<String, Object>> assessments = Arrays.asList(unknown, violated);
    Unknowns.complete(assessments, Collections.<Map<String, Object>>emptyList());
    Map<String, Object> report = report(assessments);
    Path output = temporary.newFolder("formats").toPath().toRealPath();
    Map<String, String> docs = Reports.write(report, output);
    JsonObject json = Json.parse(docs.get("json")).getAsJsonObject();
    JsonObject run =
        Json.parse(docs.get("sarif"))
            .getAsJsonObject()
            .getAsJsonArray("runs")
            .get(0)
            .getAsJsonObject();
    JsonObject properties = run.getAsJsonObject("properties");
    JsonObject detail =
        properties.getAsJsonArray("unknownAssessmentsDetails").get(0).getAsJsonObject();
    assertEquals(
        json.getAsJsonArray("assessments").get(0).getAsJsonObject().get("reviewActions"),
        detail.get("reviewActions"));
    assertTrue(detail.get("manualReviewRequired").getAsBoolean());
    assertEquals(
        json.getAsJsonArray("assessments").get(0).getAsJsonObject().get("controlReviewSites"),
        detail.get("controlReviewSites"));
    assertTrue(detail.get("controlReviewSitesTruncated").getAsBoolean());
    JsonArray other = properties.getAsJsonArray("reviewAssessmentsDetails");
    assertEquals(1, other.size());
    assertEquals("VIOLATED", other.get(0).getAsJsonObject().get("disposition").getAsString());
    assertEquals(1, other.get(0).getAsJsonObject().getAsJsonArray("siteAssessments").size());
    assertTrue(other.get(0).getAsJsonObject().get("siteAssessmentsTruncated").getAsBoolean());
    assertEquals(1, run.getAsJsonArray("results").size());
    assertFalse(properties.get("securityVerified").getAsBoolean());
    assertFalse(properties.get("controlEvaluationComplete").getAsBoolean());
    assertFalse(properties.get("analysisComplete").getAsBoolean());
    assertEquals(
        "fixture-version",
        run.getAsJsonObject("tool").getAsJsonObject("driver").get("version").getAsString());
    assertTrue(docs.get("markdown").contains("必须人工复核：是"));
    assertTrue(docs.get("markdown").contains("调用点评估列表已截断"));
    assertTrue(docs.get("markdown").contains("控制复核 UNKNOWN"));
    assertTrue(docs.get("markdown").contains("控制复核列表已截断"));
    assertEquals(Unknowns.summarize(assessments), report.get("unknownSummary"));
  }

  @Test
  public void sarifWhitelistsNestedActionAndSiteMetadata() throws Exception {
    Map<String, Object> unknown = finding("BANK-IAM-001", "UNKNOWN", 12);
    Unknowns.set(
        unknown, Unknowns.INSUFFICIENT_EVIDENCE, "IDENTITY_TRUST_UNVERIFIED", "Confirm trust.");
    Map<String, Object> site = finding("BANK-IAM-001", "UNKNOWN", 40);
    unknown.put("siteAssessments", Arrays.asList(site));
    Unknowns.complete(Arrays.asList(unknown), Collections.<Map<String, Object>>emptyList());
    site.put("rawSource", "PRIVATE_SITE");
    items(site, "evidence").get(0).put("sourceText", "PRIVATE_EVIDENCE");
    items(unknown, "reviewActions").get(0).put("sourceText", "PRIVATE_ACTION");
    items(items(unknown, "reviewActions").get(0), "locations")
        .get(0)
        .put("rawSource", "PRIVATE_LOCATION");
    String sarif =
        Reports.write(
                report(Arrays.asList(unknown)), temporary.newFolder("safe").toPath().toRealPath())
            .get("sarif");
    assertFalse(sarif.contains("PRIVATE_"));
    assertTrue(sarif.contains("Controlled evidence"));
  }

  private static Map<String, Object> report(List<Map<String, Object>> assessments) {
    return Findings.map(
        "scanId",
        "review-fixture",
        "createdAt",
        "2026-10-15T00:00:00Z",
        "ruleSetVersion",
        "fixture",
        "sourceDigest",
        "fixture",
        "gateDecision",
        "REVIEW",
        "policy",
        Findings.map("profile", "bank-all"),
        "project",
        Findings.map(
            "languages",
            Arrays.asList("Java"),
            "aiProtocols",
            Collections.emptyList(),
            "customGatewayMethods",
            0),
        "runtime",
        Findings.map(
            "javaVersion", System.getProperty("java.version"), "scannerVersion", "fixture-version"),
        "assessments",
        assessments,
        "diagnostics",
        new ArrayList<Map<String, Object>>(),
        "unknownSummary",
        Unknowns.summarize(assessments));
  }
}
