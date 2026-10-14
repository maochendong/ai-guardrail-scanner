package dev.aiguard.compat;

import static org.junit.Assert.*;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class UnknownsTest {
  @Rule public TemporaryFolder temporary = new TemporaryFolder();

  private static Map<String, Object> finding(String id, String disposition, boolean located) {
    return Findings.assessment(
        id,
        "L2",
        disposition,
        "HIGH",
        "Synthetic control",
        "Static control evidence is incomplete.",
        "Verify this control.",
        located
            ? Arrays.asList(Findings.evidence("app/Flow.java", 17, "Mapped local operation."))
            : Collections.<Map<String, Object>>emptyList());
  }

  @SuppressWarnings("unchecked")
  private static List<Map<String, Object>> reasons(Map<String, Object> finding) {
    return (List<Map<String, Object>>) finding.get("unknownReasons");
  }

  @Test
  public void unknownDefaultsDistinguishUnlocatedFromUnverifiedEvidence() {
    Map<String, Object> empty = finding("A", "UNKNOWN", false);
    Map<String, Object> located = finding("B", "UNKNOWN", true);
    assertEquals(Unknowns.INSUFFICIENT_EVIDENCE, empty.get("unknownCategory"));
    assertEquals("NO_LOCATED_EVIDENCE", reasons(empty).get(0).get("code"));
    assertEquals("CONTROL_SEMANTICS_UNVERIFIED", reasons(located).get(0).get("code"));
  }

  @Test
  public void explicitReasonReplacesDefaultAndDeduplicatesWithoutLosingOtherCauses() {
    Map<String, Object> unknown = finding("A", "UNKNOWN", false);
    Unknowns.set(unknown, Unknowns.MISSING_MAPPING, "IDENTITY_SOURCE_UNMAPPED", "Map identity.");
    Unknowns.set(unknown, Unknowns.MISSING_MAPPING, "IDENTITY_SOURCE_UNMAPPED", "Map identity.");
    Unknowns.set(unknown, Unknowns.MISSING_MAPPING, "ACL_CHECK_UNMAPPED", "Map ACL.");
    Unknowns.set(unknown, Unknowns.UNSUPPORTED, "CALLBACK_FLOW", "Callback flow is unavailable.");
    assertEquals(Unknowns.MISSING_MAPPING, unknown.get("unknownCategory"));
    assertEquals(3, reasons(unknown).size());
    assertFalse(String.valueOf(reasons(unknown)).contains("NO_LOCATED_EVIDENCE"));
    Unknowns.complete(Arrays.asList(unknown), Collections.<Map<String, Object>>emptyList());
    assertEquals(3, reasons(unknown).size());
  }

  @Test
  public void nonUnknownFindingsNeverAcquireUnknownMetadata() {
    for (String disposition : Arrays.asList("OBSERVED", "VIOLATED", "NOT_APPLICABLE")) {
      Map<String, Object> item = finding("A", disposition, true);
      Unknowns.set(item, Unknowns.UNSUPPORTED, "UNSUPPORTED_FLOW", "Unsupported flow.");
      Unknowns.complete(Arrays.asList(item), Collections.<Map<String, Object>>emptyList());
      assertFalse(item.containsKey("unknownCategory"));
      assertFalse(item.containsKey("unknownReasons"));
    }
  }

  @Test
  public void unknownCategoriesRejectTypos() {
    try {
      Unknowns.set(finding("A", "UNKNOWN", false), "PASS", "X", "Incorrect category.");
      fail("Unknown classification accepted an invalid category.");
    } catch (IllegalArgumentException expected) {
      assertEquals("INVALID_UNKNOWN_REASON", expected.getMessage());
    }
  }

  @Test
  public void summaryCountsPrimaryCategoriesOnceAndRetainsLegacyUnknowns() {
    Map<String, Object> a = finding("A", "UNKNOWN", false);
    Map<String, Object> b = finding("B", "UNKNOWN", true);
    Map<String, Object> legacy = Findings.map("disposition", "UNKNOWN");
    Unknowns.set(a, Unknowns.MISSING_MAPPING, "SOURCE_UNMAPPED", "Map source.");
    Unknowns.set(a, Unknowns.UNSUPPORTED, "DYNAMIC_CALL", "Resolve dynamic target.");
    Unknowns.set(b, Unknowns.UNSUPPORTED, "LOOP_FLOW", "Loop flow is unavailable.");
    Map<String, Object> summary =
        Unknowns.summarize(Arrays.asList(a, b, legacy, finding("C", "OBSERVED", true)));
    assertEquals(3, summary.size());
    assertEquals(1, summary.get(Unknowns.MISSING_MAPPING));
    assertEquals(1, summary.get(Unknowns.INSUFFICIENT_EVIDENCE));
    assertEquals(1, summary.get(Unknowns.UNSUPPORTED));
  }

  @Test
  public void globalDiagnosticsDoNotReclassifyUnrelatedRuleEvidence() {
    Map<String, Object> item = finding("A", "UNKNOWN", true);
    List<Map<String, Object>> diagnostics =
        Arrays.asList(
            Findings.diagnostic("PYTHON_FSTRING_BOUNDARY", "other.py", "Unrelated f-string."),
            Findings.diagnostic("BANK_POLICY_UNMAPPED", "", "No bank contracts."),
            Findings.diagnostic("STATIC_ONLY", "", "Runtime behavior is unverified."));
    Unknowns.complete(Arrays.asList(item), diagnostics);
    assertEquals(Unknowns.INSUFFICIENT_EVIDENCE, item.get("unknownCategory"));
    assertEquals(1, reasons(item).size());
    assertEquals(Unknowns.UNSUPPORTED, diagnostics.get(0).get("category"));
    assertEquals(Unknowns.MISSING_MAPPING, diagnostics.get(1).get("category"));
    assertEquals(Unknowns.INSUFFICIENT_EVIDENCE, diagnostics.get(2).get("category"));
  }

  @Test
  public void parsingBudgetAndSkippedDiagnosticsAreUnsupported() {
    for (String code :
        Arrays.asList(
            "JAVA_PARSE_ERROR",
            "PYTHON_PARSE_FAILED",
            "BANK_JAVA_PARSE_INCOMPLETE",
            "BANK_PYTHON_ANALYSIS_LIMIT",
            "SYMLINK_SKIPPED",
            "READ_ERROR",
            "BANK_FLOW_INCOMPLETE")) {
      Map<String, Object> diagnostic = Findings.diagnostic(code, "source", "Controlled detail.");
      Unknowns.complete(Collections.<Map<String, Object>>emptyList(), Arrays.asList(diagnostic));
      assertEquals(code, Unknowns.UNSUPPORTED, diagnostic.get("category"));
    }
  }

  @Test
  public void allFormatsPreserveUnknownReasonsAndCountsWithoutCreatingViolationResults()
      throws Exception {
    Map<String, Object> a = finding("A", "UNKNOWN", true);
    Map<String, Object> b = finding("B", "UNKNOWN", false);
    Map<String, Object> c = finding("C", "UNKNOWN", true);
    Unknowns.set(a, Unknowns.MISSING_MAPPING, "SOURCE_UNMAPPED", "Identity source is unmapped.");
    Unknowns.set(c, Unknowns.UNSUPPORTED, "CALLBACK_FLOW", "Callback flow is unavailable.");
    List<Map<String, Object>> assessments = Arrays.asList(a, b, c);
    Map<String, Object> report = report(assessments);
    Path output = temporary.newFolder("formats").toPath().toRealPath();
    Map<String, String> documents = Reports.write(report, output);
    for (String format : Arrays.asList("json", "markdown", "sarif")) {
      String text = documents.get(format);
      assertEquals(
          text,
          new String(
              Files.readAllBytes(output.resolve(Reports.fileName(format))),
              StandardCharsets.UTF_8));
      assertTrue(format, text.contains("Identity source is unmapped"));
      assertTrue(format, text.contains("Callback flow is unavailable"));
    }
    JsonObject json = Json.parse(documents.get("json")).getAsJsonObject();
    assertEquals(1, json.getAsJsonObject("unknownSummary").get("MISSING_MAPPING").getAsInt());
    JsonObject run =
        Json.parse(documents.get("sarif"))
            .getAsJsonObject()
            .getAsJsonArray("runs")
            .get(0)
            .getAsJsonObject();
    assertEquals(0, run.getAsJsonArray("results").size());
    JsonObject properties = run.getAsJsonObject("properties");
    assertEquals(3, properties.get("unknownAssessments").getAsInt());
    assertEquals(json.get("unknownSummary"), properties.get("unknownSummary"));
    JsonArray details = properties.getAsJsonArray("unknownAssessmentsDetails");
    assertEquals(3, details.size());
    assertEquals("A", details.get(0).getAsJsonObject().get("ruleId").getAsString());
    assertEquals(
        17,
        details
            .get(0)
            .getAsJsonObject()
            .getAsJsonArray("evidence")
            .get(0)
            .getAsJsonObject()
            .get("line")
            .getAsInt());
    assertEquals(
        "MISSING_MAPPING",
        details
            .get(0)
            .getAsJsonObject()
            .getAsJsonArray("unknownReasons")
            .get(0)
            .getAsJsonObject()
            .get("category")
            .getAsString());
  }

  @Test
  @SuppressWarnings("unchecked")
  public void sarifUnknownDetailsExportOnlyControlledFields() throws Exception {
    Map<String, Object> unknown = finding("A", "UNKNOWN", true);
    unknown.put("rawSource", "PRIVATE_ANALYSIS_VALUE");
    ((List<Map<String, Object>>) unknown.get("evidence"))
        .get(0)
        .put("sourceText", "PRIVATE_EVIDENCE_VALUE");
    Map<String, String> documents =
        Reports.write(
            report(Arrays.asList(unknown)), temporary.newFolder("filtered").toPath().toRealPath());
    assertFalse(documents.get("sarif").contains("PRIVATE_ANALYSIS_VALUE"));
    assertFalse(documents.get("sarif").contains("PRIVATE_EVIDENCE_VALUE"));
    assertTrue(documents.get("sarif").contains("Mapped local operation."));
  }

  private static Map<String, Object> report(List<Map<String, Object>> assessments) {
    List<Map<String, Object>> diagnostics = new ArrayList<Map<String, Object>>();
    Unknowns.complete(assessments, diagnostics);
    return Findings.map(
        "scanId",
        "unknown-fixture",
        "createdAt",
        "2026-10-14T00:00:00Z",
        "ruleSetVersion",
        "synthetic",
        "sourceDigest",
        "synthetic",
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
        Findings.map("javaVersion", System.getProperty("java.version")),
        "assessments",
        assessments,
        "diagnostics",
        diagnostics,
        "unknownSummary",
        Unknowns.summarize(assessments));
  }
}
