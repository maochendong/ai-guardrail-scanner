package dev.aiguard.compat;

import static org.junit.Assert.*;

import com.google.gson.JsonObject;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/** Report provenance survives every disposition; Markdown/SARIF expose selected metadata only. */
public class GenericSemanticReportTest {
  @Rule public TemporaryFolder temporary = new TemporaryFolder();

  @Test
  public void allSemanticDispositionsExportProvenanceAndLocalScope() throws Exception {
    for (String state : Arrays.asList("OBSERVED", "VIOLATED", "UNKNOWN")) {
      // Injected private fields test the Markdown/SARIF projection whitelist. JSON intentionally
      // serializes the full engine report; production origins have a fixed, validated field set.
      Map<String, Object> finding =
          Findings.assessment(
              "AI-PY-005",
              "L5",
              state,
              "HIGH",
              "Mapped output",
              "Local evidence",
              "Verify runtime",
              Arrays.asList(Findings.evidence("flow.py", 12, "Same mapped value")));
      Map<String, Object> site =
          Findings.map(
              "ruleId",
              "AI-PY-005",
              "path",
              "flow.py",
              "line",
              12,
              "disposition",
              state,
              "evidence",
              finding.get("evidence"),
              "symbol",
              "private.Port#publish",
              "siteId",
              "internal-private-site");
      finding.put("siteAssessments", Arrays.asList(site));
      finding.put("siteAssessmentsTruncated", false);
      finding.put(
          "semanticOrigin",
          Findings.map(
              "kind",
              "external-api-contract",
              "engine",
              "BusinessAnalysis",
              "policyDigest",
              "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
              "sourceRuleIds",
              Arrays.asList("BANK-GUARD-001"),
              "language",
              "python",
              "privateContractBody",
              "NEVER_EXPORT_THIS"));
      finding.put("semanticScope", "MAPPED_LOCAL_SITES_ONLY");
      finding.put("semanticCoverageIncomplete", true);
      Unknowns.complete(Arrays.asList(finding), Collections.<Map<String, Object>>emptyList());
      Map<String, Object> report =
          new Scanner()
              .scan(
                  temporary.newFolder().toPath().toRealPath(),
                  "semantic-report",
                  new Cancel() {
                    public void check() {}
                  });
      report.put("assessments", Arrays.asList(finding));
      Map<String, String> documents =
          Reports.write(report, temporary.newFolder().toPath().toRealPath());
      String markdown = documents.get("markdown");
      assertTrue(markdown.contains("语义来源：external"));
      assertTrue(markdown.contains("BusinessAnalysis"));
      assertTrue(markdown.contains("覆盖仍不完整：true"));
      assertFalse(markdown.contains("NEVER_EXPORT_THIS"));
      JsonObject properties =
          Json.parse(documents.get("sarif"))
              .getAsJsonObject()
              .getAsJsonArray("runs")
              .get(0)
              .getAsJsonObject()
              .getAsJsonObject("properties");
      assertEquals(1, properties.getAsJsonArray("semanticAssessmentsDetails").size());
      JsonObject exported =
          properties.getAsJsonArray("semanticAssessmentsDetails").get(0).getAsJsonObject();
      assertEquals(state, exported.get("disposition").getAsString());
      assertEquals("MAPPED_LOCAL_SITES_ONLY", exported.get("semanticScope").getAsString());
      assertEquals(5, exported.getAsJsonObject("semanticOrigin").entrySet().size());
      assertFalse(exported.toString().contains("privateContractBody"));
      assertFalse(exported.toString().contains("private.Port"));
      assertFalse(exported.toString().contains("internal-private-site"));
    }
  }
}
