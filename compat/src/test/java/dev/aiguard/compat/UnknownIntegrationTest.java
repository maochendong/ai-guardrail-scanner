package dev.aiguard.compat;

import static org.junit.Assert.*;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class UnknownIntegrationTest {
  @Rule public TemporaryFolder temporary = new TemporaryFolder();

  private static final Cancel NEVER =
      new Cancel() {
        public void check() {}
      };

  private Path source(String name) throws Exception {
    Path root = temporary.newFolder(name).toPath().toRealPath();
    Files.write(
        root.resolve("Application.java"),
        "package fixture; class Application { String value() { return \"synthetic\"; } }"
            .getBytes(StandardCharsets.UTF_8));
    return root;
  }

  @SuppressWarnings("unchecked")
  private static List<Map<String, Object>> assessments(Map<String, Object> report) {
    return (List<Map<String, Object>>) report.get("assessments");
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> object(Map<String, Object> report, String key) {
    return (Map<String, Object>) report.get(key);
  }

  private static void assertSummaryMatchesReport(Map<String, Object> report) {
    assertEquals(Unknowns.summarize(assessments(report)), report.get("unknownSummary"));
    int sum = 0;
    for (Object value : object(report, "unknownSummary").values())
      sum += ((Number) value).intValue();
    assertEquals(Scanner.count(report, "UNKNOWN"), sum);
    assertTrue(assessments(report).size() <= 1000);
    for (Map<String, Object> assessment : assessments(report)) {
      assertTrue(((List<?>) assessment.get("evidence")).size() <= 16);
      if ("UNKNOWN".equals(assessment.get("disposition"))) {
        assertTrue(object(report, "unknownSummary").containsKey(assessment.get("unknownCategory")));
        assertFalse(((List<?>) assessment.get("unknownReasons")).isEmpty());
      }
    }
  }

  @Test
  public void scannerCompletesLegacyUnknownsAndCountsOnlyReturnedAssessments() throws Exception {
    Map<String, Object> report = new Scanner().scan(source("generic"), "generic", NEVER);
    assertSummaryMatchesReport(report);
    assertTrue(object(report, "mappingCoverage").isEmpty());
    for (Map<String, Object> assessment : assessments(report))
      if ("UNKNOWN".equals(assessment.get("disposition")))
        assertEquals(Unknowns.INSUFFICIENT_EVIDENCE, assessment.get("unknownCategory"));
  }

  @Test
  public void bankingCoverageAndUnknownReasonsSurviveAllReportFormats() throws Exception {
    Map<String, Object> report =
        new Scanner().scan(source("bank"), "bank", NEVER, BusinessPolicy.load("bank-all", null));
    assertSummaryMatchesReport(report);
    Map<String, Object> coverage = object(report, "mappingCoverage");
    for (String key :
        Arrays.asList(
            "contractDefinitions",
            "matchedDefinitions",
            "matchedCallSites",
            "matchedBoundarySites",
            "candidateCallSites",
            "argumentBindingFailures",
            "analyzedFunctions")) {
      assertTrue(key, coverage.get(key) instanceof Number);
      assertTrue(key, ((Number) coverage.get(key)).intValue() >= 0);
    }
    assertEquals(0, ((Number) coverage.get("contractDefinitions")).intValue());
    assertTrue(coverage.get("sourceDigestMatched") instanceof Boolean);
    Map<String, String> documents =
        Reports.write(report, temporary.newFolder("formats").toPath().toRealPath());
    JsonObject json = Json.parse(documents.get("json")).getAsJsonObject();
    JsonObject properties =
        Json.parse(documents.get("sarif"))
            .getAsJsonObject()
            .getAsJsonArray("runs")
            .get(0)
            .getAsJsonObject()
            .getAsJsonObject("properties");
    assertEquals(json.get("mappingCoverage"), properties.get("mappingCoverage"));
    assertEquals(json.get("unknownSummary"), properties.get("unknownSummary"));
    assertEquals(
        Scanner.count(report, "UNKNOWN"),
        properties.getAsJsonArray("unknownAssessmentsDetails").size());
    assertTrue(documents.get("markdown").contains("UNKNOWN 原因分类"));
  }

  @Test
  public void serviceStatusAndResultExposeIdenticalSummaryAndMappingCoverage() throws Exception {
    Path root = source("service");
    Path output = temporary.newFolder("service-output").toPath().toRealPath();
    ScanService service =
        new ScanService(Arrays.asList(root), output, BusinessPolicy.load("bank-all", null));
    try {
      Map<String, Object> state = service.start(root);
      String id = String.valueOf(state.get("scanId"));
      long deadline = System.nanoTime() + 10000000000L;
      while ("RUNNING".equals(state.get("state")) && System.nanoTime() < deadline) {
        Thread.sleep(5);
        state = service.status(id);
      }
      assertEquals(String.valueOf(state), "COMPLETED", state.get("state"));
      Map<String, Object> result = service.result(id, "json");
      assertEquals(state, result.get("status"));
      JsonObject report = Json.parse(String.valueOf(result.get("content"))).getAsJsonObject();
      assertEquals(
          Json.COMPACT.toJsonTree(state.get("unknownSummary")), report.get("unknownSummary"));
      assertEquals(
          Json.COMPACT.toJsonTree(state.get("mappingCoverage")), report.get("mappingCoverage"));
      int unknowns = 0;
      for (JsonElement assessment : report.getAsJsonArray("assessments"))
        if ("UNKNOWN".equals(assessment.getAsJsonObject().get("disposition").getAsString()))
          unknowns++;
      assertEquals(unknowns, state.get("unknowns"));
    } finally {
      service.close();
    }
  }
}
