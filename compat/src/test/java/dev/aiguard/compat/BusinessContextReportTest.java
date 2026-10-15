package dev.aiguard.compat;

import static org.junit.Assert.*;

import com.google.gson.JsonObject;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class BusinessContextReportTest {
  @Rule public TemporaryFolder temporary = new TemporaryFolder();

  private Map<String, Object> finding(String disposition) {
    Map<String, Object> item =
        Findings.assessment(
            "BANK-GUARD-001",
            "L7",
            disposition,
            "HIGH",
            "Synthetic context",
            "Evidence only",
            "Review the scope",
            Collections.<Map<String, Object>>emptyList());
    item.put(
        "callContextSites",
        Arrays.asList(
            Findings.map(
                "callPath",
                "src/Entry.java",
                "callLine",
                3,
                "calleePath",
                "src/Worker.java",
                "calleeLine",
                8,
                "binding",
                "candidate",
                "parameterStates",
                Arrays.asList("trusted", "unknown"))));
    item.put("callContextSitesTruncated", false);
    item.put(
        "streamTimingSites",
        Arrays.asList(
            Findings.map(
                "path",
                "flow.py",
                "line",
                7,
                "checkPath",
                "flow.py",
                "checkLine",
                10,
                "ordering",
                "RELEASE_PRECEDES_MAPPED_CHECK",
                "valueBinding",
                "unknown",
                "assurance",
                "candidate",
                "failureMode",
                "open",
                "limits",
                Arrays.asList("Local boundary only."))));
    item.put("streamTimingSitesTruncated", false);
    return item;
  }

  private Map<String, String> write(Map<String, Object> item) throws Exception {
    Map<String, Object> report =
        Findings.map(
            "scanId",
            "context-fixture",
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
                "javaVersion", System.getProperty("java.version"), "scannerVersion", "fixture"),
            "assessments",
            Arrays.asList(item),
            "diagnostics",
            Collections.emptyList(),
            "unknownSummary",
            Unknowns.summarize(Arrays.asList(item)));
    return Reports.write(report, temporary.newFolder().toPath().toRealPath());
  }

  private JsonObject properties(String sarif) throws Exception {
    return Json.parse(sarif)
        .getAsJsonObject()
        .getAsJsonArray("runs")
        .get(0)
        .getAsJsonObject()
        .getAsJsonObject("properties");
  }

  @Test
  public void contextFactsRemainAvailableForEveryDispositionWithoutCertifyingSecurity()
      throws Exception {
    for (String disposition : Arrays.asList("UNKNOWN", "OBSERVED", "VIOLATED")) {
      Map<String, Object> item = finding(disposition);
      Object manual = item.get("manualReviewRequired");
      Map<String, String> docs = write(item);
      JsonObject props = properties(docs.get("sarif"));
      JsonObject exported =
          props.getAsJsonArray("contextAssessmentsDetails").get(0).getAsJsonObject();
      assertEquals(disposition, exported.get("disposition").getAsString());
      assertEquals(1, exported.getAsJsonArray("callContextSites").size());
      assertEquals(1, exported.getAsJsonArray("streamTimingSites").size());
      assertEquals(manual, item.get("manualReviewRequired"));
      assertFalse(props.get("securityVerified").getAsBoolean());
      assertFalse(props.get("controlEvaluationComplete").getAsBoolean());
      String markdown = decoded(docs.get("markdown"));
      assertTrue(markdown.contains("参数身份：[trusted, unknown]"));
      assertTrue(markdown.contains("RELEASE_PRECEDES_MAPPED_CHECK"));
      assertTrue(markdown.contains("时序限制：Local boundary only."));
    }
  }

  private String decoded(String text) {
    java.util.regex.Matcher matches = java.util.regex.Pattern.compile("&#([0-9]+);").matcher(text);
    StringBuffer out = new StringBuffer();
    while (matches.find())
      matches.appendReplacement(
          out,
          java.util.regex.Matcher.quoteReplacement(
              String.valueOf((char) Integer.parseInt(matches.group(1)))));
    matches.appendTail(out);
    return out.toString();
  }

  @Test
  @SuppressWarnings("unchecked")
  public void sarifContextAllowlistDoesNotPublishInternalSymbolsOrSourceValues() throws Exception {
    Map<String, Object> item = finding("UNKNOWN");
    for (String field : Arrays.asList("callContextSites", "streamTimingSites")) {
      Map<String, Object> site = ((List<Map<String, Object>>) item.get(field)).get(0);
      site.put("symbol", "PRIVATE_SYMBOL");
      site.put("sourceValue", "PRIVATE_VALUE");
    }
    String sarif = write(item).get("sarif");
    assertFalse(sarif.contains("PRIVATE_"));
    assertTrue(sarif.contains("src/Worker.java"));
    assertTrue(sarif.contains("candidate"));
  }

  @Test
  public void truncatedContextIsExplicitEvenWithoutRetainedSites() throws Exception {
    Map<String, Object> item = finding("OBSERVED");
    item.put("callContextSites", Collections.emptyList());
    item.put("streamTimingSites", Collections.emptyList());
    item.put("callContextSitesTruncated", true);
    item.put("streamTimingSitesTruncated", true);
    Map<String, String> docs = write(item);
    JsonObject detail =
        properties(docs.get("sarif"))
            .getAsJsonArray("contextAssessmentsDetails")
            .get(0)
            .getAsJsonObject();
    assertTrue(detail.get("callContextSitesTruncated").getAsBoolean());
    assertTrue(detail.get("streamTimingSitesTruncated").getAsBoolean());
    assertTrue(docs.get("markdown").contains("调用上下文列表已截断"));
    assertTrue(docs.get("markdown").contains("首包时序列表已截断"));
  }
}
