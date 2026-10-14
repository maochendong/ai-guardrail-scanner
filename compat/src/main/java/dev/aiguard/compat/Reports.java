package dev.aiguard.compat;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

public final class Reports {
  private static final String[] DOMAINS = {"L1", "L2", "L3", "L4", "L5", "L6", "L7"};
  private static final String[] STATES = {"VIOLATED", "OBSERVED", "UNKNOWN", "NOT_APPLICABLE"};

  private Reports() {}

  public static Map<String, String> write(Map<String, Object> report, Path directory)
      throws IOException {
    Path target = directory.toAbsolutePath().normalize();
    PathPolicy.rejectLinks(target);
    Files.createDirectories(target);
    PathPolicy.rejectLinks(target);
    try (DirectoryStream<Path> entries = Files.newDirectoryStream(target)) {
      if (entries.iterator().hasNext()) throw new IOException("REPORT_DIRECTORY_NOT_EMPTY");
    }
    Map<String, String> documents = new LinkedHashMap<String, String>();
    documents.put("json", Json.PRETTY.toJson(report) + "\n");
    documents.put("markdown", markdown(report));
    documents.put("sarif", Json.PRETTY.toJson(sarif(report)) + "\n");
    for (Map.Entry<String, String> document : documents.entrySet()) {
      byte[] bytes = document.getValue().getBytes(StandardCharsets.UTF_8);
      if (bytes.length > 16 * 1024 * 1024) throw new IOException("REPORT_TOO_LARGE");
      PathPolicy.rejectLinks(target);
      Path temporary = Files.createTempFile(target, ".guardrail-", ".tmp");
      try {
        Files.write(temporary, bytes);
        Files.createLink(target.resolve(fileName(document.getKey())), temporary);
      } finally {
        Files.deleteIfExists(temporary);
      }
    }
    return Collections.unmodifiableMap(documents);
  }

  public static String fileName(String format) {
    if ("json".equals(format)) return "report.json";
    if ("markdown".equals(format)) return "report.md";
    if ("sarif".equals(format)) return "results.sarif";
    throw new IllegalArgumentException("INVALID_FORMAT");
  }

  @SuppressWarnings("unchecked")
  private static List<Map<String, Object>> list(Map<String, Object> report, String key) {
    return (List<Map<String, Object>>) report.get(key);
  }

  @SuppressWarnings("unchecked")
  private static String markdown(Map<String, Object> report) {
    StringBuilder out =
        new StringBuilder("# AI 安全围栏静态审计\n\n本报告提供静态证据，不构成安全认证。OBSERVED 不表示安全通过；零违规也不表示安全。\n\n");
    for (String key :
        Arrays.asList(
            "scanId", "createdAt", "ruleSetVersion", "sourceDigest", "gateDecision", "policy"))
      out.append("- ").append(key).append("：").append(escape(report.get(key))).append('\n');
    Map<String, Object> project = (Map<String, Object>) report.get("project");
    Map<String, Object> runtime = (Map<String, Object>) report.get("runtime");
    out.append("- 运行 Java：").append(escape(runtime.get("javaVersion"))).append("；最低运行要求：1.7\n");
    out.append("- 源码语言：")
        .append(escape(project.get("languages")))
        .append("；AI 协议：")
        .append(escape(project.get("aiProtocols")))
        .append('\n');
    out.append("- 自定义网关边界：")
        .append(project.get("customGatewayMethods"))
        .append("；分析完整性：**不完整，必须检查诊断与未评估项**\n\n");
    out.append(
        "| 控制域 | VIOLATED | OBSERVED | UNKNOWN | NOT_APPLICABLE |\n"
            + "| --- | ---: | ---: | ---: | ---: |\n");
    for (String domain : DOMAINS) {
      out.append("| ").append(domain);
      for (String state : STATES) {
        int count = 0;
        for (Map<String, Object> a : list(report, "assessments"))
          if (domain.equals(a.get("domain")) && state.equals(a.get("disposition"))) count++;
        out.append(" | ").append(count);
      }
      out.append(" |\n");
    }
    out.append("\n## 诊断及未评估范围\n\n");
    for (Map<String, Object> d : list(report, "diagnostics"))
      out.append("- ")
          .append(escape(d.get("code")))
          .append(" · ")
          .append(escape(d.get("path")))
          .append("：")
          .append(escape(d.get("message")))
          .append('\n');
    out.append("\n## 规则证据\n\n");
    for (Map<String, Object> a : list(report, "assessments")) {
      out.append("### ")
          .append(escape(a.get("ruleId")))
          .append(" · ")
          .append(escape(a.get("title")))
          .append("\n\n状态：")
          .append(escape(a.get("disposition")))
          .append("；控制域：")
          .append(escape(a.get("domain")))
          .append("；严重度：")
          .append(escape(a.get("severity")))
          .append("。\n\n")
          .append(escape(a.get("explanation")))
          .append("\n\n建议：")
          .append(escape(a.get("recommendation")))
          .append("\n\n");
      for (Map<String, Object> e : list(a, "evidence"))
        out.append("- ")
            .append(escape(e.get("path")))
            .append(" 第 ")
            .append(e.get("line"))
            .append(" 行：")
            .append(escape(e.get("detail")))
            .append('\n');
      Object limits = a.get("limitations");
      if (limits instanceof List<?>)
        for (Object limit : (List<?>) limits)
          out.append("- 限制：").append(escape(limit)).append('\n');
      out.append('\n');
    }
    return out.toString();
  }

  private static Map<String, Object> sarif(Map<String, Object> report) {
    Map<String, Integer> indexes = new LinkedHashMap<String, Integer>();
    List<Map<String, Object>> rules = new ArrayList<Map<String, Object>>();
    List<Map<String, Object>> results = new ArrayList<Map<String, Object>>();
    Map<String, Object> coverage = new LinkedHashMap<String, Object>();
    List<String> unassessed = new ArrayList<String>();
    for (String domain : DOMAINS) {
      Map<String, Object> counts = new LinkedHashMap<String, Object>();
      int total = 0;
      for (String state : STATES) {
        int count = 0;
        for (Map<String, Object> a : list(report, "assessments"))
          if (domain.equals(a.get("domain")) && state.equals(a.get("disposition"))) count++;
        counts.put(state, count);
        total += count;
      }
      coverage.put(domain, counts);
      if (total == 0) unassessed.add(domain);
    }
    for (Map<String, Object> a : list(report, "assessments")) {
      String id = String.valueOf(a.get("ruleId"));
      if (!indexes.containsKey(id)) {
        indexes.put(id, rules.size());
        rules.add(
            Findings.map(
                "id",
                id,
                "shortDescription",
                Findings.map("text", a.get("title")),
                "fullDescription",
                Findings.map("text", a.get("explanation")),
                "help",
                Findings.map("text", a.get("recommendation")),
                "properties",
                Findings.map("domain", a.get("domain"))));
      }
      if (!"VIOLATED".equals(a.get("disposition"))) continue;
      List<Map<String, Object>> locations = new ArrayList<Map<String, Object>>();
      for (Map<String, Object> e : list(a, "evidence")) {
        String uri = relativeUri(String.valueOf(e.get("path")));
        if (uri != null)
          locations.add(
              Findings.map(
                  "physicalLocation",
                  Findings.map(
                      "artifactLocation",
                      Findings.map("uri", uri),
                      "region",
                      Findings.map("startLine", e.get("line"))),
                  "message",
                  Findings.map("text", e.get("detail"))));
      }
      Map<String, Object> finding =
          Findings.map(
              "ruleId",
              id,
              "ruleIndex",
              indexes.get(id),
              "level",
              "HIGH".equals(a.get("severity")) ? "error" : "warning",
              "message",
              Findings.map("text", a.get("explanation")),
              "properties",
              Findings.map(
                  "disposition",
                  a.get("disposition"),
                  "domain",
                  a.get("domain"),
                  "limitations",
                  a.get("limitations"),
                  "omittedLocations",
                  list(a, "evidence").size() - locations.size()));
      if (!locations.isEmpty()) finding.put("locations", locations);
      results.add(finding);
    }
    List<Map<String, Object>> notifications = new ArrayList<Map<String, Object>>();
    for (Map<String, Object> d : list(report, "diagnostics"))
      notifications.add(
          Findings.map(
              "descriptor",
              Findings.map("id", d.get("code")),
              "level",
              "warning",
              "message",
              Findings.map("text", d.get("message")),
              "properties",
              Findings.map("path", d.get("path"))));
    Map<String, Object> properties =
        Findings.map(
            "scanId",
            report.get("scanId"),
            "sourceDigest",
            report.get("sourceDigest"),
            "project",
            report.get("project"),
            "runtime",
            report.get("runtime"),
            "policy",
            report.get("policy"),
            "gateDecision",
            report.get("gateDecision"),
            "analysisComplete",
            false,
            "controlEvaluationComplete",
            false,
            "securityVerified",
            false,
            "unknownAssessments",
            Scanner.count(report, "UNKNOWN"),
            "coverage",
            coverage,
            "unassessedDomains",
            unassessed);
    Map<String, Object> run =
        Findings.map(
            "tool",
            Findings.map(
                "driver",
                Findings.map("name", "ai-guardrail-scanner", "version", "0.4.0", "rules", rules)),
            "results",
            results,
            "properties",
            properties,
            "invocations",
            Arrays.asList(
                Findings.map(
                    "executionSuccessful", false, "toolExecutionNotifications", notifications)));
    return Findings.map(
        "version",
        "2.1.0",
        "$schema",
        "https://json.schemastore.org/sarif-2.1.0.json",
        "runs",
        Arrays.asList(run));
  }

  private static String relativeUri(String path) {
    if (path.length() == 0
        || path.startsWith("/")
        || path.contains("\\")
        || path.matches("^[A-Za-z]:.*")) return null;
    for (String part : path.split("/")) if (part.equals("..")) return null;
    try {
      return new URI(null, null, path.indexOf(':') >= 0 ? "./" + path : path, null).toASCIIString();
    } catch (URISyntaxException error) {
      return null;
    }
  }

  private static String escape(Object input) {
    String text = input == null ? "未确定" : String.valueOf(input);
    StringBuilder out = new StringBuilder();
    for (int i = 0; i < text.length(); i++) {
      char c = text.charAt(i);
      if (Character.isISOControl(c)
          || c >= '\u202a' && c <= '\u202e'
          || c >= '\u2066' && c <= '\u2069') out.append(' ');
      else if (c >= '!' && c <= '/'
          || c >= ':' && c <= '@'
          || c >= '[' && c <= '`'
          || c >= '{' && c <= '~') out.append("&#").append((int) c).append(';');
      else out.append(c);
    }
    return out.toString();
  }
}
