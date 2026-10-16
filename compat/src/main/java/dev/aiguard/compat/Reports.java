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
    try (Prepared prepared =
        prepare(
            report,
            directory,
            new Cancel() {
              public void check() {}
            })) {
      prepared.publish();
      return prepared.documents;
    }
  }

  /** Prepare outside the task lock; only publish after cancellation and quota checks. */
  static Prepared prepare(Map<String, Object> report, Path directory, Cancel cancel)
      throws IOException {
    cancel.check();
    Map<String, String> documents = new LinkedHashMap<String, String>();
    documents.put("json", Json.PRETTY.toJson(report) + "\n");
    cancel.check();
    documents.put("markdown", markdown(report));
    cancel.check();
    documents.put("sarif", Json.PRETTY.toJson(sarif(report)) + "\n");
    cancel.check();
    Path target = directory.toAbsolutePath().normalize();
    Path parent = target.getParent();
    if (parent == null) throw new IOException("INVALID_REPORT_DIRECTORY");
    PathPolicy.rejectLinks(target);
    Files.createDirectories(parent);
    PathPolicy.rejectLinks(target);
    Prepared prepared =
        new Prepared(target, Files.createTempDirectory(parent, ".guardrail-"), documents);
    boolean ready = false;
    try {
      for (Map.Entry<String, String> document : documents.entrySet()) {
        cancel.check();
        byte[] bytes = document.getValue().getBytes(StandardCharsets.UTF_8);
        if (bytes.length > 16 * 1024 * 1024) throw new IOException("REPORT_TOO_LARGE");
        PathPolicy.rejectLinks(prepared.staging);
        Files.write(
            prepared.staging.resolve(fileName(document.getKey())),
            bytes,
            StandardOpenOption.CREATE_NEW,
            StandardOpenOption.WRITE);
        prepared.documentBytes.put(document.getKey(), bytes.length);
        prepared.totalBytes += bytes.length;
      }
      cancel.check();
      ready = true;
      return prepared;
    } finally {
      if (!ready) prepared.close();
    }
  }

  static final class Prepared implements AutoCloseable {
    final Map<String, String> documents;
    final Map<String, Integer> documentBytes = new LinkedHashMap<String, Integer>();
    long totalBytes;
    private final Path target, staging;

    Prepared(Path target, Path staging, Map<String, String> documents) {
      this.target = target;
      this.staging = staging;
      this.documents = Collections.unmodifiableMap(documents);
    }

    void publish() throws IOException {
      PathPolicy.rejectLinks(target);
      Files.createDirectories(target);
      PathPolicy.rejectLinks(target);
      try (DirectoryStream<Path> entries = Files.newDirectoryStream(target)) {
        if (entries.iterator().hasNext()) throw new IOException("REPORT_DIRECTORY_NOT_EMPTY");
      }
      for (String format : documents.keySet()) {
        PathPolicy.rejectLinks(target);
        Path source = staging.resolve(fileName(format));
        PathPolicy.rejectLinks(source);
        // Unlike ATOMIC_MOVE, a hard link never replaces an existing destination.
        Files.createLink(target.resolve(fileName(format)), source);
      }
    }

    public void close() throws IOException {
      // Only remove our known files; never traverse or recursively delete an unexpected entry.
      for (String format : documents.keySet()) {
        PathPolicy.rejectLinks(staging);
        Files.deleteIfExists(staging.resolve(fileName(format)));
      }
      PathPolicy.rejectLinks(staging);
      Files.deleteIfExists(staging);
    }
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
            "scanId",
            "createdAt",
            "ruleSetVersion",
            "sourceDigest",
            "gateDecision",
            "policy",
            "mappingCoverage"))
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
    Map<String, Object> unknownSummary = Unknowns.summarize(list(report, "assessments"));
    out.append("\n## UNKNOWN 原因分类\n\n")
        .append("每条 UNKNOWN 按首要原因计数一次；同一项的其他原因列在规则证据中。\n\n")
        .append("| 分类 | 数量 |\n| --- | ---: |\n");
    for (Map.Entry<String, Object> entry : unknownSummary.entrySet())
      out.append("| ")
          .append(escape(categoryLabel(entry.getKey())))
          .append(" | ")
          .append(entry.getValue())
          .append(" |\n");
    out.append("\n复核动作区分补充映射、扩展分析、定位证据与人工确认。")
        .append("仅 CONFIRM_SCOPE / VERIFY_RUNTIME 标为必须人工复核；OPEN 表示尚未提供所需证据，不改变规则结论。\n");
    out.append("\n## 诊断及未评估范围\n\n");
    for (Map<String, Object> d : list(report, "diagnostics"))
      out.append("- ")
          .append(escape(d.get("code")))
          .append(" [")
          .append(escape(categoryLabel(String.valueOf(d.get("category")))))
          .append(']')
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
      if ("UNKNOWN".equals(a.get("disposition"))) {
        out.append("UNKNOWN 分类：")
            .append(escape(categoryLabel(String.valueOf(a.get("unknownCategory")))))
            .append("。\n\n");
        Object reasons = a.get("unknownReasons");
        if (reasons instanceof List<?>)
          for (Map<String, Object> reason : list(a, "unknownReasons"))
            out.append("- 原因 ")
                .append(escape(reason.get("code")))
                .append(" [")
                .append(escape(categoryLabel(String.valueOf(reason.get("category")))))
                .append("]：")
                .append(escape(reason.get("explanation")))
                .append('\n');
      }
      if (a.get("semanticOrigin") instanceof Map<?, ?>) {
        Map<String, Object> origin = semanticOrigin(a);
        out.append("语义来源：")
            .append(escape(origin.get("kind")))
            .append("；引擎：")
            .append(escape(origin.get("engine")))
            .append("；策略摘要：")
            .append(escape(origin.get("policyDigest")))
            .append("；来源规则：")
            .append(escape(origin.get("sourceRuleIds")))
            .append("；语言：")
            .append(escape(origin.get("language")))
            .append("。\n")
            .append("语义范围：")
            .append(escape(a.get("semanticScope")))
            .append("；覆盖仍不完整：")
            .append(escape(a.get("semanticCoverageIncomplete")))
            .append("。局部语义证据不覆盖其他路径。\n\n");
      }
      appendReview(out, a, "");
      if (a.get("siteAssessments") instanceof List<?>) {
        for (Map<String, Object> site : list(a, "siteAssessments")) {
          if (!"UNKNOWN".equals(site.get("disposition"))) continue;
          out.append("\n调用点 UNKNOWN：")
              .append(escape(site.get("path")))
              .append(" 第 ")
              .append(escape(site.get("line")))
              .append(" 行\n");
          if (site.get("unknownReasons") instanceof List<?>)
            for (Map<String, Object> reason : list(site, "unknownReasons"))
              out.append("- 调用点原因 ")
                  .append(escape(reason.get("code")))
                  .append("：")
                  .append(escape(reason.get("explanation")))
                  .append('\n');
          appendReview(out, site, "调用点");
        }
        if (Boolean.TRUE.equals(a.get("siteAssessmentsTruncated")))
          out.append("- 限制：调用点评估列表已截断；本页复核动作未覆盖全部调用点。\n");
      }
      if (a.get("controlReviewSites") instanceof List<?>) {
        for (Map<String, Object> site : list(a, "controlReviewSites")) {
          out.append("\n控制复核 UNKNOWN：")
              .append(escape(site.get("path")))
              .append(" 第 ")
              .append(escape(site.get("line")))
              .append(" 行\n");
          for (Map<String, Object> reason : optionalList(site, "unknownReasons"))
            out.append("- 控制复核原因 ")
                .append(escape(reason.get("code")))
                .append("：")
                .append(escape(reason.get("explanation")))
                .append('\n');
          appendReview(out, site, "控制复核");
        }
        if (Boolean.TRUE.equals(a.get("controlReviewSitesTruncated")))
          out.append("- 限制：控制复核列表已截断；复核动作未覆盖全部控制调用。\n");
      }
      for (Map<String, Object> site : optionalList(a, "collectionReviewSites")) {
        out.append("\n集合复核 UNKNOWN：")
            .append(escape(site.get("path")))
            .append(" 第 ")
            .append(escape(site.get("line")))
            .append(" 行\n");
        for (String key : collectionFields())
          if (site.containsKey(key))
            out.append("- 集合关系 ")
                .append(key)
                .append("：")
                .append(escape(site.get(key)))
                .append('\n');
        for (Map<String, Object> reason : optionalList(site, "unknownReasons"))
          out.append("- 集合复核原因 ")
              .append(escape(reason.get("code")))
              .append("：")
              .append(escape(reason.get("explanation")))
              .append('\n');
        appendReview(out, site, "集合复核");
      }
      if (Boolean.TRUE.equals(a.get("collectionReviewSitesTruncated")))
        out.append("- 限制：集合复核列表已截断；未展示的集合关系仍须复核。\n");
      appendAnalysisContext(out, a);
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

  private static void appendAnalysisContext(StringBuilder out, Map<String, Object> assessment) {
    for (Map<String, Object> site : optionalList(assessment, "callContextSites"))
      out.append("\n调用上下文：")
          .append(escape(site.get("callPath")))
          .append(" 第 ")
          .append(escape(site.get("callLine")))
          .append(" 行 → ")
          .append(escape(site.get("calleePath")))
          .append(" 第 ")
          .append(escape(site.get("calleeLine")))
          .append(" 行；绑定：")
          .append(escape(site.get("binding")))
          .append("；参数身份：")
          .append(escape(site.get("parameterStates")))
          .append('\n');
    if (Boolean.TRUE.equals(assessment.get("callContextSitesTruncated")))
      out.append("- 限制：调用上下文列表已截断。\n");
    for (Map<String, Object> site : optionalList(assessment, "streamTimingSites")) {
      out.append("\n首包时序：")
          .append(escape(site.get("path")))
          .append(" 第 ")
          .append(escape(site.get("line")))
          .append(" 行；检查：")
          .append(escape(site.get("checkPath")))
          .append(" 第 ")
          .append(escape(site.get("checkLine")))
          .append(" 行；顺序：")
          .append(escape(site.get("ordering")))
          .append("；值绑定：")
          .append(escape(site.get("valueBinding")))
          .append("；资格：")
          .append(escape(site.get("assurance")))
          .append("；失败语义：")
          .append(escape(site.get("failureMode")))
          .append('\n');
      Object limits = site.get("limits");
      if (limits instanceof List<?>)
        for (Object limit : (List<?>) limits)
          out.append("- 时序限制：").append(escape(limit)).append('\n');
    }
    if (Boolean.TRUE.equals(assessment.get("streamTimingSitesTruncated")))
      out.append("- 限制：首包时序列表已截断。\n");
  }

  private static void appendReview(
      StringBuilder out, Map<String, Object> assessment, String prefix) {
    if (!(assessment.get("reviewActions") instanceof List<?>)) return;
    out.append("\n")
        .append(prefix)
        .append("必须人工复核：")
        .append(Boolean.TRUE.equals(assessment.get("manualReviewRequired")) ? "是" : "否")
        .append("。\n");
    for (Map<String, Object> action : list(assessment, "reviewActions")) {
      out.append("- 复核动作 ")
          .append(escape(action.get("code")))
          .append(" [")
          .append(escape(action.get("kind")))
          .append(" / ")
          .append(escape(action.get("status")))
          .append("]；负责角色：")
          .append(escape(action.get("ownerRole")))
          .append("；原因：")
          .append(escape(action.get("reasonCodes")))
          .append('\n');
      if (action.get("requiredEvidence") instanceof List<?>)
        for (Object evidence : (List<?>) action.get("requiredEvidence"))
          out.append("  - 所需证据：").append(escape(evidence)).append('\n');
      if (action.get("locations") instanceof List<?>)
        for (Map<String, Object> location : list(action, "locations"))
          out.append("  - 定位：")
              .append(escape(location.get("path")))
              .append(" 第 ")
              .append(escape(location.get("line")))
              .append(" 行\n");
    }
  }

  private static Map<String, Object> sarif(Map<String, Object> report) {
    Map<String, Integer> indexes = new LinkedHashMap<String, Integer>();
    List<Map<String, Object>> rules = new ArrayList<Map<String, Object>>();
    List<Map<String, Object>> results = new ArrayList<Map<String, Object>>();
    List<Map<String, Object>> unknownDetails = new ArrayList<Map<String, Object>>();
    List<Map<String, Object>> otherReviewDetails = new ArrayList<Map<String, Object>>();
    List<Map<String, Object>> contextDetails = new ArrayList<Map<String, Object>>();
    List<Map<String, Object>> semanticDetails = new ArrayList<Map<String, Object>>();
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
      if (a.get("semanticOrigin") instanceof Map<?, ?>) semanticDetails.add(unknownDetail(a));
      if (!optionalList(a, "callContextSites").isEmpty()
          || !optionalList(a, "streamTimingSites").isEmpty()
          || Boolean.TRUE.equals(a.get("callContextSitesTruncated"))
          || Boolean.TRUE.equals(a.get("streamTimingSitesTruncated")))
        contextDetails.add(unknownDetail(a));
      if ("UNKNOWN".equals(a.get("disposition"))) unknownDetails.add(unknownDetail(a));
      else if (a.get("reviewActions") instanceof List<?> && !list(a, "reviewActions").isEmpty())
        otherReviewDetails.add(unknownDetail(a));
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
              Findings.map("path", d.get("path"), "category", d.get("category"))));
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
            "mappingCoverage",
            report.get("mappingCoverage"),
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
            "unknownSummary",
            Unknowns.summarize(list(report, "assessments")),
            "unknownAssessmentsDetails",
            unknownDetails,
            "reviewAssessmentsDetails",
            otherReviewDetails,
            "contextAssessmentsDetails",
            contextDetails,
            "semanticAssessmentsDetails",
            semanticDetails,
            "coverage",
            coverage,
            "unassessedDomains",
            unassessed);
    Map<String, Object> run =
        Findings.map(
            "tool",
            Findings.map(
                "driver",
                Findings.map(
                    "name",
                    "ai-guardrail-scanner",
                    "version",
                    scannerVersion(report),
                    "rules",
                    rules)),
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

  private static String categoryLabel(String category) {
    if (Unknowns.MISSING_MAPPING.equals(category)) return "MISSING_MAPPING（缺少映射）";
    if (Unknowns.UNSUPPORTED.equals(category)) return "UNSUPPORTED（暂不支持）";
    return "INSUFFICIENT_EVIDENCE（证据不足）";
  }

  private static String scannerVersion(Map<String, Object> report) {
    Object runtime = report.get("runtime");
    if (runtime instanceof Map<?, ?>) {
      Object version = ((Map<?, ?>) runtime).get("scannerVersion");
      if (version instanceof String && !((String) version).isEmpty()) return (String) version;
    }
    return "unknown";
  }

  /** Only report metadata is exported; analysis internals and target source values are excluded. */
  private static Map<String, Object> unknownDetail(Map<String, Object> assessment) {
    Map<String, Object> out = new LinkedHashMap<String, Object>();
    for (String key :
        Arrays.asList(
            "ruleId",
            "domain",
            "disposition",
            "severity",
            "title",
            "explanation",
            "recommendation",
            "limitations",
            "profile",
            "mappedPathOutcomes",
            "unknownCategory",
            "manualReviewRequired",
            "controlReviewSitesTruncated",
            "siteAssessmentsTruncated",
            "callContextSitesTruncated",
            "streamTimingSitesTruncated",
            "collectionReviewSitesTruncated",
            "semanticScope",
            "semanticCoverageIncomplete"))
      if (assessment.containsKey(key)) out.put(key, assessment.get(key));
    if (assessment.get("semanticOrigin") instanceof Map<?, ?>)
      out.put("semanticOrigin", semanticOrigin(assessment));
    List<Map<String, Object>> reasons = new ArrayList<Map<String, Object>>();
    if (assessment.get("unknownReasons") instanceof List<?>)
      for (Map<String, Object> reason : list(assessment, "unknownReasons"))
        reasons.add(
            Findings.map(
                "category", reason.get("category"),
                "code", reason.get("code"),
                "explanation", reason.get("explanation")));
    out.put("unknownReasons", reasons);
    List<Map<String, Object>> evidence = new ArrayList<Map<String, Object>>();
    for (Map<String, Object> item : optionalList(assessment, "evidence")) {
      Map<String, Object> location = new LinkedHashMap<String, Object>();
      for (String key : Arrays.asList("path", "line", "detail", "role", "nodeId"))
        if (item.containsKey(key)) location.put(key, item.get(key));
      evidence.add(location);
    }
    out.put("evidence", evidence);
    List<Map<String, Object>> actions = new ArrayList<Map<String, Object>>();
    for (Map<String, Object> action : optionalList(assessment, "reviewActions")) {
      Map<String, Object> safe =
          select(action, "kind", "code", "status", "ownerRole", "reasonCodes", "requiredEvidence");
      List<Map<String, Object>> locations = new ArrayList<Map<String, Object>>();
      for (Map<String, Object> location : optionalList(action, "locations"))
        locations.add(select(location, "path", "line", "nodeId"));
      safe.put("locations", locations);
      actions.add(safe);
    }
    if (assessment.containsKey("reviewActions")) out.put("reviewActions", actions);
    for (String siteKey :
        Arrays.asList("siteAssessments", "controlReviewSites", "collectionReviewSites")) {
      if (!(assessment.get(siteKey) instanceof List<?>)) continue;
      List<Map<String, Object>> sites = new ArrayList<Map<String, Object>>();
      for (Map<String, Object> site : list(assessment, siteKey)) {
        // Nested site lists are not part of the schema and must not recurse into analysis
        // internals.
        Map<String, Object> controlled =
            select(
                site,
                "ruleId",
                "disposition",
                "unknownCategory",
                "unknownReasons",
                "evidence",
                "reviewActions",
                "manualReviewRequired");
        Map<String, Object> safe = unknownDetail(controlled);
        safe.putAll(select(site, "path", "line"));
        if ("collectionReviewSites".equals(siteKey))
          for (String key : collectionFields())
            if (site.containsKey(key)) safe.put(key, site.get(key));
        sites.add(safe);
      }
      out.put(siteKey, sites);
    }
    if (assessment.containsKey("callContextSites")) {
      List<Map<String, Object>> sites = new ArrayList<Map<String, Object>>();
      for (Map<String, Object> site : optionalList(assessment, "callContextSites"))
        sites.add(
            select(
                site,
                "calleePath",
                "calleeLine",
                "callPath",
                "callLine",
                "binding",
                "parameterStates"));
      out.put("callContextSites", sites);
    }
    if (assessment.containsKey("streamTimingSites")) {
      List<Map<String, Object>> sites = new ArrayList<Map<String, Object>>();
      for (Map<String, Object> site : optionalList(assessment, "streamTimingSites"))
        sites.add(
            select(
                site,
                "path",
                "line",
                "checkPath",
                "checkLine",
                "ordering",
                "valueBinding",
                "assurance",
                "failureMode",
                "limits"));
      out.put("streamTimingSites", sites);
    }
    return out;
  }

  private static Map<String, Object> select(Map<String, Object> source, String... keys) {
    Map<String, Object> out = new LinkedHashMap<String, Object>();
    for (String key : keys) if (source.containsKey(key)) out.put(key, source.get(key));
    return out;
  }

  private static List<String> collectionFields() {
    return Arrays.asList(
        "appendPath",
        "appendLine",
        "checkPath",
        "checkLine",
        "control",
        "assurance",
        "failureMode",
        "checkedElementPath",
        "elementBinding",
        "subjectBinding",
        "decisionBinding",
        "outputBinding",
        "coverage",
        "limitations");
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> semanticOrigin(Map<String, Object> assessment) {
    return select(
        (Map<String, Object>) assessment.get("semanticOrigin"),
        "kind",
        "engine",
        "policyDigest",
        "sourceRuleIds",
        "language");
  }

  private static List<Map<String, Object>> optionalList(Map<String, Object> source, String key) {
    return source.get(key) instanceof List<?>
        ? list(source, key)
        : new ArrayList<Map<String, Object>>();
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
