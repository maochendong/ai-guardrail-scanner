package dev.aiguard.compat;

import java.nio.file.Path;
import java.text.SimpleDateFormat;
import java.util.*;

public final class Scanner {
  public Map<String, Object> scan(Path root, String id, Cancel cancel) throws Exception {
    return scan(root, id, cancel, BusinessPolicy.generic());
  }

  public Map<String, Object> scan(Path root, String id, Cancel cancel, BusinessPolicy policy)
      throws Exception {
    policy.checkRepository(root);
    Inventory inventory = Inventory.load(root, cancel);
    JavaSyntax.Cache javaSyntax = new JavaSyntax.Cache();
    PythonSyntax.Cache pythonSyntax = new PythonSyntax.Cache();
    List<Map<String, Object>> assessments = new ArrayList<Map<String, Object>>();
    List<Map<String, Object>> diagnostics =
        new ArrayList<Map<String, Object>>(inventory.diagnostics);
    Map<String, Object> mappingCoverage = new LinkedHashMap<String, Object>();
    Set<String> protocols = new TreeSet<String>();
    List<String> languages = new ArrayList<String>();
    boolean detected = false;
    int gateways = 0;
    String springVersion = "UNKNOWN", versionStatus = "UNKNOWN";
    if (inventory.javaFiles > 0 || !inventory.javaAndConfig.isEmpty()) {
      AnalysisResult java = JavaAnalysis.analyze(inventory.javaAndConfig, cancel, javaSyntax);
      assessments.addAll(java.assessments);
      diagnostics.addAll(java.diagnostics);
      protocols.addAll(java.protocols);
      detected |= java.aiDetected;
      gateways += java.gatewayMethods;
      springVersion = java.springAiVersion;
      versionStatus = java.versionStatus;
      languages.add("java");
    }
    if (!inventory.python.isEmpty()) {
      AnalysisResult python = PythonAnalysis.analyze(inventory.python, cancel, pythonSyntax);
      assessments.addAll(python.assessments);
      diagnostics.addAll(python.diagnostics);
      protocols.addAll(python.protocols);
      detected |= python.aiDetected;
      gateways += python.gatewayMethods;
      languages.add("python");
    }
    if (languages.isEmpty())
      diagnostics.add(
          Findings.diagnostic(
              "NO_SUPPORTED_SOURCE",
              "",
              "No supported production Java or Python source was analyzed."));
    if (policy.enabled() || policy.contractCount() > 0) {
      BusinessAnalysis bank =
          BusinessAnalysis.analyze(inventory, policy, cancel, javaSyntax, pythonSyntax);
      assessments.addAll(0, bank.assessments);
      diagnostics.addAll(bank.diagnostics);
      mappingCoverage.putAll(bank.mappingCoverage);
      GenericSemanticAnalysis.merge(assessments, bank, policy, inventory, cancel);
      detected |= ((Number) bank.mappingCoverage.get("matchedModelSourceSites")).intValue() > 0;
    }
    List<Map<String, Object>> bounded = new ArrayList<Map<String, Object>>();
    boolean truncated = assessments.size() > 1000;
    for (Map<String, Object> item : assessments) {
      cancel.check();
      if (bounded.size() == 1000) break;
      Map<String, Object> copy = new LinkedHashMap<String, Object>(item);
      @SuppressWarnings("unchecked")
      List<Map<String, Object>> evidence = (List<Map<String, Object>>) item.get("evidence");
      if (evidence == null) evidence = Collections.emptyList();
      truncated |= evidence.size() > 16;
      copy.put(
          "evidence",
          new ArrayList<Map<String, Object>>(evidence.subList(0, Math.min(16, evidence.size()))));
      bounded.add(copy);
    }
    if (truncated)
      diagnostics.add(
          Findings.diagnostic(
              "RESULT_LIMIT",
              "",
              "Evidence bounded to 1000 assessments and 16 locations per assessment."));
    if (diagnostics.size() > 2048) {
      diagnostics = new ArrayList<Map<String, Object>>(diagnostics.subList(0, 2048));
      diagnostics.add(
          Findings.diagnostic(
              "DIAGNOSTIC_LIMIT", "", "Additional diagnostics omitted; coverage incomplete."));
    }
    Unknowns.complete(bounded, diagnostics);
    SimpleDateFormat date = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.ROOT);
    date.setTimeZone(TimeZone.getTimeZone("UTC"));
    Map<String, Object> report =
        Findings.map(
            "schemaVersion",
            "1.9",
            "ruleSetVersion",
            "java-python-guardrail-v11",
            "scanId",
            id,
            "createdAt",
            date.format(new Date()),
            "sourceDigest",
            inventory.digest,
            "project",
            Findings.map(
                "springAiVersion",
                springVersion,
                "versionStatus",
                versionStatus,
                "javaFiles",
                inventory.javaFiles,
                "pythonFiles",
                inventory.python.size(),
                "configurationFiles",
                inventory.configurationFiles,
                "aiDetected",
                detected,
                "aiProtocols",
                new ArrayList<String>(protocols),
                "customGatewayMethods",
                gateways,
                "languages",
                languages),
            "runtime",
            Findings.map(
                "javaVersion",
                System.getProperty("java.version"),
                "minimumJavaVersion",
                "1.7",
                "scannerVersion",
                "0.10.0"),
            "policy",
            policy.metadata(),
            "mappingCoverage",
            mappingCoverage,
            "unknownSummary",
            Unknowns.summarize(bounded),
            "complete",
            false,
            "securityVerified",
            false,
            "analysisScope",
            "bounded offline Java/Python syntax and source relations; no target execution, model"
                + " calls or runtime security verification",
            "assessments",
            bounded,
            "diagnostics",
            diagnostics);
    report.put("gateDecision", count(report, "VIOLATED") > 0 ? "BLOCK" : "REVIEW");
    return report;
  }

  @SuppressWarnings("unchecked")
  public static int count(Map<String, Object> report, String disposition) {
    int result = 0;
    for (Map<String, Object> item : (List<Map<String, Object>>) report.get("assessments"))
      if (disposition.equals(item.get("disposition"))) result++;
    return result;
  }
}
