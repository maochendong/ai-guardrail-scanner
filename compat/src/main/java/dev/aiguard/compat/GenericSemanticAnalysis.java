package dev.aiguard.compat;

import java.util.*;

/**
 * Reuses located engine facts; it does not interpret API contracts or infer new control semantics.
 */
final class GenericSemanticAnalysis {
  private GenericSemanticAnalysis() {}

  static void merge(
      List<Map<String, Object>> assessments,
      BusinessAnalysis analysis,
      BusinessPolicy policy,
      Inventory inventory,
      Cancel cancel) {
    if (policy.contractCount() == 0) return;
    if (!policy.matchesSourceDigest(inventory.digest)) {
      staleMappings(assessments, policy, inventory);
      return;
    }
    Set<String> javaPaths = new HashSet<String>(), pythonPaths = new HashSet<String>();
    for (SourceFile file : inventory.javaAndConfig)
      if (file.path.endsWith(".java")) javaPaths.add(file.path);
    for (SourceFile file : inventory.python) pythonPaths.add(file.path);
    Map<String, Map<String, Object>> facts = new LinkedHashMap<String, Map<String, Object>>();
    for (Map<String, Object> finding : analysis.semanticAssessments)
      facts.put(String.valueOf(finding.get("ruleId")), finding);
    Map<String, List<Map<String, Object>>> identity =
        bySite(analysis.semanticSites(BusinessPolicy.IAM));
    List<Map<String, Object>> added = new ArrayList<Map<String, Object>>();
    for (String sourceRule : Arrays.asList(BusinessPolicy.GUARD, BusinessPolicy.ACL)) {
      Map<String, Object> fact = facts.get(sourceRule);
      Map<String, List<Map<String, Object>>> grouped =
          new LinkedHashMap<String, List<Map<String, Object>>>();
      for (List<Map<String, Object>> originals :
          bySite(analysis.semanticSites(sourceRule)).values()) {
        cancel.check();
        Map<String, Object> original = originals.get(0);
        String path = String.valueOf(original.get("path"));
        String language =
            javaPaths.contains(path) ? "java" : pythonPaths.contains(path) ? "python" : "";
        if (language.isEmpty()) continue;
        boolean guard = BusinessPolicy.GUARD.equals(sourceRule);
        // A release contract alone does not establish that the released value came from a model.
        List<Map<String, Object>> scoped = new ArrayList<Map<String, Object>>();
        for (Map<String, Object> candidate : originals)
          if (!guard || strings(candidate, "valueLabels").contains("model-output"))
            scoped.add(candidate);
        if (scoped.isEmpty()) continue;
        String target =
            guard
                ? ("java".equals(language) ? "AI-GUARD-002" : "AI-PY-005")
                : ("java".equals(language) ? "AI-L2-003" : "AI-PY-002");
        if (!guard) {
          List<Map<String, Object>> subjects = identity.get(String.valueOf(original.get("siteId")));
          if (subjects == null || subjects.isEmpty()) {
            Map<String, Object> site = copySite(original, target);
            site.put("disposition", "UNKNOWN");
            Unknowns.set(
                site,
                "INSUFFICIENT_EVIDENCE",
                "RETRIEVAL_IDENTITY_UNRESOLVED",
                "Document permission alone does not establish the retrieval subject binding.");
            scoped.add(site);
          } else scoped.addAll(subjects);
        }
        for (Map<String, Object> site : aggregate(scoped, target)) {
          String key = target + ":" + site.get("disposition");
          if (!grouped.containsKey(key)) grouped.put(key, new ArrayList<Map<String, Object>>());
          grouped.get(key).add(site);
        }
      }
      for (List<Map<String, Object>> sites : grouped.values()) {
        boolean projectedTruncated = sites.size() > 128;
        if (projectedTruncated) sites = new ArrayList<Map<String, Object>>(sites.subList(0, 128));
        Map<String, Object> first = sites.get(0);
        String target = String.valueOf(first.get("ruleId"));
        String language = target.startsWith("AI-PY-") ? "python" : "java";
        Map<String, Object> template = template(assessments, target);
        if (template == null) continue;
        String disposition = String.valueOf(first.get("disposition"));
        List<Map<String, Object>> evidence = new ArrayList<Map<String, Object>>();
        for (Map<String, Object> site : sites) append(evidence, items(site, "evidence"), 16);
        Map<String, Object> finding =
            Findings.assessment(
                target,
                String.valueOf(template.get("domain")),
                disposition,
                "VIOLATED".equals(disposition) ? "HIGH" : "INFO",
                String.valueOf(template.get("title")),
                "External API semantics refine only the listed mapped local sites. Existing syntax"
                    + " findings and uncovered scope remain independent; this is not whole-rule"
                    + " coverage.",
                String.valueOf(template.get("recommendation")),
                evidence,
                "Operator API contracts are assumptions; their implementation and deployment need"
                    + " review.",
                "Only the listed source paths and value-bound local outcomes are reused; dynamic"
                    + " dispatch, asynchronous delivery and unvisited paths are not certified.");
        finding.put(
            "semanticOrigin",
            Findings.map(
                "kind",
                "external-api-contract",
                "engine",
                "BusinessAnalysis",
                "policyDigest",
                policy.digest,
                "sourceRuleIds",
                BusinessPolicy.GUARD.equals(sourceRule)
                    ? Arrays.asList(BusinessPolicy.GUARD)
                    : Arrays.asList(BusinessPolicy.ACL, BusinessPolicy.IAM),
                "language",
                language));
        finding.put("semanticScope", "MAPPED_LOCAL_SITES_ONLY");
        finding.put("siteAssessments", sites);
        boolean truncated =
            projectedTruncated || Boolean.TRUE.equals(fact.get("siteAssessmentsTruncated"));
        boolean incomplete = !"OBSERVED".equals(fact.get("disposition")) || truncated;
        if (BusinessPolicy.ACL.equals(sourceRule)) {
          Map<String, Object> iam = facts.get(BusinessPolicy.IAM);
          truncated |= Boolean.TRUE.equals(iam.get("siteAssessmentsTruncated"));
          incomplete |= !"OBSERVED".equals(iam.get("disposition")) || truncated;
        }
        finding.put("siteAssessmentsTruncated", truncated);
        finding.put("semanticCoverageIncomplete", incomplete);
        for (Map<String, Object> site : sites)
          for (Map<String, Object> reason : items(site, "unknownReasons"))
            Unknowns.set(
                finding,
                String.valueOf(reason.get("category")),
                String.valueOf(reason.get("code")),
                String.valueOf(reason.get("explanation")));
        added.add(finding);
      }
    }
    unlocatedFailures(assessments, added, policy, inventory, analysis);
    // NOT_APPLICABLE has no located boundary evidence in the syntax analyzers. A mapped boundary
    // makes that rule applicable, without removing its independent UNKNOWN or VIOLATED evidence.
    removeInapplicable(assessments, added);
    assessments.addAll(added);
  }

  private static void staleMappings(
      List<Map<String, Object>> assessments, BusinessPolicy policy, Inventory inventory) {
    List<Map<String, Object>> gaps = new ArrayList<Map<String, Object>>();
    for (String id : declaredTargets(policy, inventory)) {
      Map<String, Object> template = template(assessments, id);
      if (template == null) continue;
      Map<String, Object> gap =
          Findings.assessment(
              id,
              String.valueOf(template.get("domain")),
              "UNKNOWN",
              "INFO",
              String.valueOf(template.get("title")),
              "External API contracts for this rule are bound to a different source digest. Their"
                  + " declared scope remains unassessed; no current source location is inferred.",
              String.valueOf(template.get("recommendation")),
              Collections.<Map<String, Object>>emptyList(),
              "A stale contract does not establish applicability or safety of a current call"
                  + " site.");
      Unknowns.set(
          gap,
          "MISSING_MAPPING",
          "STALE_SOURCE_MAPPING",
          "Review and bind the operator API contracts to this source snapshot before applying"
              + " them.");
      gaps.add(gap);
    }
    removeInapplicable(assessments, gaps);
    assessments.addAll(gaps);
  }

  private static Set<String> declaredTargets(BusinessPolicy policy, Inventory inventory) {
    Set<String> applicable = new LinkedHashSet<String>();
    boolean javaModel = false, pythonModel = false;
    for (BusinessPolicy.Contract contract : policy.allContracts())
      if ("source".equals(contract.kind) && "model-output".equals(contract.label)) {
        if (contract.symbol.contains("#")) javaModel = true;
        else pythonModel = true;
      }
    for (BusinessPolicy.Contract contract : policy.allContracts()) {
      if (!"sink".equals(contract.kind)) continue;
      boolean java = contract.symbol.contains("#");
      if (java ? inventory.javaFiles == 0 : inventory.python.isEmpty()) continue;
      if ("retrieve".equals(contract.channel)) applicable.add(java ? "AI-L2-003" : "AI-PY-002");
      if ("release".equals(contract.channel)
          && ("model-output".equals(contract.requiresLabel) || (java ? javaModel : pythonModel)))
        applicable.add(java ? "AI-GUARD-002" : "AI-PY-005");
    }
    return applicable;
  }

  private static void unlocatedFailures(
      List<Map<String, Object>> assessments,
      List<Map<String, Object>> added,
      BusinessPolicy policy,
      Inventory inventory,
      BusinessAnalysis analysis) {
    for (String id : declaredTargets(policy, inventory)) {
      if (template(added, id) != null) continue;
      List<String> sourceRules =
          "AI-GUARD-002".equals(id) || "AI-PY-005".equals(id)
              ? Arrays.asList(BusinessPolicy.GUARD)
              : Arrays.asList(BusinessPolicy.ACL, BusinessPolicy.IAM);
      List<Map<String, Object>> reasons = new ArrayList<Map<String, Object>>();
      String language = id.startsWith("AI-PY-") ? "python" : "java";
      for (String sourceRule : sourceRules)
        for (String code :
            Arrays.asList(
                "BANK_ANALYSIS_BOUNDED", "ARGUMENT_BINDING_UNRESOLVED", "SOURCE_FLOW_INCOMPLETE"))
          if (analysis.hasSemanticFailure(sourceRule, code, language)) {
            Map<String, Object> reason =
                Findings.map(
                    "category",
                    "UNSUPPORTED",
                    "code",
                    code,
                    "explanation",
                    "BANK_ANALYSIS_BOUNDED".equals(code)
                        ? "A mapped flow in this language exceeded its analysis budget before full"
                              + " coverage."
                        : "ARGUMENT_BINDING_UNRESOLVED".equals(code)
                            ? "A mapped API in this language could not bind its arguments"
                                  + " unambiguously."
                            : "Discarded or unvisited source in this language leaves mapped flow"
                                  + " incomplete.");
            if (!reasons.contains(reason)) reasons.add(reason);
          }
      if (reasons.isEmpty()) continue;
      Map<String, Object> template = template(assessments, id);
      if (template == null) continue;
      Map<String, Object> gap =
          Findings.assessment(
              id,
              String.valueOf(template.get("domain")),
              "UNKNOWN",
              "INFO",
              String.valueOf(template.get("title")),
              "Declared API semantics could not produce located outcomes because parsing, binding"
                  + " or bounded flow analysis was incomplete. The declared scope remains"
                  + " unassessed.",
              String.valueOf(template.get("recommendation")),
              Collections.<Map<String, Object>>emptyList(),
              "No call location or control disposition is inferred from the contract declaration.");
      for (Map<String, Object> reason : reasons)
        Unknowns.set(
            gap,
            "UNSUPPORTED",
            String.valueOf(reason.get("code")),
            String.valueOf(reason.get("explanation")));
      added.add(gap);
    }
  }

  private static void removeInapplicable(
      List<Map<String, Object>> assessments, List<Map<String, Object>> added) {
    for (Map<String, Object> finding : added) {
      Iterator<Map<String, Object>> existing = assessments.iterator();
      while (existing.hasNext()) {
        Map<String, Object> item = existing.next();
        if (finding.get("ruleId").equals(item.get("ruleId"))
            && "NOT_APPLICABLE".equals(item.get("disposition"))
            && items(item, "evidence").isEmpty()) existing.remove();
      }
    }
  }

  private static Map<String, Object> copySite(Map<String, Object> site, String target) {
    Map<String, Object> copy = new LinkedHashMap<String, Object>(site);
    copy.put("ruleId", target);
    copy.put("unknownReasons", new ArrayList<Map<String, Object>>(items(site, "unknownReasons")));
    copy.put("evidence", new ArrayList<Map<String, Object>>(items(site, "evidence")));
    return copy;
  }

  private static Map<String, List<Map<String, Object>>> bySite(List<Map<String, Object>> sites) {
    Map<String, List<Map<String, Object>>> grouped =
        new LinkedHashMap<String, List<Map<String, Object>>>();
    for (Map<String, Object> site : sites) {
      String key = String.valueOf(site.get("siteId"));
      if (!grouped.containsKey(key)) grouped.put(key, new ArrayList<Map<String, Object>>());
      grouped.get(key).add(site);
    }
    return grouped;
  }

  /**
   * The source engines aggregate by line and symbol. Never splice successes from separate calls on
   * that line; keep violations and unknown paths independently, and observe only all-known sites.
   */
  private static List<Map<String, Object>> aggregate(
      List<Map<String, Object>> sources, String target) {
    boolean violated = false, unknown = false;
    for (Map<String, Object> source : sources) {
      violated |= "VIOLATED".equals(source.get("disposition"));
      unknown |= "UNKNOWN".equals(source.get("disposition"));
    }
    List<Map<String, Object>> result = new ArrayList<Map<String, Object>>();
    for (String disposition : Arrays.asList("VIOLATED", "UNKNOWN", "OBSERVED")) {
      if ("VIOLATED".equals(disposition) && !violated
          || "UNKNOWN".equals(disposition) && !unknown
          || "OBSERVED".equals(disposition) && (violated || unknown)) continue;
      Map<String, Object> site = copySite(sources.get(0), target);
      site.put("disposition", disposition);
      site.put("evidence", new ArrayList<Map<String, Object>>());
      site.put("unknownReasons", new ArrayList<Map<String, Object>>());
      site.remove("unknownCategory");
      for (Map<String, Object> source : sources) {
        if (!disposition.equals(source.get("disposition"))) continue;
        append(items(site, "evidence"), items(source, "evidence"), 16);
        for (Map<String, Object> reason : items(source, "unknownReasons"))
          Unknowns.set(
              site,
              String.valueOf(reason.get("category")),
              String.valueOf(reason.get("code")),
              String.valueOf(reason.get("explanation")));
      }
      result.add(site);
    }
    return result;
  }

  private static Map<String, Object> template(List<Map<String, Object>> assessments, String id) {
    for (Map<String, Object> finding : assessments)
      if (id.equals(finding.get("ruleId"))) return finding;
    return null;
  }

  private static void append(
      List<Map<String, Object>> into, List<Map<String, Object>> from, int limit) {
    for (Map<String, Object> item : from)
      if (into.size() < limit && !into.contains(item)) into.add(item);
  }

  @SuppressWarnings("unchecked")
  private static List<Map<String, Object>> items(Map<String, Object> value, String key) {
    Object items = value == null ? null : value.get(key);
    return items instanceof List
        ? (List<Map<String, Object>>) items
        : Collections.<Map<String, Object>>emptyList();
  }

  @SuppressWarnings("unchecked")
  private static List<String> strings(Map<String, Object> value, String key) {
    Object items = value.get(key);
    return items instanceof List ? (List<String>) items : Collections.<String>emptyList();
  }
}
