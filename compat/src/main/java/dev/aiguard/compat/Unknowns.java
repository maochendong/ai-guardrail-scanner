package dev.aiguard.compat;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/** Reasons for an unknown result are distinct from independently reported scan diagnostics. */
public final class Unknowns {
  public static final String MISSING_MAPPING = "MISSING_MAPPING";
  public static final String INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE";
  public static final String UNSUPPORTED = "UNSUPPORTED";

  private Unknowns() {}

  /** The first explicit reason is primary; subsequent reasons do not change the summary count. */
  public static void set(
      Map<String, Object> finding, String category, String code, String explanation) {
    if (!"UNKNOWN".equals(finding.get("disposition"))) return;
    if (!valid(category) || code == null || explanation == null)
      throw new IllegalArgumentException("INVALID_UNKNOWN_REASON");
    List<Map<String, Object>> reasons = reasons(finding);
    if (reasons.size() == 1 && isDefault(reasons.get(0))) reasons.clear();
    if (reasons.isEmpty()) finding.put("unknownCategory", category);
    Map<String, Object> reason =
        Findings.map("category", category, "code", code, "explanation", explanation);
    if (!reasons.contains(reason)) reasons.add(reason);
    finding.put("unknownReasons", reasons);
  }

  /** Counts each UNKNOWN once by its primary category, including older unclassified results. */
  public static Map<String, Object> summarize(List<Map<String, Object>> assessments) {
    Map<String, Object> counts =
        Findings.map(MISSING_MAPPING, 0, INSUFFICIENT_EVIDENCE, 0, UNSUPPORTED, 0);
    for (Map<String, Object> finding : assessments) {
      if (!"UNKNOWN".equals(finding.get("disposition"))) continue;
      String category = String.valueOf(finding.get("unknownCategory"));
      if (!valid(category)) category = INSUFFICIENT_EVIDENCE;
      counts.put(category, ((Integer) counts.get(category)) + 1);
    }
    return counts;
  }

  /** Global diagnostics never supply a finding's reason without an explicit causal binding. */
  public static void complete(
      List<Map<String, Object>> assessments, List<Map<String, Object>> diagnostics) {
    for (Map<String, Object> finding : assessments) {
      if (!"UNKNOWN".equals(finding.get("disposition"))) continue;
      if (valid(String.valueOf(finding.get("unknownCategory"))) && !reasons(finding).isEmpty())
        continue;
      Object evidence = finding.get("evidence");
      boolean located = evidence instanceof List<?> && !((List<?>) evidence).isEmpty();
      set(
          finding,
          INSUFFICIENT_EVIDENCE,
          located ? "CONTROL_SEMANTICS_UNVERIFIED" : "NO_LOCATED_EVIDENCE",
          located
              ? "Located static evidence does not establish the required control semantics."
              : "No located evidence establishes whether this control is present or effective.");
    }
    for (Map<String, Object> diagnostic : diagnostics) {
      if (valid(String.valueOf(diagnostic.get("category")))) continue;
      String code = String.valueOf(diagnostic.get("code"));
      String category = INSUFFICIENT_EVIDENCE;
      if ("BANK_POLICY_UNMAPPED".equals(code)) category = MISSING_MAPPING;
      else if (code.matches(
              ".*(?:^|_)(?:LIMIT|ERROR|FAILED|DEPTH|SKIPPED|UNSUPPORTED|PARSE)(?:_|$).*")
          || Arrays.asList(
                  "PYTHON_FSTRING_BOUNDARY",
                  "EXCLUDED_SCOPE",
                  "BANK_JAVA_BINDING_INCOMPLETE",
                  "BANK_FLOW_INCOMPLETE",
                  "BANK_PATHS_MERGED")
              .contains(code)) category = UNSUPPORTED;
      diagnostic.put("category", category);
    }
  }

  private static boolean valid(String category) {
    return MISSING_MAPPING.equals(category)
        || INSUFFICIENT_EVIDENCE.equals(category)
        || UNSUPPORTED.equals(category);
  }

  private static boolean isDefault(Map<String, Object> reason) {
    return INSUFFICIENT_EVIDENCE.equals(reason.get("category"))
        && ("NO_LOCATED_EVIDENCE".equals(reason.get("code"))
            || "CONTROL_SEMANTICS_UNVERIFIED".equals(reason.get("code")));
  }

  @SuppressWarnings("unchecked")
  private static List<Map<String, Object>> reasons(Map<String, Object> finding) {
    Object reasons = finding.get("unknownReasons");
    return reasons instanceof List<?>
        ? new ArrayList<Map<String, Object>>((List<Map<String, Object>>) reasons)
        : new ArrayList<Map<String, Object>>();
  }
}
