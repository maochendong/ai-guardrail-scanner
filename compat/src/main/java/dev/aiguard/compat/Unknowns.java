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
    review(finding, String.valueOf(finding.get("ruleId")));
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
      completeFinding(finding, String.valueOf(finding.get("ruleId")));
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

  private static void completeFinding(Map<String, Object> finding, String ruleId) {
    if ("UNKNOWN".equals(finding.get("disposition"))) {
      List<Map<String, Object>> existing = reasons(finding);
      if (!existing.isEmpty() && valid(String.valueOf(existing.get(0).get("category"))))
        finding.put("unknownCategory", existing.get(0).get("category"));
      if (existing.isEmpty()) {
        boolean located = !items(finding, "evidence").isEmpty();
        set(
            finding,
            INSUFFICIENT_EVIDENCE,
            located ? "CONTROL_SEMANTICS_UNVERIFIED" : "NO_LOCATED_EVIDENCE",
            located
                ? "Located static evidence does not establish the required control semantics."
                : "No located evidence establishes whether this control is present or effective.");
      }
      review(finding, ruleId);
    }
    List<Map<String, Object>> sites =
        new ArrayList<Map<String, Object>>(items(finding, "siteAssessments"));
    sites.addAll(items(finding, "controlReviewSites"));
    if (sites.isEmpty()) return;
    List<Map<String, Object>> actions = new ArrayList<Map<String, Object>>();
    List<String> locatedCodes = new ArrayList<String>();
    for (Map<String, Object> site : sites) {
      completeFinding(site, ruleId);
      for (Map<String, Object> reason : reasons(site))
        locatedCodes.add(String.valueOf(reason.get("code")));
      for (Map<String, Object> action : items(site, "reviewActions")) merge(actions, action);
    }
    List<Map<String, Object>> unlocated = new ArrayList<Map<String, Object>>();
    for (Map<String, Object> reason : reasons(finding))
      if (!locatedCodes.contains(String.valueOf(reason.get("code")))) unlocated.add(reason);
    if (!unlocated.isEmpty()) {
      Map<String, Object> gaps = Findings.map("unknownReasons", unlocated);
      review(gaps, ruleId);
      for (Map<String, Object> action : items(gaps, "reviewActions")) merge(actions, action);
    }
    // Site reasons have a causal location. Do not attach the parent's combined reasons to all
    // sites.
    if (actions.isEmpty() && "UNKNOWN".equals(finding.get("disposition")))
      actions.addAll(items(finding, "reviewActions"));
    putActions(finding, actions);
  }

  private static void review(Map<String, Object> finding, String ruleId) {
    List<Map<String, Object>> actions = new ArrayList<Map<String, Object>>();
    List<Map<String, Object>> locations = locations(finding);
    boolean missingMapping = false;
    List<String> reasonCodes = new ArrayList<String>();
    for (Map<String, Object> reason : reasons(finding)) {
      String code = String.valueOf(reason.get("code"));
      String category = String.valueOf(reason.get("category"));
      if (!reasonCodes.contains(code)) reasonCodes.add(code);
      Map<String, Object> action;
      if (MISSING_MAPPING.equals(category)) {
        missingMapping = true;
        action =
            action(
                "MAP_API",
                "MAP_CONTROL_API",
                "应用研发与规则维护人员",
                "提供当前源码版本对应的 API 类型、参数与返回值语义，核实身份、资源、控制结果与真实调用的绑定后补充映射。",
                code,
                locations);
      } else if ("IDENTITY_SLOT_MISSING".equals(code)) {
        missingMapping = true;
        action =
            action(
                "MAP_API",
                "BIND_IDENTITY_ARGUMENT",
                "应用研发与规则维护人员",
                "确认 API 中承载用户或租户身份的实际参数或接收者字段，并将其与资源操作绑定；没有身份槽位时核实是否应补充接口约束。",
                code,
                locations);
      } else if ("IDENTITY_TRUST_UNVERIFIED".equals(code)) {
        action =
            action(
                "CONFIRM_SCOPE",
                "CONFIRM_TRUSTED_IDENTITY",
                "身份平台与应用负责人",
                "提供服务端认证主体的来源、网关到应用的信任链及不可被客户端覆盖的依据；参数名称不能替代可信身份凭证。",
                code,
                locations);
      } else if ("RESOURCE_SCOPE_UNCLASSIFIED".equals(code)) {
        action =
            action(
                "CONFIRM_SCOPE",
                "CONFIRM_RESOURCE_SCOPE",
                "业务与数据权限负责人",
                "确认资源是公开、用户私有还是租户共享，并提供所有权、文档授权、共享及撤销规则和适用范围。",
                code,
                locations);
      } else if ("CONTROL_ASSURANCE_UNVERIFIED".equals(code)) {
        action =
            action(
                "CONFIRM_SCOPE",
                "CONFIRM_CONTROL_SEMANTICS",
                "安全控制与应用负责人",
                "提供当前控制实现或依赖版本的审核依据，明确校验对象、允许与拒绝语义及实际生效的业务边界。",
                code,
                locations);
      } else if ("GUARD_FAILURE_OPEN".equals(code) || "GUARD_FAILURE_UNVERIFIED".equals(code)) {
        action = runtimeAction("BANK-GUARD-001", code, locations);
      } else if (UNSUPPORTED.equals(category)) {
        String actionCode = "EXTEND_FLOW_ANALYSIS";
        String required = "补充可复现的最小控制流用例与期望值绑定，扩展分析器后重扫；暂不支持不能视为控制通过。";
        if ("RECEIVER_BINDING_UNRESOLVED".equals(code)) {
          actionCode = "RESOLVE_RECEIVER_BINDING";
          required = "补充接收者实例的构造、注入或别名来源及目标类型，验证方法调用绑定后重扫。";
        } else if ("STREAM_ELEMENT_UNRESOLVED".equals(code)) {
          actionCode = "RESOLVE_STREAM_ELEMENT_FLOW";
          required = "补充流元素、回调和输出边界之间的值流用例，证明每个输出元素与校验决策的对应关系后重扫。";
        } else if ("INTERPROCEDURAL_FLOW_BOUNDED".equals(code)) {
          actionCode = "EXTEND_CALL_CONTEXT";
          required = "定位未完成的调用上下文、递归或调用深度，补充参数与返回关系的最小用例；不得把某个调用者的身份或证明复用于其他入口。";
        }
        action = action("EXTEND_ANALYSIS", actionCode, "扫描器维护人员", required, code, locations);
      } else {
        action =
            action(
                "TRIAGE_EVIDENCE",
                "LOCATE_CONTROL_EVIDENCE",
                "应用研发与规则维护人员",
                "定位当前规则对应的入口、控制实现和真实输出或资源边界，再判断需补 API 映射、扩展分析还是提供业务或运行证据。",
                code,
                locations);
      }
      merge(actions, action);
    }
    // Final acceptance needs negative tests only after a relevant boundary has been located.
    if (!missingMapping && !locations.isEmpty()) {
      Map<String, Object> runtime = runtimeAction(ruleId, null, locations);
      if (runtime != null) {
        runtime.put("reasonCodes", reasonCodes);
        merge(actions, runtime);
      }
    }
    putActions(finding, actions);
  }

  private static Map<String, Object> runtimeAction(
      String ruleId, String reasonCode, List<Map<String, Object>> locations) {
    String code;
    String evidence;
    if ("BANK-GUARD-001".equals(ruleId)) {
      code = "VERIFY_GUARD_FAIL_CLOSED";
      evidence = "在实际部署配置中执行拒绝、异常和超时负测，记录响应及工具副作用；验证审核前不释放原文或流式首包，回退内容满足已批准策略。";
    } else if ("BANK-IAM-001".equals(ruleId)) {
      code = "VERIFY_IDENTITY_ISOLATION";
      evidence = "使用不同用户和租户执行交叉访问、会话复用与并发请求负测，保留请求身份及资源归属记录；验证客户端参数不能覆盖服务端认证主体。";
    } else if ("BANK-INTERNAL-001".equals(ruleId)) {
      code = "VERIFY_DOCUMENT_AUTHORIZATION";
      evidence = "使用不同用户或租户及撤权文档执行检索负测，覆盖向量检索、关键词检索、重排与缓存；记录无权文档未进入上下文或响应的证据。";
    } else return null;
    return action("VERIFY_RUNTIME", code, "应用测试与安全负责人", evidence, reasonCode, locations);
  }

  private static Map<String, Object> action(
      String kind,
      String code,
      String owner,
      String evidence,
      String reason,
      List<Map<String, Object>> locations) {
    List<String> codes = new ArrayList<String>();
    if (reason != null) codes.add(reason);
    return Findings.map(
        "kind",
        kind,
        "code",
        code,
        "status",
        "OPEN",
        "ownerRole",
        owner,
        "reasonCodes",
        codes,
        "requiredEvidence",
        Arrays.asList(evidence),
        "locations",
        new ArrayList<Map<String, Object>>(locations));
  }

  @SuppressWarnings("unchecked")
  private static void merge(List<Map<String, Object>> actions, Map<String, Object> added) {
    for (Map<String, Object> action : actions)
      if (action.get("kind").equals(added.get("kind"))
          && action.get("code").equals(added.get("code"))) {
        for (String key : Arrays.asList("reasonCodes", "locations")) {
          List<Object> current = (List<Object>) action.get(key);
          for (Object value : (List<?>) added.get(key))
            if (!current.contains(value)) current.add(value);
        }
        return;
      }
    Map<String, Object> copy = Findings.map();
    copy.putAll(added);
    copy.put("reasonCodes", new ArrayList<Object>((List<?>) added.get("reasonCodes")));
    copy.put("locations", new ArrayList<Object>((List<?>) added.get("locations")));
    actions.add(copy);
  }

  private static void putActions(Map<String, Object> finding, List<Map<String, Object>> actions) {
    boolean manual = false;
    for (Map<String, Object> action : actions)
      if ("CONFIRM_SCOPE".equals(action.get("kind")) || "VERIFY_RUNTIME".equals(action.get("kind")))
        manual = true;
    finding.put("reviewActions", actions);
    finding.put("manualReviewRequired", manual);
  }

  private static List<Map<String, Object>> locations(Map<String, Object> finding) {
    List<Map<String, Object>> out = new ArrayList<Map<String, Object>>();
    for (Map<String, Object> evidence : items(finding, "evidence")) {
      if (!(evidence.get("path") instanceof String) || !(evidence.get("line") instanceof Number))
        continue;
      Map<String, Object> location =
          Findings.map("path", evidence.get("path"), "line", evidence.get("line"));
      if (evidence.get("nodeId") instanceof String) location.put("nodeId", evidence.get("nodeId"));
      if (!out.contains(location)) out.add(location);
    }
    return out;
  }

  @SuppressWarnings("unchecked")
  private static List<Map<String, Object>> items(Map<String, Object> map, String key) {
    Object value = map.get(key);
    return value instanceof List<?>
        ? (List<Map<String, Object>>) value
        : new ArrayList<Map<String, Object>>();
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
