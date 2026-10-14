package dev.aiguard.compat;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Only controlled descriptions and relative source locations belong in reports. */
public final class Findings {
  private Findings() {}

  public static Map<String, Object> map(Object... pairs) {
    if (pairs.length % 2 != 0) throw new IllegalArgumentException("Expected key/value pairs");
    Map<String, Object> out = new LinkedHashMap<String, Object>();
    for (int i = 0; i < pairs.length; i += 2) out.put((String) pairs[i], pairs[i + 1]);
    return out;
  }

  public static Map<String, Object> evidence(String path, int line, String detail) {
    return map("path", path, "line", Math.max(1, line), "detail", detail);
  }

  public static Map<String, Object> diagnostic(String code, String path, String message) {
    return map("code", code, "path", path, "message", message);
  }

  public static Map<String, Object> assessment(
      String id,
      String domain,
      String disposition,
      String severity,
      String title,
      String explanation,
      String recommendation,
      List<Map<String, Object>> evidence,
      String... limitations) {
    Map<String, Object> result =
        map(
            "ruleId",
            id,
            "domain",
            domain,
            "disposition",
            disposition,
            "severity",
            severity,
            "title",
            title,
            "explanation",
            explanation,
            "recommendation",
            recommendation,
            "evidence",
            new ArrayList<Map<String, Object>>(evidence),
            "limitations",
            new ArrayList<String>(Arrays.asList(limitations)));
    Unknowns.complete(Arrays.asList(result), Collections.<Map<String, Object>>emptyList());
    return result;
  }
}
