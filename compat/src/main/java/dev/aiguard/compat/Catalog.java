package dev.aiguard.compat;

import com.google.gson.reflect.TypeToken;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public final class Catalog {
  private Catalog() {}

  public static List<Map<String, Object>> javaRules() {
    try {
      return Json.COMPACT.fromJson(
          Json.readResource("/rules.json"),
          new TypeToken<List<Map<String, Object>>>() {}.getType());
    } catch (IOException error) {
      throw new IllegalStateException("RULE_RESOURCE_UNAVAILABLE");
    }
  }

  public static List<Map<String, Object>> all() {
    List<Map<String, Object>> rules = new ArrayList<Map<String, Object>>(javaRules());
    rules.addAll(PythonAnalysis.catalog());
    rules.addAll(BusinessPolicy.catalog());
    return rules;
  }
}
