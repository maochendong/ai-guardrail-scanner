package dev.aiguard.compat;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class AnalysisResult {
  public final List<Map<String, Object>> assessments = new ArrayList<Map<String, Object>>();
  public final List<Map<String, Object>> diagnostics = new ArrayList<Map<String, Object>>();
  public final Set<String> protocols = new LinkedHashSet<String>();
  public String springAiVersion = "UNKNOWN", versionStatus = "UNKNOWN";
  public int gatewayMethods;
  public boolean aiDetected;
}
