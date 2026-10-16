package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class GenericSemanticAnalysisTest {
  @Rule public TemporaryFolder temporary = new TemporaryFolder();
  private static final Cancel NEVER =
      new Cancel() {
        public void check() {}
      };

  private String contract(String symbol, int arity, String properties) {
    return "{\"symbol\":\"" + symbol + "\",\"arity\":" + arity + "," + properties + "}";
  }

  private String policy(String... contracts) {
    StringBuilder json = new StringBuilder("{\"version\":2,\"contracts\":[");
    for (String contract : contracts) {
      if (json.charAt(json.length() - 1) != '[') json.append(',');
      json.append(contract);
    }
    return json.append("]}").toString();
  }

  private String guardPolicy(String prefix, String assurance, String failure) {
    return policy(
        contract(prefix + "mint", 0, "\"kind\":\"source\",\"label\":\"model-output\""),
        contract(
            prefix + "permit",
            1,
            "\"kind\":\"check\",\"control\":\"guard\",\"args\":[0],"
                + "\"accept\":true,\"assurance\":\""
                + assurance
                + "\",\"failureMode\":\""
                + failure
                + "\""),
        contract(
            prefix + "publish",
            1,
            "\"kind\":\"sink\",\"channel\":\"release\",\"args\":[0],"
                + "\"requiresLabel\":\"model-output\""));
  }

  private Path source(String file, String text) throws Exception {
    Path root = temporary.newFolder().toPath().toRealPath();
    Files.write(root.resolve(file), text.getBytes(StandardCharsets.UTF_8));
    return root;
  }

  private Map<String, Object> scan(Path root, String profile, String policy) throws Exception {
    return new Scanner()
        .scan(root, "generic-semantics", NEVER, BusinessPolicy.parse(profile, policy));
  }

  private String java(String body) {
    return "import remote.Port; class Runner { void run() { " + body + " } }";
  }

  private String python(String body) {
    return "import remote\ndef run():\n" + body;
  }

  @SuppressWarnings("unchecked")
  private static List<Map<String, Object>> items(Map<String, Object> object, String key) {
    Object value = object.get(key);
    return value instanceof List
        ? (List<Map<String, Object>>) value
        : Collections.<Map<String, Object>>emptyList();
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> object(Map<String, Object> map, String key) {
    return (Map<String, Object>) map.get(key);
  }

  private static List<Map<String, Object>> mapped(Map<String, Object> report, String rule) {
    List<Map<String, Object>> out = new ArrayList<Map<String, Object>>();
    for (Map<String, Object> item : items(report, "assessments"))
      if (rule.equals(item.get("ruleId")) && item.containsKey("semanticOrigin")) out.add(item);
    return out;
  }

  private static void mappedDisposition(
      Map<String, Object> report, String rule, String disposition) {
    List<Map<String, Object>> mapped = mapped(report, rule);
    assertFalse("Missing mapped evidence: " + report, mapped.isEmpty());
    for (Map<String, Object> item : mapped) {
      assertEquals(item.toString(), disposition, item.get("disposition"));
      assertEquals("MAPPED_LOCAL_SITES_ONLY", item.get("semanticScope"));
      assertFalse(items(item, "siteAssessments").isEmpty());
      for (Map<String, Object> site : items(item, "siteAssessments")) {
        assertEquals(rule, site.get("ruleId"));
        assertEquals(disposition, site.get("disposition"));
        assertNotNull(site.get("siteId"));
        assertTrue(String.valueOf(site.get("siteId")).matches("[a-f0-9]{64}"));
        assertFalse(site.containsKey("symbol"));
      }
    }
  }

  private static boolean has(Map<String, Object> report, String rule, String disposition) {
    for (Map<String, Object> item : items(report, "assessments"))
      if (rule.equals(item.get("ruleId")) && disposition.equals(item.get("disposition")))
        return true;
    return false;
  }

  @Test
  public void javaRenamedApiContractsReuseSameValueGuardAndKeepGenericProfile() throws Exception {
    String text = java("Object a=Port.mint(); if(!Port.permit(a))return; Port.publish(a);");
    String mapping = guardPolicy("remote.Port#", "reviewed", "closed");
    for (String replacement : Arrays.asList("Port", "ServiceUnrelatedToSafetyNames")) {
      Map<String, Object> report =
          scan(
              source("Runner.java", text.replace("Port", replacement)),
              "generic",
              mapping.replace("Port", replacement));
      mappedDisposition(report, "AI-GUARD-002", "OBSERVED");
      assertFalse(has(report, "AI-GUARD-002", "NOT_APPLICABLE"));
      assertTrue(mapped(report, "AI-GUARD-003").isEmpty());
      assertEquals(Boolean.TRUE, object(report, "project").get("aiDetected"));
      for (Map<String, Object> item : items(report, "assessments"))
        assertFalse(String.valueOf(item.get("ruleId")).startsWith("BANK-"));
      Map<String, Object> origin = object(mapped(report, "AI-GUARD-002").get(0), "semanticOrigin");
      assertEquals("java", origin.get("language"));
      assertEquals(object(report, "policy").get("digest"), origin.get("policyDigest"));
    }
  }

  @Test
  public void javaIgnoredLateAndWrongValueChecksRemainViolations() throws Exception {
    for (String body :
        Arrays.asList(
            "Object a=Port.mint(); Port.permit(a); Port.publish(a);",
            "Object a=Port.mint(); Port.publish(a); if(!Port.permit(a))return;",
            "Object a=Port.mint(); Object b=Port.mint(); if(!Port.permit(b))return;"
                + " Port.publish(a);")) {
      Map<String, Object> report =
          scan(
              source("Runner.java", java(body)),
              "generic",
              guardPolicy("remote.Port#", "reviewed", "closed"));
      mappedDisposition(report, "AI-GUARD-002", "VIOLATED");
      assertEquals("BLOCK", report.get("gateDecision"));
    }
  }

  @Test
  public void pythonRenamedApiContractsReuseGuardWithoutRemovingBroaderUnknown() throws Exception {
    String source =
        python(
            "    a=remote.mint()\n"
                + "    if not remote.permit(a):\n"
                + "        return\n"
                + "    remote.publish(a)\n");
    String mapping = guardPolicy("remote.", "reviewed", "closed");
    for (String replacement : Arrays.asList("remote", "unrelated_adapter")) {
      Map<String, Object> report =
          scan(
              source("app.py", source.replace("remote", replacement)),
              "generic",
              mapping.replace("remote", replacement));
      mappedDisposition(report, "AI-PY-005", "OBSERVED");
      assertTrue(
          "Broader content and runtime coverage remains unassessed",
          has(report, "AI-PY-005", "UNKNOWN"));
      assertEquals(
          "python", object(mapped(report, "AI-PY-005").get(0), "semanticOrigin").get("language"));
    }
  }

  @Test
  public void pythonIgnoredLateAndWrongValueChecksRemainViolations() throws Exception {
    for (String body :
        Arrays.asList(
            "    a=remote.mint()\n    remote.permit(a)\n    remote.publish(a)\n",
            "    a=remote.mint()\n"
                + "    remote.publish(a)\n"
                + "    if not remote.permit(a):\n"
                + "        return\n",
            "    a=remote.mint()\n"
                + "    b=remote.mint()\n"
                + "    if not remote.permit(b):\n"
                + "        return\n"
                + "    remote.publish(a)\n")) {
      Map<String, Object> report =
          scan(
              source("app.py", python(body)),
              "generic",
              guardPolicy("remote.", "reviewed", "closed"));
      mappedDisposition(report, "AI-PY-005", "VIOLATED");
    }
  }

  @Test
  public void candidateUnknownFailureAndStaleMappingsCannotCertifyJavaOrPython() throws Exception {
    for (boolean isJava : Arrays.asList(Boolean.TRUE, Boolean.FALSE)) {
      String prefix = isJava ? "remote.Port#" : "remote.";
      String rule = isJava ? "AI-GUARD-002" : "AI-PY-005";
      Path root =
          source(
              isJava ? "Runner.java" : "app.py",
              isJava
                  ? java("Object a=Port.mint(); if(!Port.permit(a))return; Port.publish(a);")
                  : python(
                      "    a=remote.mint()\n"
                          + "    if not remote.permit(a):\n"
                          + "        return\n"
                          + "    remote.publish(a)\n"));
      mappedDisposition(
          scan(root, "generic", guardPolicy(prefix, "candidate", "closed")), rule, "UNKNOWN");
      mappedDisposition(
          scan(root, "generic", guardPolicy(prefix, "reviewed", "unknown")), rule, "UNKNOWN");
      mappedDisposition(
          scan(root, "generic", guardPolicy(prefix, "reviewed", "open")), rule, "VIOLATED");
      String mapping = guardPolicy(prefix, "reviewed", "closed");
      mapping =
          mapping.substring(0, mapping.length() - 1)
              + ",\"sourceDigests\":[\"0000000000000000000000000000000000000000000000000000000000000000\"]}";
      Map<String, Object> report = scan(root, "generic", mapping);
      assertTrue(mapped(report, rule).isEmpty());
      assertTrue(has(report, rule, "UNKNOWN"));
      assertFalse(has(report, rule, "NOT_APPLICABLE"));
      boolean stale = false;
      for (Map<String, Object> finding : items(report, "assessments"))
        if (rule.equals(finding.get("ruleId")))
          for (Map<String, Object> reason : items(finding, "unknownReasons"))
            if ("STALE_SOURCE_MAPPING".equals(reason.get("code"))) {
              stale = true;
              assertTrue(items(finding, "evidence").isEmpty());
              assertFalse(finding.containsKey("semanticOrigin"));
            }
      assertTrue(stale);
      assertEquals(Boolean.FALSE, object(report, "project").get("aiDetected"));
      assertEquals(Boolean.FALSE, object(report, "mappingCoverage").get("sourceDigestMatched"));
    }
  }

  private String aclPolicy(String prefix) {
    return policy(
        contract(prefix + "who", 0, "\"kind\":\"source\",\"label\":\"trusted-identity\""),
        contract(prefix + "document", 0, "\"kind\":\"source\",\"label\":\"knowledge\""),
        contract(
            prefix + "scope",
            2,
            "\"kind\":\"check\",\"control\":\"scope\",\"args\":[0,1],\"accept\":true,\"failureMode\":\"closed\""),
        contract(
            prefix + "acl",
            2,
            "\"kind\":\"check\",\"control\":\"doc-acl\",\"args\":[0,1],\"accept\":true,\"failureMode\":\"closed\""),
        contract(
            prefix + "fetch",
            2,
            "\"kind\":\"sink\",\"channel\":\"retrieve\",\"identity\":0,\"args\":[1],\"scope\":\"restricted\""));
  }

  @Test
  public void retrievalRequiresBothDocumentAclAndSameSiteIdentityScope() throws Exception {
    for (boolean isJava : Arrays.asList(Boolean.TRUE, Boolean.FALSE)) {
      String text =
          isJava
              ? java(
                  "Object u=Port.who(); Object d=Port.document(); if(!Port.scope(u,d))return;"
                      + " if(!Port.acl(u,d))return; Port.fetch(u,d);")
              : python(
                  "    u=remote.who()\n"
                      + "    d=remote.document()\n"
                      + "    if not remote.scope(u,d):\n"
                      + "        return\n"
                      + "    if not remote.acl(u,d):\n"
                      + "        return\n"
                      + "    remote.fetch(u,d)\n");
      String file = isJava ? "Runner.java" : "app.py", rule = isJava ? "AI-L2-003" : "AI-PY-002";
      String mapping = aclPolicy(isJava ? "remote.Port#" : "remote.");
      mappedDisposition(scan(source(file, text), "generic", mapping), rule, "OBSERVED");
      String withoutScope =
          text.replace(
              isJava
                  ? "if(!Port.scope(u,d))return;"
                  : "    if not remote.scope(u,d):\n        return\n",
              "");
      mappedDisposition(scan(source(file, withoutScope), "generic", mapping), rule, "VIOLATED");
      String candidateIdentity =
          mapping.replace(
              "\"label\":\"trusted-identity\"",
              "\"label\":\"trusted-identity\",\"assurance\":\"candidate\"");
      mappedDisposition(scan(source(file, text), "generic", candidateIdentity), rule, "UNKNOWN");
    }
  }

  @Test
  public void onlySelectedBusinessRulesPublishButAllSemanticFactsCanBeReused() throws Exception {
    Path root =
        source(
            "app.py",
            python(
                "    u=remote.who()\n"
                    + "    d=remote.document()\n"
                    + "    if not remote.scope(u,d):\n"
                    + "        return\n"
                    + "    if not remote.acl(u,d):\n"
                    + "        return\n"
                    + "    remote.fetch(u,d)\n"));
    Map<String, Object> report = scan(root, "bank-common", aclPolicy("remote."));
    mappedDisposition(report, "AI-PY-002", "OBSERVED");
    assertFalse(has(report, BusinessPolicy.ACL, "OBSERVED"));
    for (Map<String, Object> finding : items(report, "assessments"))
      assertFalse(String.valueOf(finding.get("ruleId")).startsWith("BANK-INTERNAL-"));
  }

  @Test
  public void mixedLanguagesNeverShareSiteConclusions() throws Exception {
    Path root =
        source(
            "Runner.java",
            java("Object a=Port.mint(); if(!Port.permit(a))return; Port.publish(a);"));
    Files.write(
        root.resolve("app.py"),
        python("    a=remote.mint()\n    remote.publish(a)\n").getBytes(StandardCharsets.UTF_8));
    Map<String, Object> report =
        scan(root, "generic", guardPolicy("remote.Port#", "reviewed", "closed"));
    mappedDisposition(report, "AI-GUARD-002", "OBSERVED");
    assertTrue(mapped(report, "AI-PY-005").isEmpty());
    assertTrue(has(report, "AI-PY-005", "UNKNOWN"));
    for (Map<String, Object> site : items(mapped(report, "AI-GUARD-002").get(0), "siteAssessments"))
      assertEquals("Runner.java", site.get("path"));
  }

  @Test
  public void emptyAndUnmatchedContractsDoNotAlterGenericFindings() throws Exception {
    Path root =
        source(
            "app.py",
            "from openai import OpenAI\n"
                + "client=OpenAI()\n"
                + "def run():\n"
                + "    r=client.chat.completions.create(model='m',messages=[])\n"
                + "    return r.choices[0].message.content\n");
    Map<String, Object> baseline = new Scanner().scan(root, "generic-semantics", NEVER);
    Map<String, Object> empty = scan(root, "generic", policy());
    Map<String, Object> unrelated =
        scan(root, "generic", guardPolicy("nowhere.", "reviewed", "closed"));
    assertEquals(baseline.get("assessments"), empty.get("assessments"));
    assertEquals(baseline.get("assessments"), unrelated.get("assessments"));
    assertEquals(baseline.get("project"), unrelated.get("project"));
    assertEquals(baseline.get("unknownSummary"), unrelated.get("unknownSummary"));
  }

  @Test
  public void releaseOfNonModelValueCannotEstablishGenericModelGuard() throws Exception {
    Path root =
        source(
            "Runner.java",
            java("Object a=Port.mint(); if(!Port.permit(a))return; Port.publish(a);"));
    Map<String, Object> report =
        scan(
            root,
            "generic",
            guardPolicy("remote.Port#", "reviewed", "closed").replace("model-output", "knowledge"));
    assertTrue(mapped(report, "AI-GUARD-002").isEmpty());
    assertEquals(Boolean.FALSE, object(report, "project").get("aiDetected"));
  }

  @Test
  public void sameLineDifferentCallsNeverCombineIntoAnObservedRetrieval() throws Exception {
    String text =
        java(
            "Object u=Port.who(); Object a=Port.document(); Object b=Port.document();"
                + " if(!Port.scope(u,a))return; if(!Port.acl(u,b))return; Port.fetch(u,a);"
                + " Port.fetch(u,b);");
    Map<String, Object> report =
        scan(source("Runner.java", text), "generic", aclPolicy("remote.Port#"));
    mappedDisposition(report, "AI-L2-003", "VIOLATED");
    assertFalse(has(report, "AI-L2-003", "OBSERVED"));
  }

  @Test
  public void sameLineViolationAndUnknownPathsRemainSeparate() throws Exception {
    String text =
        "import remote.Port; class Runner { void run(Object stranger) {"
            + " Object u=Port.who(); Object d=Port.document(); if(!Port.acl(u,d))return;"
            + " Port.fetch(u,d); Port.fetch(stranger,d); } }";
    Map<String, Object> report =
        scan(source("Runner.java", text), "generic", aclPolicy("remote.Port#"));
    List<Map<String, Object>> projected = mapped(report, "AI-L2-003");
    assertEquals(2, projected.size());
    assertTrue(has(report, "AI-L2-003", "VIOLATED"));
    assertTrue(has(report, "AI-L2-003", "UNKNOWN"));
    assertFalse(has(report, "AI-L2-003", "OBSERVED"));
    for (Map<String, Object> finding : projected)
      if ("UNKNOWN".equals(finding.get("disposition")))
        assertFalse(items(finding, "unknownReasons").isEmpty());
  }

  @Test
  public void iamUncoveredScopeIsReflectedInRetrievalCoverageFlag() throws Exception {
    String text =
        java("Object u=Port.who(); Object d=Port.document(); if(!Port.scope(u,d))return;"
                + " if(!Port.acl(u,d))return; Port.fetch(u,d);")
            .replace("} }", "} void other(Object u,Object d){Port.access(u,d);} }");
    String mapping = aclPolicy("remote.Port#");
    mapping =
        mapping.substring(0, mapping.length() - 2)
            + ","
            + contract(
                "remote.Port#access",
                2,
                "\"kind\":\"sink\",\"channel\":\"access\",\"identity\":0,\"args\":[1],\"scope\":\"restricted\"")
            + "]}";
    Map<String, Object> report = scan(source("Runner.java", text), "generic", mapping);
    mappedDisposition(report, "AI-L2-003", "OBSERVED");
    assertEquals(
        Boolean.TRUE, mapped(report, "AI-L2-003").get(0).get("semanticCoverageIncomplete"));
  }

  @Test
  public void truncatedSitesDoNotImplyWholeRuleCoverage() throws Exception {
    StringBuilder body =
        new StringBuilder(
            "Object u=Port.who(); Object d=Port.document();"
                + " if(!Port.scope(u,d))return; if(!Port.acl(u,d))return;\n");
    for (int i = 0; i < 130; i++) body.append("Port.fetch(u,d);\n");
    Map<String, Object> report =
        scan(source("Runner.java", java(body.toString())), "generic", aclPolicy("remote.Port#"));
    mappedDisposition(report, "AI-L2-003", "OBSERVED");
    Map<String, Object> finding = mapped(report, "AI-L2-003").get(0);
    assertEquals(Boolean.TRUE, finding.get("semanticCoverageIncomplete"));
    assertEquals(Boolean.TRUE, finding.get("siteAssessmentsTruncated"));
    assertEquals(128, items(finding, "siteAssessments").size());
    assertEquals(Boolean.FALSE, report.get("securityVerified"));
  }

  @Test
  public void candidateModelSourceCannotEstablishObservedGuardOrAiDetection() throws Exception {
    Path root =
        source(
            "Runner.java",
            java("Object a=Port.mint(); if(!Port.permit(a))return; Port.publish(a);"));
    String mapping =
        guardPolicy("remote.Port#", "reviewed", "closed")
            .replace(
                "\"label\":\"model-output\"",
                "\"label\":\"model-output\",\"assurance\":\"candidate\"");
    Map<String, Object> report = scan(root, "generic", mapping);
    mappedDisposition(report, "AI-GUARD-002", "UNKNOWN");
    assertEquals(Boolean.FALSE, object(report, "project").get("aiDetected"));
  }

  @Test
  public void nonModelViolationOnSameLineCannotBecomeModelGuardViolation() throws Exception {
    String text =
        java(
            "Object a=Port.mint(); Object d=Port.document();"
                + " if(!Port.permit(a))return; Port.publish(a); Port.publish(d);");
    String mapping =
        guardPolicy("remote.Port#", "reviewed", "closed")
            .replace(",\"requiresLabel\":\"model-output\"", "");
    mapping =
        mapping.substring(0, mapping.length() - 2)
            + ","
            + contract("remote.Port#document", 0, "\"kind\":\"source\",\"label\":\"knowledge\"")
            + "]}";
    Map<String, Object> report = scan(source("Runner.java", text), "generic", mapping);
    mappedDisposition(report, "AI-GUARD-002", "OBSERVED");
    assertFalse(has(report, "AI-GUARD-002", "VIOLATED"));
  }

  private static boolean mappedHas(Map<String, Object> report, String rule, String disposition) {
    for (Map<String, Object> finding : mapped(report, rule))
      if (disposition.equals(finding.get("disposition"))) return true;
    return false;
  }

  private String protectedGuardSites(int count) {
    StringBuilder body = new StringBuilder("Object a=Port.mint(); if(!Port.permit(a))return;\n");
    for (int i = 0; i < count; i++) body.append("Port.publish(a);\n");
    return body.toString();
  }

  @Test
  public void lateGuardViolationSurvivesTheSiteCap() throws Exception {
    Path root =
        source(
            "Runner.java",
            java(protectedGuardSites(128) + "Object b=Port.mint(); Port.publish(b);"));
    Map<String, Object> report =
        scan(root, "generic", guardPolicy("remote.Port#", "reviewed", "closed"));
    assertTrue(mappedHas(report, "AI-GUARD-002", "VIOLATED"));
    assertEquals("BLOCK", report.get("gateDecision"));
    for (Map<String, Object> finding : mapped(report, "AI-GUARD-002")) {
      assertTrue(items(finding, "siteAssessments").size() <= 128);
      assertEquals(Boolean.TRUE, finding.get("semanticCoverageIncomplete"));
      if ("VIOLATED".equals(finding.get("disposition")))
        assertEquals(130, items(finding, "siteAssessments").get(0).get("line"));
    }
  }

  @Test
  public void lateRetrievalIdentityViolationKeepsItsAclPair() throws Exception {
    StringBuilder body =
        new StringBuilder(
            "Object u=Port.who(); Object d=Port.document();"
                + " if(!Port.scope(u,d))return; if(!Port.acl(u,d))return;\n");
    for (int i = 0; i < 128; i++) body.append("Port.fetch(u,d);\n");
    body.append(
        "Object another=Port.who(); if(!Port.acl(another,d))return; Port.fetch(another,d);");
    Map<String, Object> report =
        scan(source("Runner.java", java(body.toString())), "generic", aclPolicy("remote.Port#"));
    assertTrue(mappedHas(report, "AI-L2-003", "VIOLATED"));
    assertFalse(
        "The late ACL companion must be retained rather than invented as unknown",
        mappedHas(report, "AI-L2-003", "UNKNOWN"));
    assertEquals("BLOCK", report.get("gateDecision"));
  }

  @Test
  public void nonModelViolationCannotHideUnlocatedModelBindingFailure() throws Exception {
    String mapping =
        guardPolicy("remote.Port#", "reviewed", "closed")
            .replace(",\"requiresLabel\":\"model-output\"", "");
    mapping =
        combinePolicies(
            mapping,
            policy(
                contract(
                    "remote.Port#document", 0, "\"kind\":\"source\",\"label\":\"knowledge\"")));
    Path root =
        source("Runner.java", java("Port.publish(Port.document()); Port.publish(Port.mint(), 3);"));
    Map<String, Object> report = scan(root, "generic", mapping);
    unlocatedReason(report, "AI-GUARD-002", "ARGUMENT_BINDING_UNRESOLVED");
    assertFalse(mappedHas(report, "AI-GUARD-002", "VIOLATED"));
    assertFalse(has(report, "AI-GUARD-002", "NOT_APPLICABLE"));
  }

  private String combinePolicies(String left, String right) {
    return left.substring(0, left.length() - 2) + "," + right.substring(right.indexOf('[') + 1);
  }

  @Test
  public void mixedLanguageLateViolationRetainsOnlyItsOwnLanguage() throws Exception {
    Path root = source("Runner.java", java(protectedGuardSites(130)));
    Files.write(
        root.resolve("app.py"),
        python("    a=remote.mint()\n    remote.publish(a)\n").getBytes(StandardCharsets.UTF_8));
    String mapping =
        combinePolicies(
            guardPolicy("remote.Port#", "reviewed", "closed"),
            guardPolicy("remote.", "reviewed", "closed"));
    Map<String, Object> report = scan(root, "generic", mapping);
    assertTrue(mappedHas(report, "AI-PY-005", "VIOLATED"));
    assertFalse(mappedHas(report, "AI-GUARD-002", "VIOLATED"));
    mappedDisposition(report, "AI-GUARD-002", "OBSERVED");
    for (Map<String, Object> finding : mapped(report, "AI-PY-005"))
      for (Map<String, Object> site : items(finding, "siteAssessments"))
        assertEquals("app.py", site.get("path"));
    assertEquals("BLOCK", report.get("gateDecision"));
  }

  private static void unlocatedReason(Map<String, Object> report, String rule, String code) {
    boolean found = false;
    for (Map<String, Object> finding : items(report, "assessments")) {
      if (!rule.equals(finding.get("ruleId"))) continue;
      for (Map<String, Object> reason : items(finding, "unknownReasons"))
        if (code.equals(reason.get("code"))) {
          found = true;
          assertEquals("UNSUPPORTED", reason.get("category"));
          assertEquals("UNKNOWN", finding.get("disposition"));
          assertTrue(items(finding, "evidence").isEmpty());
          assertFalse(finding.containsKey("semanticOrigin"));
        }
    }
    assertTrue("Missing unlocated reason " + code + ": " + report, found);
  }

  @Test
  public void argumentBindingFailureBeforeFirstSinkHasUnlocatedUnsupportedScope() throws Exception {
    Map<String, Object> javaReport =
        scan(
            source("Runner.java", java("Port.publish(Port.mint(), 3);")),
            "generic",
            guardPolicy("remote.Port#", "reviewed", "closed"));
    unlocatedReason(javaReport, "AI-GUARD-002", "ARGUMENT_BINDING_UNRESOLVED");
    assertFalse(has(javaReport, "AI-GUARD-002", "NOT_APPLICABLE"));
    Map<String, Object> pythonReport =
        scan(
            source("app.py", python("    remote.publish(payload=remote.mint())\n")),
            "generic",
            guardPolicy("remote.", "reviewed", "closed"));
    unlocatedReason(pythonReport, "AI-PY-005", "ARGUMENT_BINDING_UNRESOLVED");
  }

  @Test
  public void firstSinkBeyondParserDepthHasUnlocatedUnsupportedScope() throws Exception {
    StringBuilder body = new StringBuilder();
    for (int i = 0; i < 70; i++) body.append("if(true){");
    body.append("Object a=Port.mint(); Port.publish(a);");
    for (int i = 0; i < 70; i++) body.append('}');
    Map<String, Object> report =
        scan(
            source("Runner.java", java(body.toString())),
            "generic",
            guardPolicy("remote.Port#", "reviewed", "closed"));
    unlocatedReason(report, "AI-GUARD-002", "SOURCE_FLOW_INCOMPLETE");
    assertTrue(mapped(report, "AI-GUARD-002").isEmpty());
    assertFalse(has(report, "AI-GUARD-002", "NOT_APPLICABLE"));
  }

  @Test
  public void sharedFlowBudgetBeforeFirstSinkHasUnlocatedUnsupportedScope() throws Exception {
    Path root = source("Runner.java", java("Object a=Port.mint(); Port.publish(a);"));
    Inventory inventory = Inventory.load(root, NEVER);
    BusinessPolicy mapping =
        BusinessPolicy.parse("generic", guardPolicy("remote.Port#", "reviewed", "closed"));
    BusinessFlow.Program program =
        BusinessJavaAnalysis.adapt(inventory.javaAndConfig, NEVER, mapping);
    assertEquals(1, program.functions.size());
    BusinessFlow.Function function = program.functions.get(0);
    List<BusinessFlow.Stmt> original = new ArrayList<BusinessFlow.Stmt>(function.body);
    function.body.clear();
    List<BusinessFlow.Stmt> nested = function.body;
    for (int i = 0; i < 70; i++) {
      BusinessFlow.Stmt branch = new BusinessFlow.Stmt("IF");
      branch.expr = new BusinessFlow.Expr("LITERAL");
      branch.expr.literal = Boolean.TRUE;
      nested.add(branch);
      nested = branch.body;
    }
    nested.addAll(original);
    BusinessAnalysis analysis = BusinessAnalysis.analyze(program, mapping, NEVER);
    List<Map<String, Object>> findings =
        JavaAnalysis.analyze(inventory.javaAndConfig, NEVER).assessments;
    GenericSemanticAnalysis.merge(findings, analysis, mapping, inventory, NEVER);
    unlocatedReason(Findings.map("assessments", findings), "AI-GUARD-002", "BANK_ANALYSIS_BOUNDED");
  }

  @Test
  public void bindingFailureDoesNotPoisonAnotherLanguageWithUnmatchedContracts() throws Exception {
    Path root = source("Runner.java", java("Port.publish(Port.mint(), 3);"));
    Files.write(root.resolve("app.py"), "value = 1\n".getBytes(StandardCharsets.UTF_8));
    String mapping =
        combinePolicies(
            guardPolicy("remote.Port#", "reviewed", "closed"),
            guardPolicy("remote.", "reviewed", "closed"));
    Map<String, Object> report = scan(root, "generic", mapping);
    unlocatedReason(report, "AI-GUARD-002", "ARGUMENT_BINDING_UNRESOLVED");
    for (Map<String, Object> finding : items(report, "assessments"))
      if ("AI-PY-005".equals(finding.get("ruleId")))
        for (Map<String, Object> reason : items(finding, "unknownReasons"))
          assertFalse("ARGUMENT_BINDING_UNRESOLVED".equals(reason.get("code")));
  }
}
