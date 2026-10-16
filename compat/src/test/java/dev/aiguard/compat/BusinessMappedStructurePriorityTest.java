package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.util.*;
import org.junit.Test;

/** Explicit qualified contracts outrank optional source/container summaries. */
public class BusinessMappedStructurePriorityTest {
  private static final Cancel NONE =
      new Cancel() {
        public void check() {}
      };

  private Map<String, Object> source(String symbol, int arity, String label) {
    return Findings.map("symbol", symbol, "arity", arity, "kind", "source", "label", label);
  }

  private Map<String, Object> check(String symbol) {
    return Findings.map(
        "symbol",
        symbol,
        "arity",
        1,
        "kind",
        "check",
        "control",
        "guard",
        "args",
        Arrays.asList(0),
        "accept",
        true,
        "failureMode",
        "closed");
  }

  private String scan(String code, boolean python, String rule, List<Map<String, Object>> contracts)
      throws Exception {
    return String.valueOf(scanFinding(code, python, rule, contracts).get("disposition"));
  }

  private Map<String, Object> scanFinding(
      String code, boolean python, String rule, List<Map<String, Object>> contracts)
      throws Exception {
    List<SourceFile> files =
        Arrays.asList(
            new SourceFile(
                python ? "case.py" : "Demo.java", python ? code : "package demo;" + code));
    return scanFiles(files, python, rule, contracts);
  }

  private Map<String, Object> scanFiles(
      List<SourceFile> files, boolean python, String rule, List<Map<String, Object>> contracts)
      throws Exception {
    BusinessPolicy policy =
        BusinessPolicy.parse(
            "bank-common", Json.COMPACT.toJson(Findings.map("version", 2, "contracts", contracts)));
    BusinessFlow.Program program =
        python
            ? BusinessPythonAnalysis.adapt(files, NONE, policy)
            : BusinessJavaAnalysis.adapt(files, NONE, policy);
    for (Map<String, Object> result : BusinessAnalysis.analyze(program, policy, NONE).assessments)
      if (rule.equals(result.get("ruleId"))) return result;
    throw new AssertionError("missing rule");
  }

  private List<Map<String, Object>> guardContracts(boolean python) {
    String prefix = python ? "port." : "port.Api#";
    List<Map<String, Object>> out = new ArrayList<Map<String, Object>>();
    out.add(check(prefix + "check"));
    out.add(
        Findings.map(
            "symbol",
            prefix + "release",
            "arity",
            1,
            "kind",
            "sink",
            "channel",
            "release",
            "args",
            Arrays.asList(0),
            "requiresLabel",
            "model-output"));
    return out;
  }

  @Test
  public void sourceGetterAndNormalReturnSetterUseExplicitSemantics() throws Exception {
    List<Map<String, Object>> contracts = guardContracts(false);
    contracts.add(source("demo.Box#value", 0, "model-output"));
    Map<String, Object> setter = check("demo.Box#accept");
    setter.put("mode", "normal-return");
    contracts.add(setter);
    assertEquals(
        "OBSERVED",
        scan(
            "import port.Api;final class Box {Object payload;Box(){}final Object value(){return"
                + " payload;}final void accept(Object value){this.payload=value;}}class Demo {void"
                + " run(){Box box=new Box();Object v=box.value();box.accept(v);Api.release(v);}}",
            false,
            BusinessPolicy.GUARD,
            contracts));
  }

  @Test
  public void mapFactoryAndConstructorSourcesRemainMappedCalls() throws Exception {
    for (String expression :
        Arrays.asList("Map.of(\"payload\",\"literal\")", "new LinkedHashMap<String,Object>()")) {
      List<Map<String, Object>> contracts = guardContracts(false);
      contracts.add(
          source(
              expression.startsWith("Map") ? "java.util.Map#of" : "java.util.LinkedHashMap#<init>",
              expression.startsWith("Map") ? 2 : 0,
              "model-output"));
      assertEquals(
          "OBSERVED",
          scan(
              "import port.Api;import java.util.Map;import java.util.LinkedHashMap;class Demo {void"
                  + " run(){Object v="
                  + expression
                  + ";if(Api.check(v))Api.release(v);}}",
              false,
              BusinessPolicy.GUARD,
              contracts));
    }
  }

  @Test
  public void mappedMapGetterTransformationIsNotPlainFieldProjection() throws Exception {
    List<Map<String, Object>> contracts = guardContracts(false);
    contracts.add(source("port.Api#make", 0, "model-output"));
    contracts.add(
        Findings.map(
            "symbol",
            "java.util.Map#get",
            "arity",
            1,
            "kind",
            "transform",
            "control",
            "preserve",
            "arg",
            -1));
    assertEquals(
        "OBSERVED",
        scan(
            "import port.Api;import java.util.Map;import java.util.LinkedHashMap;class Demo {void"
                + " run(){Map<String,Object> map=new"
                + " LinkedHashMap<String,Object>();map.put(\"payload\",Api.make());if(Api.check(map))Api.release(map.get(\"payload\"));}}",
            false,
            BusinessPolicy.GUARD,
            contracts));
  }

  @Test
  public void jsonSourceContractOverridesConstantParserSummary() throws Exception {
    List<Map<String, Object>> contracts = guardContracts(true);
    contracts.add(source("json.loads", 1, "model-output"));
    assertEquals(
        "OBSERVED",
        scan(
            "import port\n"
                + "import json\n"
                + "def run():\n"
                + "    value=json.loads('{\"payload\":\"literal\"}')\n"
                + "    if port.check(value):\n"
                + "        port.release(value)\n",
            true,
            BusinessPolicy.GUARD,
            contracts));
  }

  @Test
  public void sourceDecisionGetterStillProjectsItsOwningCheck() throws Exception {
    List<Map<String, Object>> contracts = guardContracts(false);
    contracts.add(source("port.Api#make", 0, "model-output"));
    Map<String, Object> inspect = check("port.Api#inspect");
    inspect.put("decision", Findings.map("symbol", "demo.Decision#allowed", "arg", -1));
    contracts.add(inspect);
    assertEquals(
        "OBSERVED",
        scan(
            "import port.Api;final class Decision{private boolean okay;final boolean"
                + " allowed(){return this.okay;}}class Demo{void run(){Object"
                + " text=Api.make();Decision"
                + " d=Api.inspect(text);if(d.allowed())Api.release(text);}}",
            false,
            BusinessPolicy.GUARD,
            contracts));
  }

  @Test
  public void changingReturnedDecisionCannotCompleteAcceptance() throws Exception {
    List<Map<String, Object>> contracts = guardContracts(false);
    contracts.add(source("port.Api#make", 0, "model-output"));
    Map<String, Object> inspect = check("port.Api#inspect");
    inspect.put(
        "decision",
        Findings.map(
            "all",
            Arrays.asList(
                Findings.map("symbol", "demo.Decision#allowed", "arg", -1, "accept", true),
                Findings.map("symbol", "demo.Decision#needsReview", "arg", -1, "accept", false))));
    contracts.add(inspect);
    String declarations =
        "import port.Api;final class Decision{private boolean okay;private boolean"
            + " review;Decision(boolean a,boolean r){this.okay=a;this.review=r;}final boolean"
            + " allowed(){return this.okay;}final boolean needsReview(){return this.review;}final"
            + " void setReview(boolean r){this.review=r;}}";
    for (String body :
        Arrays.asList(
            "if(d.allowed()){d.setReview(false);if(!d.needsReview())Api.release(text);}",
            "if(d.allowed()&&!d.needsReview()){d.setReview(true);Api.release(text);}"))
      assertNotEquals(
          "OBSERVED",
          scan(
              declarations
                  + "class Demo{void run(){Object text=Api.make();Decision d=Api.inspect(text);"
                  + body
                  + "}}",
              false,
              BusinessPolicy.GUARD,
              contracts));
  }

  @Test
  public void unknownDecisionMutationCannotPruneAChangedPredicateBranch() throws Exception {
    List<Map<String, Object>> contracts = guardContracts(false);
    contracts.add(source("port.Api#make", 0, "model-output"));
    Map<String, Object> inspect = check("port.Api#inspect");
    inspect.put("decision", Findings.map("symbol", "demo.Decision#allowed", "arg", -1));
    contracts.add(inspect);
    Map<String, Object> result =
        scanFinding(
            "import port.Api;final class Decision{private boolean okay;final boolean"
                + " allowed(){return this.okay;}}class Demo{void run(){Object"
                + " text=Api.make();Decision"
                + " d=Api.inspect(text);if(d.allowed()){Api.mutate(d);if(!d.allowed())Api.release(text);}}}",
            false,
            BusinessPolicy.GUARD,
            contracts);
    assertTrue(result.toString(), ((Number) result.get("mappedPathOutcomes")).intValue() > 0);
    assertNotEquals("OBSERVED", result.get("disposition"));
  }

  @Test
  public void localJsonModulesCannotBorrowStandardLibraryFieldEquality() throws Exception {
    List<Map<String, Object>> contracts = guardContracts(true);
    contracts.get(1).remove("requiresLabel");
    for (String imported : Arrays.asList("import json", "from json import loads as decode")) {
      String call = imported.startsWith("from") ? "decode" : "json.loads";
      String code =
          "import port\n"
              + imported
              + "\ndef run():\n    checked='fixed'\n    if port.check(checked):\n        result="
              + call
              + "('{\"payload\":\"fixed\"}')\n        port.release(result['payload'])\n";
      for (String path :
          Arrays.asList(
              "json.py", "json/__init__.py", "src/json.py", "src/vendor/json/__init__.py")) {
        Map<String, Object> result =
            scanFiles(
                Arrays.asList(
                    new SourceFile("app.py", code),
                    new SourceFile(
                        path, "def loads(value):\n    return {'payload':'unapproved'}\n")),
                true,
                BusinessPolicy.GUARD,
                contracts);
        assertNotEquals(path + ": " + result, "OBSERVED", result.get("disposition"));
        assertTrue(result.toString(), ((Number) result.get("mappedPathOutcomes")).intValue() > 0);
      }
    }
  }

  @Test
  public void unshadowedJsonAndUnrelatedModuleNamesRetainConstantSummary() throws Exception {
    List<Map<String, Object>> contracts = guardContracts(true);
    contracts.get(1).remove("requiresLabel");
    String code =
        "import port\n"
            + "import json\n"
            + "def run():\n"
            + "    checked='fixed'\n"
            + "    if port.check(checked):\n"
            + "        result=json.loads('{\"payload\":\"fixed\"}')\n"
            + "        port.release(result['payload'])\n";
    for (String path : Arrays.asList("json_tools.py", "vendor/myjson/__init__.py"))
      assertEquals(
          "OBSERVED",
          scanFiles(
                  Arrays.asList(
                      new SourceFile("app.py", code),
                      new SourceFile(path, "def loads(value):\n    return {}\n")),
                  true,
                  BusinessPolicy.GUARD,
                  contracts)
              .get("disposition"));
  }

  @Test
  public void explicitJsonContractStillAppliesWithLocalModule() throws Exception {
    List<Map<String, Object>> contracts = guardContracts(true);
    contracts.add(source("json.loads", 1, "model-output"));
    String code =
        "import port\n"
            + "import json\n"
            + "def run():\n"
            + "    value=json.loads('{\"payload\":\"literal\"}')\n"
            + "    if port.check(value):\n"
            + "        port.release(value)\n";
    assertEquals(
        "OBSERVED",
        scanFiles(
                Arrays.asList(
                    new SourceFile("app.py", code),
                    new SourceFile(
                        "src/json/__init__.py",
                        "def loads(value):\n    return {'payload':'local'}\n")),
                true,
                BusinessPolicy.GUARD,
                contracts)
            .get("disposition"));
  }
}
