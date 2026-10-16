package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.util.*;
import org.junit.Test;

/** Field equality is source-derived; field names never establish a security control. */
public class BusinessStructuredValueFlowTest {
  private static final Cancel NONE =
      new Cancel() {
        public void check() {}
      };

  private Map<String, Object> scan(String text, boolean python, boolean path) throws Exception {
    return scan(text, python, path, BusinessPolicy.GUARD);
  }

  private Map<String, Object> scan(String text, boolean python, boolean path, String rule)
      throws Exception {
    String prefix = python ? "port." : "port.Api#";
    List<Map<String, Object>> contracts = new ArrayList<Map<String, Object>>();
    contracts.add(
        Findings.map(
            "symbol", prefix + "make", "arity", 0, "kind", "source", "label", "model-output"));
    contracts.add(
        Findings.map(
            "symbol",
            prefix + "check",
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
            "closed"));
    Map<String, Object> release =
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
            Arrays.asList(0));
    if (path) release.put("valuePath", Arrays.asList("payload"));
    contracts.add(release);
    contracts.add(
        Findings.map(
            "symbol",
            prefix + "wrap",
            "arity",
            1,
            "kind",
            "transform",
            "control",
            "preserve",
            "arg",
            0,
            "assurance",
            "candidate"));
    contracts.add(
        Findings.map(
            "symbol", prefix + "sensitive", "arity", 0, "kind", "source", "label", "sensitive"));
    contracts.add(
        Findings.map(
            "symbol",
            prefix + "send",
            "arity",
            1,
            "kind",
            "sink",
            "channel",
            "egress",
            "args",
            Arrays.asList(0)));
    BusinessPolicy policy =
        BusinessPolicy.parse(
            "bank-common", Json.COMPACT.toJson(Findings.map("version", 2, "contracts", contracts)));
    List<SourceFile> files =
        Arrays.asList(
            new SourceFile(
                python ? "case.py" : "Example.java",
                python
                    ? "import port\n" + text
                    : "import port.Api;import java.util.Map;import java.util.LinkedHashMap;"
                        + text));
    BusinessFlow.Program program =
        python
            ? BusinessPythonAnalysis.adapt(files, NONE, policy)
            : BusinessJavaAnalysis.adapt(files, NONE, policy);
    BusinessAnalysis analysis = BusinessAnalysis.analyze(program, policy, NONE);
    for (Map<String, Object> result : analysis.assessments)
      if (rule.equals(result.get("ruleId"))) return result;
    throw new AssertionError("Missing guard assessment");
  }

  private String status(String source, boolean python, boolean path) throws Exception {
    return String.valueOf(scan(source, python, path).get("disposition"));
  }

  @Test
  public void javaMapFieldAndAliasPreserveCheckedChild() throws Exception {
    assertEquals(
        "OBSERVED",
        status(
            "class Demo {void run(){ Object v=Api.make(); Map<String,Object> m=new"
                + " LinkedHashMap<String,Object>(); Map<String,Object> alias=m;"
                + " alias.put(\"payload\",v); if(Api.check(v)) Api.release(m); }}",
            false,
            true));
  }

  @Test
  public void javaWrongFieldDoesNotBorrowGuard() throws Exception {
    assertEquals(
        "VIOLATED",
        status(
            "class Demo {void run(){ Object v=Api.make(), w=Api.make(); Map<String,Object> m=new"
                + " LinkedHashMap<String,Object>(); m.put(\"payload\",w); if(Api.check(v))"
                + " Api.release(m); }}",
            false,
            true));
  }

  @Test
  public void javaPutAfterGuardKeepsUnchangedChildProof() throws Exception {
    assertEquals(
        "OBSERVED",
        status(
            "class Demo {void run(){ Object v=Api.make(); Map<String,Object> m=new"
                + " LinkedHashMap<String,Object>(); if(Api.check(v)){m.put(\"payload\",v);"
                + " Api.release(m);} }}",
            false,
            true));
  }

  @Test
  public void mutationCannotResurrectPreviouslyReturnedDecision() throws Exception {
    assertNotEquals(
        "OBSERVED",
        status(
            "class Demo {void run(){ Map<String,Object> m=new LinkedHashMap<String,Object>();"
                + " m.put(\"payload\",Api.make()); boolean ok=Api.check(m);"
                + " m.put(\"payload\",Api.make()); if(ok) Api.release(m); }}",
            false,
            false));
  }

  @Test
  public void branchWritesCannotContaminateSiblingPath() throws Exception {
    assertEquals(
        "VIOLATED",
        status(
            "class Demo {void run(boolean condition){ Object v=Api.make(), w=Api.make();"
                + " Map<String,Object> m=new LinkedHashMap<String,Object>(); m.put(\"payload\",w);"
                + " if(condition) m.put(\"payload\",v); if(Api.check(v)) Api.release(m); }}",
            false,
            true));
  }

  @Test
  public void unknownMutationCannotKeepFieldProof() throws Exception {
    assertNotEquals(
        "OBSERVED",
        status(
            "class Demo {void run(){ Object v=Api.make(); Map<String,Object> m=new"
                + " LinkedHashMap<String,Object>(); m.put(\"payload\",v);"
                + " if(Api.check(v)){unknown(m); Api.release(m);} } void unknown(Object x){} }",
            false,
            true));
  }

  @Test
  public void sourceConstructorFactoryAndGetterPreserveExactValue() throws Exception {
    assertEquals(
        "OBSERVED",
        status(
            "final class Box {private Object payload; Box(Object v){this.payload=v;} final Object"
                + " extract(){return this.payload;} static Box wrap(Object v){return new Box(v);}}"
                + " class Demo {void run(){Object v=Api.make(); Box box=Box.wrap(v);"
                + " if(Api.check(v)) Api.release(box.extract());}}",
            false,
            false));
  }

  @Test
  public void sourceSetterTracksTheActualField() throws Exception {
    assertEquals(
        "OBSERVED",
        status(
            "final class Box {private Object payload; Box(){} final void set(Object"
                + " v){this.payload=v;}} class Demo {void run(){Object v=Api.make(); Box box=new"
                + " Box(); box.set(v); if(Api.check(v)) Api.release(box);}}",
            false,
            true));
  }

  @Test
  public void arbitraryGetterOrGeneratedSetterDoesNotEstablishEquality() throws Exception {
    assertNotEquals(
        "OBSERVED",
        status(
            "class Box {Object payload; Box(){} Object get(){return null;}} class Demo {void"
                + " run(){Object v=Api.make(); Box box=new Box(); box.setPayload(v);"
                + " if(Api.check(v)) Api.release(box.get());}}",
            false,
            false));
  }

  @Test
  public void pythonDictionaryGetAndWritePreserveChild() throws Exception {
    assertEquals(
        "OBSERVED",
        status(
            "def run():\n"
                + "    v = port.make()\n"
                + "    out = {}\n"
                + "    out['payload'] = v\n"
                + "    alias = out\n"
                + "    if port.check(v):\n"
                + "        port.release(alias.get('payload'))\n",
            true,
            false));
  }

  @Test
  public void pythonWrongObjectAndDefaultAreDistinct() throws Exception {
    assertEquals(
        "VIOLATED",
        status(
            "def run():\n"
                + "    v = port.make()\n"
                + "    w = port.make()\n"
                + "    out = {'other': v}\n"
                + "    if port.check(v):\n"
                + "        port.release(out.get('payload', w))\n",
            true,
            false));
  }

  @Test
  public void pythonDynamicDictionaryKeyRemainsUnknown() throws Exception {
    assertNotEquals(
        "OBSERVED",
        status(
            "def run(key):\n"
                + "    v = port.make()\n"
                + "    out = {'payload': v}\n"
                + "    out[key] = port.make()\n"
                + "    if port.check(v):\n"
                + "        port.release(out)\n",
            true,
            true));
  }

  @Test
  public void jsonConstantHasBoundedExactFields() throws Exception {
    assertEquals(
        "OBSERVED",
        status(
            "import json\n"
                + "def run():\n"
                + "    out = json.loads('{\"payload\":\"fixed\"}')\n"
                + "    if port.check(out['payload']):\n"
                + "        port.release(out)\n",
            true,
            true));
  }

  @Test
  public void dynamicJsonAndHookCannotInventFields() throws Exception {
    for (String value :
        Arrays.asList("port.make()", "'{\"payload\":\"fixed\"}', object_hook=custom"))
      assertNotEquals(
          "OBSERVED",
          status(
              "import json\ndef run():\n    out = json.loads("
                  + value
                  + ")\n    if port.check(out['payload']):\n        port.release(out)\n",
              true,
              true));
  }

  @Test
  public void knownEnvelopeWithOpaqueMemberNoLongerReportsMissingProjection() throws Exception {
    Map<String, Object> result =
        scan(
            "class Demo {void run(Object x){Map<String,Object> out=new"
                + " LinkedHashMap<String,Object>(); out.put(\"payload\",x); Api.release(out);}}",
            false,
            true);
    assertFalse(Json.COMPACT.toJson(result).contains("VALUE_PROJECTION_UNRESOLVED"));
  }

  @Test
  public void overwrittenCheckHistoryDoesNotResurrectOldEnvelopeDecision() throws Exception {
    assertNotEquals(
        "OBSERVED",
        status(
            "class Demo {void run(){Map<String,Object> m=new"
                + " LinkedHashMap<String,Object>();m.put(\"payload\",Api.make());boolean"
                + " first=Api.check(m);boolean"
                + " second=Api.check(m);m.put(\"payload\",Api.make());if(first)Api.release(m);}}",
            false,
            false));
  }

  @Test
  public void sensitiveFieldWritesAndNestedAliasesRemainSensitiveAtEgress() throws Exception {
    for (String body :
        Arrays.asList(
            "Map<String,Object> out=new"
                + " LinkedHashMap<String,Object>();out.put(\"payload\",Api.sensitive());Api.send(out);",
            "Map<String,Object> out=new LinkedHashMap<String,Object>();Map<String,Object>"
                + " nested=new"
                + " LinkedHashMap<String,Object>();out.put(\"nested\",nested);nested.put(\"payload\",Api.sensitive());Api.send(out);")) {
      Map<String, Object> report =
          scan("class Demo{void run(){" + body + "}}", false, false, BusinessPolicy.DATA);
      assertEquals(report.toString(), "VIOLATED", report.get("disposition"));
    }
  }

  @Test
  public void nestedObjectMutationInvalidatesWholeEnvelopeGuard() throws Exception {
    assertNotEquals(
        "OBSERVED",
        status(
            "class Demo{void run(){Map<String,Object> out=new"
                + " LinkedHashMap<String,Object>();Map<String,Object> child=new"
                + " LinkedHashMap<String,Object>();out.put(\"child\",child);child.put(\"payload\",Api.make());boolean"
                + " accepted=Api.check(out);child.put(\"payload\",Api.make());if(accepted)Api.release(out);}}",
            false,
            false));
  }

  @Test
  public void pythonThreeConditionsRetainShortCircuitOrderAndContradictions() throws Exception {
    assertEquals(
        "OBSERVED",
        status(
            "def run():\n"
                + "    v=port.make()\n"
                + "    out={'payload':v}\n"
                + "    if True and port.check(v) and True:\n"
                + "        port.release(out)\n",
            true,
            true));
    assertNotEquals(
        "VIOLATED",
        status(
            "def run():\n"
                + "    v=port.make()\n"
                + "    accepted=port.check(v)\n"
                + "    if accepted and True and not accepted:\n"
                + "        port.release(v)\n",
            true,
            false));
  }

  @Test
  public void dynamicAdditionCannotPreservePrecedingGuardOfItsOperand() throws Exception {
    assertNotEquals(
        "OBSERVED",
        status(
            "def run():\n"
                + "    chunk=port.make()\n"
                + "    full=''\n"
                + "    if port.check(chunk):\n"
                + "        full += chunk\n"
                + "        port.release(chunk)\n",
            true,
            false));
  }

  @Test
  public void malformedAndDynamicJsonRetainUncheckedExceptionalRelease() throws Exception {
    for (String input : Arrays.asList("'{broken'", "external")) {
      Map<String, Object> result =
          scan(
              "import json\n"
                  + "def run(external):\n"
                  + "    checked=port.make()\n"
                  + "    other=port.make()\n"
                  + "    if port.check(checked):\n"
                  + "        try:\n"
                  + "            json.loads("
                  + input
                  + ")\n"
                  + "        except Exception:\n"
                  + "            port.release(other)\n"
                  + "        port.release(checked)\n",
              true,
              false);
      if (input.startsWith("'"))
        assertEquals(result.toString(), "VIOLATED", result.get("disposition"));
      else assertNotEquals(result.toString(), "OBSERVED", result.get("disposition"));
      boolean catchLocated = false;
      for (Object site : (List<?>) result.get("siteAssessments"))
        catchLocated |= Integer.valueOf(10).equals(((Map<?, ?>) site).get("line"));
      assertTrue("Exceptional release must remain visible: " + result, catchLocated);
    }
  }

  @Test
  public void duplicateJsonKeysDoNotMakeNormalReleaseUnreachable() throws Exception {
    Map<String, Object> result =
        scan(
            "import json\n"
                + "def run():\n"
                + "    other=port.make()\n"
                + "    json.loads('{\"key\":1,\"key\":2}')\n"
                + "    port.release(other)\n",
            true,
            false);
    assertNotEquals("OBSERVED", result.get("disposition"));
    assertTrue(result.toString(), ((Number) result.get("mappedPathOutcomes")).intValue() > 0);
  }

  @Test
  public void sourceConstructorDoesNotIgnoreStaticInitializationEffects() throws Exception {
    assertNotEquals(
        "OBSERVED",
        status(
            "final class Box{static{Api.unknown();}Object payload;Box(Object"
                + " v){this.payload=v;}}class Demo{void run(){Object"
                + " v=Api.make();if(Api.check(v)){Box box=new Box(v);Api.release(box);}}",
            false,
            true));
  }

  @Test
  public void candidatePreserveDoesNotProveMemberEqualityBeforeOrAfterWrite() throws Exception {
    for (String mutation : Arrays.asList("", "    result['other']='x'\n"))
      assertEquals(
          "UNKNOWN",
          status(
              "def run():\n"
                  + "    checked=port.make()\n"
                  + "    box={'payload':checked}\n"
                  + "    result=port.wrap(box)\n"
                  + mutation
                  + "    if port.check(checked):\n        port.release(result['payload'])\n",
              true,
              false));
  }

  @Test
  public void dynamicJsonCannotRetainItsOperandsOldGuardInCatch() throws Exception {
    assertNotEquals(
        "OBSERVED",
        status(
            "import json\n"
                + "def run():\n"
                + "    checked=port.make()\n"
                + "    if port.check(checked):\n"
                + "        try:\n"
                + "            json.loads(checked)\n"
                + "        except Exception:\n"
                + "            port.release(checked)\n",
            true,
            false));
  }

  @Test
  public void unknownGetAndItemWriteRetainExceptionalRelease() throws Exception {
    for (String expression : Arrays.asList("external.get('key')", "external['key']='value'")) {
      Map<String, Object> result =
          scan(
              "def run(external):\n"
                  + "    checked=port.make()\n"
                  + "    other=port.make()\n"
                  + "    if port.check(checked):\n"
                  + "        try:\n"
                  + "            "
                  + expression
                  + "\n"
                  + "        except Exception:\n"
                  + "            port.release(other)\n"
                  + "        port.release(checked)\n",
              true,
              false);
      assertNotEquals(result.toString(), "OBSERVED", result.get("disposition"));
      boolean catchLocated = false;
      for (Object site : (List<?>) result.get("siteAssessments"))
        catchLocated |= Integer.valueOf(9).equals(((Map<?, ?>) site).get("line"));
      assertTrue("Exceptional release must remain visible: " + result, catchLocated);
    }
  }

  @Test
  public void ignoringCandidateTransformResultCannotRetainInputApproval() throws Exception {
    for (String call :
        Arrays.asList(
            "        port.wrap(box)\n        port.release(box)\n",
            "        try:\n"
                + "            port.wrap(box)\n"
                + "        except Exception:\n"
                + "            port.release(box)\n"))
      assertNotEquals(
          "OBSERVED",
          status(
              "def run():\n"
                  + "    checked=port.make()\n"
                  + "    box={'payload':checked}\n"
                  + "    if port.check(box):\n"
                  + call,
              true,
              false));
  }
}
