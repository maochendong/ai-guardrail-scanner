package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.Map;
import org.junit.Test;

/** JSON syntax establishes decoded identities, never trust or inherited approval. */
public class BusinessDynamicJsonValueFlowTest {
  private static final Cancel NONE =
      new Cancel() {
        public void check() {}
      };

  private Map<String, Object> scan(String code, String rule, boolean fieldPath) throws Exception {
    String path = fieldPath ? ",\"valuePath\":[\"payload\"]" : "";
    BusinessPolicy policy =
        BusinessPolicy.parse(
            "bank-common",
            "{\"version\":2,\"contracts\":["
                + "{\"symbol\":\"port.make\",\"arity\":0,\"kind\":\"source\",\"label\":\"model-output\"},"
                + "{\"symbol\":\"port.secret\",\"arity\":0,\"kind\":\"source\",\"label\":\"sensitive\"},"
                + "{\"symbol\":\"port.identity\",\"arity\":0,\"kind\":\"source\",\"label\":\"trusted-identity\"},"
                + "{\"symbol\":\"port.check\",\"arity\":1,\"kind\":\"check\",\"control\":\"guard\",\"args\":[0],\"accept\":true,\"failureMode\":\"closed\"},"
                + "{\"symbol\":\"port.release\",\"arity\":1,\"kind\":\"sink\",\"channel\":\"release\",\"args\":[0]"
                + path
                + "},{\"symbol\":\"port.send\",\"arity\":1,\"kind\":\"sink\",\"channel\":\"egress\",\"args\":[0]}]}");
    BusinessFlow.Program program =
        BusinessPythonAnalysis.adapt(
            Arrays.asList(new SourceFile("example.py", "import port\nimport json\n" + code)),
            NONE,
            policy);
    for (Map<String, Object> item : BusinessAnalysis.analyze(program, policy, NONE).assessments)
      if (rule.equals(item.get("ruleId"))) return item;
    throw new AssertionError("missing " + rule);
  }

  private String status(String code) throws Exception {
    return String.valueOf(scan(code, BusinessPolicy.GUARD, false).get("disposition"));
  }

  @Test
  public void checkedDynamicFieldHasStableIdentity() throws Exception {
    assertEquals(
        "OBSERVED",
        status(
            "def run():\n    data=json.loads(port.make())\n"
                + "    if port.check(data['payload']):\n        port.release(data['payload'])\n"));
    assertEquals(
        "OBSERVED",
        scan(
                "def run():\n    data=json.loads(port.make())\n"
                    + "    if port.check(data['payload']):\n        port.release(data)\n",
                BusinessPolicy.GUARD,
                true)
            .get("disposition"));
  }

  @Test
  public void keyAliasesNestedFieldsAndBoundedArrayIndicesPreserveValues() throws Exception {
    assertEquals(
        "OBSERVED",
        status(
            "def run():\n    key='payload'\n    index=0\n"
                + "    data=json.loads(port.make())\n    value=data[key][index]['text']\n"
                + "    if port.check(value):\n        port.release(data['payload'][0]['text'])\n"));
    assertEquals(
        "OBSERVED",
        status(
            "def run():\n"
                + "    data=json.loads('[{\"text\":\"ready\"}]')\n"
                + "    value=data[0]['text']\n"
                + "    if port.check(value):\n"
                + "        port.release(data[0]['text'])\n"));
  }

  @Test
  public void textRootSiblingAndOtherParseDoNotBorrowFieldApproval() throws Exception {
    for (String released : Arrays.asList("raw", "data", "data['other']", "other['payload']"))
      assertNotEquals(
          "OBSERVED",
          status(
              "def run():\n"
                  + "    raw=port.make()\n"
                  + "    data=json.loads(raw)\n"
                  + "    other=json.loads(raw)\n"
                  + "    value=data['payload']\n"
                  + "    if port.check(value):\n"
                  + "        port.release("
                  + released
                  + ")\n"));
  }

  @Test
  public void runtimeDecoderInputEffectsCannotKeepEarlierApproval() throws Exception {
    assertNotEquals(
        "OBSERVED",
        status(
            "def run(raw):\n"
                + "    value=port.make()\n"
                + "    if port.check(value):\n"
                + "        json.loads(raw)\n"
                + "        port.release(value)\n"));
    assertEquals(
        "OBSERVED",
        status(
            "def run(raw):\n"
                + "    data=json.loads(raw)\n"
                + "    value=data['payload']\n"
                + "    if port.check(value):\n"
                + "        port.release(value)\n"));
  }

  @Test
  public void pureLazyReadDoesNotVersionTheCheckedRoot() throws Exception {
    assertEquals(
        "OBSERVED",
        status(
            "def run():\n"
                + "    data=json.loads(port.make())\n"
                + "    if port.check(data):\n"
                + "        child=data['payload']\n"
                + "        port.release(data)\n"));
  }

  @Test
  public void mappedFieldReadSurvivesAUniqueHelperCall() throws Exception {
    assertEquals(
        "OBSERVED",
        status(
            "def payload(data):\n    return data['payload']\n"
                + "def run():\n    data=json.loads(port.make())\n    value=payload(data)\n"
                + "    if port.check(value):\n        port.release(data['payload'])\n"));
  }

  @Test
  public void fieldWritesAliasWritesAndUnknownCallsInvalidateRelevantProofs() throws Exception {
    for (String change : Arrays.asList("alias['payload']=port.make()", "unknown(alias)"))
      assertNotEquals(
          "OBSERVED",
          status(
              "def run():\n    data=json.loads(port.make())\n"
                  + "    alias=data\n    value=data['payload']\n    if port.check(value):\n"
                  + "        "
                  + change
                  + "\n        port.release(data['payload'])\n"));
    assertNotEquals(
        "OBSERVED",
        status(
            "def run():\n"
                + "    data=json.loads(port.make())\n"
                + "    if port.check(data):\n"
                + "        child=data['payload']\n"
                + "        child['text']=port.make()\n"
                + "        port.release(data)\n"));
  }

  @Test
  public void fieldObservationAndWriteDoNotContaminateSiblingBranch() throws Exception {
    assertNotEquals(
        "OBSERVED",
        status(
            "def run(flag):\n    data=json.loads(port.make())\n"
                + "    checked=port.make()\n    if flag:\n        data['payload']=checked\n"
                + "    if port.check(checked):\n        port.release(data['payload'])\n"));
  }

  @Test
  public void getWithUnknownPresenceDoesNotBecomeSubscriptOrDefault() throws Exception {
    for (String checked : Arrays.asList("data['payload']", "fallback"))
      assertNotEquals(
          "OBSERVED",
          status(
              "def run():\n    data=json.loads(port.make())\n"
                  + "    fallback=port.make()\n    selected=data.get('payload', fallback)\n"
                  + "    if port.check("
                  + checked
                  + "):\n        port.release(selected)\n"));
    assertEquals(
        "OBSERVED",
        status(
            "def run():\n    data=json.loads(port.make())\n"
                + "    selected=data.get('payload', None)\n    if port.check(selected):\n"
                + "        port.release(selected)\n"));
  }

  @Test
  public void nativeDictionaryAndListDefaultsAllowFurtherBoundedReads() throws Exception {
    assertEquals(
        "OBSERVED",
        status(
            "def run():\n"
                + "    data=json.loads(port.make())\n"
                + "    items=data.get('recommendation', {}).get('items', [])\n"
                + "    selected=items[0]['text']\n"
                + "    if port.check(selected):\n"
                + "        port.release(selected)\n"));
    assertEquals(
        "OBSERVED",
        status(
            "def run():\n"
                + "    items=[{'text':port.make()}]\n"
                + "    selected=items[0]['text']\n"
                + "    if port.check(selected):\n"
                + "        port.release(items[0]['text'])\n"));
  }

  @Test
  public void arbitraryDefaultObjectsCannotAcquireNativeJsonShape() throws Exception {
    assertNotEquals(
        "OBSERVED",
        status(
            "def run(custom):\n    data=json.loads(port.make())\n"
                + "    selected=data.get('payload', custom)\n    if port.check(selected['text']):\n"
                + "        port.release(selected['text'])\n"));
  }

  @Test
  public void parsingAndMissingFieldCatchPathsRemainVisible() throws Exception {
    assertNotEquals(
        "OBSERVED",
        status(
            "def run():\n    raw=port.make()\n    other=port.make()\n"
                + "    try:\n        data=json.loads(raw)\n        value=data['payload']\n"
                + "        if port.check(value):\n            port.release(value)\n"
                + "    except Exception:\n        port.release(other)\n"));
  }

  @Test
  public void openSchemaAndFieldsKeepSensitiveProvenance() throws Exception {
    for (String outgoing : Arrays.asList("data", "data['payload']"))
      assertEquals(
          "VIOLATED",
          scan(
                  "def run():\n    data=json.loads(port.secret())\n"
                      + "    ignored=data['payload']\n    port.send("
                      + outgoing
                      + ")\n",
                  BusinessPolicy.DATA,
                  false)
              .get("disposition"));
  }

  @Test
  public void unresolvedKeysCustomDecodersAndArrayBoundsRemainConservative() throws Exception {
    for (String decoder :
        Arrays.asList("json.loads(port.make(), object_hook=custom)", "custom(port.make())"))
      assertNotEquals(
          "OBSERVED",
          status(
              "def run():\n    data="
                  + decoder
                  + "\n"
                  + "    if port.check(data['payload']):\n"
                  + "        port.release(data['payload'])\n"));
    assertNotEquals(
        "OBSERVED",
        status(
            "def run(key):\n    data=json.loads(port.make())\n"
                + "    if port.check(data[key]):\n        port.release(data[key])\n"));
    assertNotEquals(
        "OBSERVED",
        status(
            "def run():\n    data=json.loads(port.make())\n"
                + "    if port.check(data[129]):\n        port.release(data[129])\n"));
  }

  @Test
  public void decodedNumericKeysCannotEraseTypeErrorCatchPaths() throws Exception {
    for (String number : Arrays.asList("1.0", "1e0", "-0.0"))
      assertNotEquals(
          "OBSERVED",
          status(
              "def run():\n    key=json.loads('"
                  + number
                  + "')\n"
                  + "    items=json.loads('[\"a\",\"b\"]')\n"
                  + "    raw=port.make()\n"
                  + "    other=port.make()\n"
                  + "    if port.check(raw):\n"
                  + "        try:\n"
                  + "            ignored=items[key]\n"
                  + "        except Exception:\n"
                  + "            port.release(other)\n"
                  + "        port.release(raw)\n"));
  }

  @Test
  public void getAndSubscriptPossibleAliasesInvalidateBothDirections() throws Exception {
    assertNotEquals(
        "OBSERVED",
        status(
            "def run():\n    data=json.loads(port.make())\n"
                + "    selected=data.get('x')\n    if port.check(selected):\n"
                + "        data['x']['a']=port.make()\n        port.release(selected)\n"));
    assertNotEquals(
        "OBSERVED",
        status(
            "def run():\n    data=json.loads(port.make())\n"
                + "    selected=data.get('x')\n    field=data['x']\n    if port.check(field):\n"
                + "        selected['a']=port.make()\n        port.release(field)\n"));
    assertNotEquals(
        "OBSERVED",
        status(
            "def run():\n"
                + "    data=json.loads(port.make())\n"
                + "    fallback={}\n"
                + "    selected=data.get('x', fallback)\n"
                + "    if port.check(fallback):\n"
                + "        selected['a']=port.make()\n"
                + "        port.release(fallback)\n"));
    assertNotEquals(
        "OBSERVED",
        status(
            "def run():\n"
                + "    data=json.loads(port.make())\n"
                + "    fallback={}\n"
                + "    selected=data.get('x', fallback)\n"
                + "    if port.check(selected):\n"
                + "        fallback['a']=port.make()\n"
                + "        port.release(selected)\n"));
  }

  @Test
  public void alternateAliasWritesCannotResurrectAStaleFieldAfterNewCheck() throws Exception {
    assertNotEquals(
        "OBSERVED",
        status(
            "def run():\n"
                + "    data=json.loads(port.make())\n"
                + "    selected=data.get('x')\n"
                + "    old=port.make()\n"
                + "    selected['a']=old\n"
                + "    data['x']['a']=port.make()\n"
                + "    if port.check(old):\n"
                + "        port.release(selected['a'])\n"));
    assertNotEquals(
        "OBSERVED",
        status(
            "def run():\n"
                + "    data=json.loads(port.make())\n"
                + "    fallback={'a': port.make()}\n"
                + "    old=fallback['a']\n"
                + "    selected=data.get('x', fallback)\n"
                + "    selected['a']=port.make()\n"
                + "    if port.check(old):\n"
                + "        port.release(fallback['a'])\n"));
  }
}
