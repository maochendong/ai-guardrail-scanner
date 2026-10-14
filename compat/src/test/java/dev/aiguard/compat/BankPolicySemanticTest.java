package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.io.IOException;
import java.math.BigDecimal;
import java.util.Arrays;
import java.util.List;
import org.junit.Test;

public class BankPolicySemanticTest {
  private static final String SOURCE =
      "{\"symbol\":\"arbitrary.Provider#read\",\"arity\":2,\"kind\":\"source\",\"label\":\"model-output\"}";
  private static final String CHECK =
      "{\"symbol\":\"arbitrary.Policy#check\",\"arity\":1,\"kind\":\"check\",\"control\":\"guard\",\"args\":[0],\"accept\":true}";
  private static final String HASH =
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

  private BankPolicy parse(String contracts) throws Exception {
    return BankPolicy.parse("bank-all", "{\"version\":2,\"contracts\":[" + contracts + "]}");
  }

  private String add(String contract, String fields) {
    return contract.substring(0, contract.length() - 1) + "," + fields + "}";
  }

  private void rejected(String json) throws Exception {
    try {
      BankPolicy.parse("bank-all", json);
      fail("accepted invalid policy");
    } catch (IOException expected) {
      assertEquals("INVALID_BANK_POLICY", expected.getMessage());
    }
  }

  private void rejectedContract(String contract) throws Exception {
    rejected("{\"version\":2,\"contracts\":[" + contract + "]}");
  }

  @Test
  public void v2DefaultsRemainConservativeWhileV1RemainsCompatible() throws Exception {
    BankPolicy policy = parse(CHECK);
    BankPolicy.Contract c = policy.contract("arbitrary.Policy#check", 1);
    assertEquals("reviewed", c.assurance);
    assertEquals("unknown", c.failureMode);
    assertEquals("boolean", c.mode);
    assertEquals("call", c.boundary);
    assertEquals("unknown", c.scope);
    assertEquals("", c.requiresLabel);
    assertEquals("", c.decisionSymbol);
    assertEquals(-1, c.decisionArg);
    assertTrue(c.parameterNames.isEmpty());
    BankPolicy old = BankPolicy.parse("bank-all", "{\"version\":1,\"contracts\":[" + CHECK + "]}");
    assertEquals("closed", old.contract("arbitrary.Policy#check", 1).failureMode);
    assertEquals("restricted", old.contract("arbitrary.Policy#check", 1).scope);
    assertEquals("bank-policy-v1", old.metadata().get("version"));
    assertEquals("bank-policy-v2", policy.metadata().get("version"));
  }

  @Test
  public void optionalV2RootFieldsAndReviewedReceiversAreSupported() throws Exception {
    assertEquals(0, BankPolicy.parse("bank-all", "{\"version\":2}").contractCount());
    BankPolicy policy =
        BankPolicy.parse(
            "bank-all",
            "{\"version\":2,\"receivers\":["
                + "{\"owner\":\"example.Store\",\"field\":\"client\",\"type\":\"vendor.Client\"}]}");
    BankPolicy.Receiver r = policy.receiver("example.Store", "client");
    assertEquals("vendor.Client", r.type);
    assertEquals("reviewed", r.assurance);
    assertNull(policy.receiver("other.Store", "client"));
    assertEquals(1, policy.metadata().get("receiverCount"));
    assertEquals(1, policy.metadata().get("bindingCount"));
  }

  @Test
  public void sourceCanDescribeOutboundSlotsAndPythonDefaults() throws Exception {
    BankPolicy policy =
        parse(
            add(
                SOURCE,
                "\"outboundArgs\":[0],\"parameterNames\":[\"payload\",\"enabled\"],\"defaults\":{\"enabled\":true}"));
    BankPolicy.Contract c = policy.contract("arbitrary.Provider#read", 2);
    assertEquals(Arrays.asList(0), c.outboundArgs);
    assertEquals(Arrays.asList("payload", "enabled"), c.parameterNames);
    assertEquals(Boolean.TRUE, c.defaults.get("enabled"));
  }

  @Test
  public void scalarDefaultsPreserveNullStringAndExactNumber() throws Exception {
    String source = SOURCE.replace("\"arity\":2", "\"arity\":3");
    BankPolicy.Contract c =
        parse(
                add(
                    source,
                    "\"parameterNames\":[\"x\",\"y\",\"z\"],\"defaults\":{\"x\":null,\"y\":\"v\",\"z\":1.25}"))
            .contract("arbitrary.Provider#read", 3);
    assertTrue(c.defaults.containsKey("x"));
    assertNull(c.defaults.get("x"));
    assertEquals("v", c.defaults.get("y"));
    assertEquals(new BigDecimal("1.25"), c.defaults.get("z"));
  }

  @Test
  public void checkProjectsDecisionAndSeparatesFailureAssurance() throws Exception {
    BankPolicy.Contract c =
        parse(
                add(
                    CHECK,
                    "\"assurance\":\"candidate\",\"failureMode\":\"open\","
                        + "\"decision\":{\"symbol\":\"vendor.Result#isAccepted\",\"arg\":-1}"))
            .contract("arbitrary.Policy#check", 1);
    assertEquals("candidate", c.assurance);
    assertEquals("open", c.failureMode);
    assertEquals("vendor.Result#isAccepted", c.decisionSymbol);
    assertEquals(-1, c.decisionArg);
    String external = add(CHECK, "\"decision\":{\"symbol\":\"vendor.decode\",\"arg\":0}");
    assertEquals(0, parse(external).contract("arbitrary.Policy#check", 1).decisionArg);
  }

  @Test
  public void assertionModeMayOmitBooleanAcceptanceButNotDeclareRejectionAsSuccess()
      throws Exception {
    String assertion =
        add(
            CHECK.replace(",\"accept\":true", ""),
            "\"mode\":\"normal-return\",\"failureMode\":\"closed\"");
    assertEquals("normal-return", parse(assertion).contract("arbitrary.Policy#check", 1).mode);
    rejectedContract(add(assertion, "\"accept\":false"));
    rejectedContract(
        add(assertion, "\"decision\":{\"symbol\":\"vendor.Result#isAccepted\",\"arg\":-1}"));
  }

  @Test
  public void constructorAndReceiverPreservationHaveExplicitSelectors() throws Exception {
    BankPolicy.Contract ctor =
        parse(SOURCE.replace("#read", "#<init>")).contract("arbitrary.Provider#<init>", 2);
    assertNotNull(ctor);
    String transform =
        "{\"symbol\":\"java.lang.String#trim\",\"arity\":0,\"kind\":\"transform\",\"control\":\"preserve\",\"arg\":-1}";
    assertEquals(-1, parse(transform).contract("java.lang.String#trim", 0).arg);
    rejectedContract(transform.replace("preserve", "redaction"));
  }

  @Test
  public void returnSinkUsesValuePlusDeclaredParameters() throws Exception {
    String sink =
        "{\"symbol\":\"sample.Service#answer\",\"arity\":2,\"kind\":\"sink\",\"channel\":\"recommend\","
            + "\"boundary\":\"return\",\"args\":[0],\"identity\":2,\"valuePath\":[\"answer\",\"text\"],"
            + "\"requiresLabel\":\"model-output\",\"scope\":\"restricted\"}";
    BankPolicy.Contract c = parse(sink).contract("sample.Service#answer", 2);
    assertEquals("return", c.boundary);
    assertEquals(2, c.identity);
    assertEquals(Arrays.asList("answer", "text"), c.valuePath);
    assertEquals("model-output", c.requiresLabel);
    rejectedContract(sink.replace("\"identity\":2", "\"identity\":3"));
    rejectedContract(sink.replace("\"boundary\":\"return\"", "\"boundary\":\"call\""));
  }

  @Test
  public void zeroArgumentRetrievalCanDeclareAbsentIdentityAndUnknownScope() throws Exception {
    String sink =
        "{\"symbol\":\"sample.Repository#all\",\"arity\":0,\"kind\":\"sink\",\"channel\":\"retrieve\",\"args\":[],\"identity\":-1}";
    BankPolicy.Contract c = parse(sink).contract("sample.Repository#all", 0);
    assertTrue(c.args.isEmpty());
    assertEquals(-1, c.identity);
    assertEquals("unknown", c.scope);
    rejectedContract(sink.replace("retrieve", "release").replace(",\"identity\":-1", ""));
  }

  @Test
  public void differentAritiesAreCandidatesButDuplicateSelectorsAreForbidden() throws Exception {
    String other = SOURCE.replace("\"arity\":2", "\"arity\":1");
    List<BankPolicy.Contract> found =
        parse(SOURCE + "," + other).contractsForSymbol("arbitrary.Provider#read");
    assertEquals(2, found.size());
    rejectedContract(SOURCE + "," + SOURCE);
    String collision =
        "{\"symbol\":\"arbitrary.Provider#read\",\"arity\":2,\"kind\":\"sink\",\"channel\":\"release\",\"args\":[0]}";
    rejectedContract(SOURCE + "," + collision);
  }

  @Test
  public void sourceBindingAndMetadataNeverExportMappings() throws Exception {
    BankPolicy policy =
        BankPolicy.parse(
            "bank-all",
            "{\"version\":2,\"sourceDigests\":[\"" + HASH + "\"],\"contracts\":[" + SOURCE + "]}");
    assertTrue(policy.matchesSourceDigest(HASH));
    assertFalse(policy.matchesSourceDigest("different"));
    assertTrue(parse(SOURCE).matchesSourceDigest("any"));
    assertEquals(1, policy.metadata().get("sourceDigestCount"));
    String metadata = Json.COMPACT.toJson(policy.metadata());
    assertFalse(metadata.contains("arbitrary.Provider"));
    assertFalse(metadata.contains(HASH));
    rejected("{\"version\":2,\"sourceDigests\":[]}");
    rejected("{\"version\":2,\"sourceDigests\":[\"" + HASH + "\",\"" + HASH + "\"]}");
    rejected("{\"version\":2,\"sourceDigests\":[\"not-a-digest\"]}");
  }

  @Test
  public void v1RejectsEveryV2Extension() throws Exception {
    for (String extension :
        Arrays.asList(
            "\"assurance\":\"candidate\"",
            "\"parameterNames\":[\"a\",\"b\"]",
            "\"outboundArgs\":[0]",
            "\"defaults\":{}")) {
      rejected("{\"version\":1,\"contracts\":[" + add(SOURCE, extension) + "]}");
    }
    rejected("{\"version\":1,\"contracts\":[],\"receivers\":[]}");
    rejected("{\"version\":1,\"contracts\":[],\"sourceDigests\":[\"" + HASH + "\"]}");
    rejected("{\"version\":1,\"contracts\":[" + SOURCE.replace("#read", "#<init>") + "]}");
  }

  @Test
  public void invalidNamesDefaultsAndArgumentIndexesAreRejected() throws Exception {
    for (String extension :
        Arrays.asList(
            "\"parameterNames\":[\"a\"]",
            "\"parameterNames\":[\"a\",\"a\"]",
            "\"parameterNames\":[\"a\",1]",
            "\"parameterNames\":[\"a.b\",\"c\"]",
            "\"defaults\":{}",
            "\"parameterNames\":[\"a\",\"b\"],\"defaults\":{\"c\":true}",
            "\"parameterNames\":[\"a\",\"b\"],\"defaults\":{\"a\":{}}",
            "\"parameterNames\":[\"a\",\"b\"],\"defaults\":{\"a\":[]}",
            "\"outboundArgs\":[2]",
            "\"outboundArgs\":[-1]",
            "\"outboundArgs\":[0,0]",
            "\"assurance\":\"trusted\"",
            "\"valuePath\":[\"content\"]")) rejectedContract(add(SOURCE, extension));
    rejectedContract(add(CHECK, "\"decision\":{\"symbol\":\"vendor.Result#ok\",\"arg\":32}"));
    rejectedContract(add(CHECK, "\"decision\":{\"symbol\":\"vendor.Result#ok\",\"arg\":1}"));
    rejectedContract(add(CHECK, "\"decision\":{\"symbol\":\"vendor.Result#ok\",\"arg\":-2}"));
  }

  @Test
  public void receiverBindingsAreStrictAndUnique() throws Exception {
    String r =
        "{\"owner\":\"sample.Store\",\"field\":\"client\",\"type\":\"vendor.Client\",\"assurance\":\"candidate\"}";
    for (String receiver :
        Arrays.asList(
            r + "," + r,
            r.replace("\"client\"", "\"nested.client\""),
            r.replace("candidate", "trusted"),
            add(r, "\"unused\":true"),
            r.replace("vendor.Client", "*")))
      rejected("{\"version\":2,\"receivers\":[" + receiver + "]}");
    rejected("{\"version\":2,\"receivers\":null}");
    rejected("{\"version\":2,\"gate\":\"ALLOW\"}");
    rejected("{\"version\":3}");
    rejected("{\"version\":2,\"version\":2}");
    rejectedContract(add(SOURCE,
        "\"parameterNames\":[\"a\",\"b\"],\"defaults\":{\"a\":true,\"a\":false}"));
  }

  @Test(expected = UnsupportedOperationException.class)
  public void contractCollectionsAreImmutable() throws Exception {
    parse(add(SOURCE, "\"outboundArgs\":[0]"))
        .contract("arbitrary.Provider#read", 2)
        .outboundArgs
        .add(1);
  }
}
