package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.Test;

/** Generated field relationships require annotation origin, dispatch and configuration evidence. */
public class BusinessLombokValueFlowTest {
  private static final Cancel NONE =
      new Cancel() {
        public void check() {}
      };

  private BusinessPolicy policy(boolean path) throws Exception {
    List<Map<String, Object>> contracts = new ArrayList<Map<String, Object>>();
    contracts.add(
        Findings.map(
            "symbol", "port.Api#make", "arity", 0, "kind", "source", "label", "model-output"));
    contracts.add(
        Findings.map(
            "symbol",
            "port.Api#check",
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
    Map<String, Object> sink =
        Findings.map(
            "symbol",
            "port.Api#release",
            "arity",
            1,
            "kind",
            "sink",
            "channel",
            "release",
            "args",
            Arrays.asList(0));
    if (path) sink.put("valuePath", Arrays.asList("payload"));
    contracts.add(sink);
    return BusinessPolicy.parse(
        "bank-common", Json.COMPACT.toJson(Findings.map("version", 2, "contracts", contracts)));
  }

  private BusinessFlow.Program adapt(String code, String config, SourceFile... extras)
      throws Exception {
    List<SourceFile> files = new ArrayList<SourceFile>();
    files.add(new SourceFile("src/Example.java", "import port.Api;import lombok.Data;" + code));
    if (config != null) files.add(new SourceFile("lombok.config", config));
    files.addAll(Arrays.asList(extras));
    return BusinessJavaAnalysis.adapt(files, NONE, policy(true));
  }

  private String status(String code, String config, boolean path) throws Exception {
    BusinessPolicy policy = policy(path);
    List<SourceFile> files = new ArrayList<SourceFile>();
    files.add(new SourceFile("src/Example.java", "import port.Api;import lombok.Data;" + code));
    if (config != null) files.add(new SourceFile("lombok.config", config));
    BusinessAnalysis result =
        BusinessAnalysis.analyze(BusinessJavaAnalysis.adapt(files, NONE, policy), policy, NONE);
    for (Map<String, Object> item : result.assessments)
      if (BusinessPolicy.GUARD.equals(item.get("ruleId")))
        return String.valueOf(item.get("disposition"));
    throw new AssertionError("guard assessment missing");
  }

  private static final String DEFAULTS = "config.stopBubbling = true\n";
  private static final String BOX = "@Data class Box {private Object payload; public Box(){}}";
  private static final String FLOW =
      "class Demo {void run(){Object v=Api.make();Box b=new"
          + " Box();b.setPayload(v);if(Api.check(v))Api.release(b);}}";

  private BusinessFlow.Expr call(BusinessFlow.Program program, String symbol) {
    for (BusinessFlow.Function function : program.functions)
      for (BusinessFlow.Stmt statement : function.body) {
        BusinessFlow.Expr found = call(statement, symbol);
        if (found != null) return found;
      }
    throw new AssertionError("call missing: " + symbol);
  }

  private BusinessFlow.Expr call(BusinessFlow.Stmt statement, String symbol) {
    BusinessFlow.Expr found = call(statement.expr, symbol);
    if (found != null) return found;
    for (List<BusinessFlow.Stmt> statements :
        Arrays.asList(statement.body, statement.otherwise, statement.finalizer))
      for (BusinessFlow.Stmt child : statements) {
        found = call(child, symbol);
        if (found != null) return found;
      }
    return null;
  }

  private BusinessFlow.Expr call(BusinessFlow.Expr expression, String symbol) {
    if (expression == null) return null;
    if (symbol.equals(expression.symbol)) return expression;
    BusinessFlow.Expr found = call(expression.receiver, symbol);
    if (found != null) return found;
    for (BusinessFlow.Expr arg : expression.args) {
      found = call(arg, symbol);
      if (found != null) return found;
    }
    return null;
  }

  @Test
  public void closedDefaultConfigurationAllowsGeneratedSetter() throws Exception {
    assertEquals("OBSERVED", status(BOX + FLOW, DEFAULTS, true));
    BusinessFlow.Expr setter = call(adapt(BOX + FLOW, DEFAULTS), "Box#setPayload");
    assertEquals("PUT_MEMBER", setter.kind);
    assertFalse(setter.generatedMethodUncertain);
  }

  @Test
  public void absentAncestorConfigurationKeepsCandidateAndUnknown() throws Exception {
    BusinessFlow.Expr setter = call(adapt(BOX + FLOW, null), "Box#setPayload");
    assertEquals("PUT_MEMBER", setter.kind);
    assertTrue(setter.generatedMethodUncertain);
    assertNotEquals("OBSERVED", status(BOX + FLOW, null, true));
  }

  @Test
  public void generatedNoArgumentConstructorAndGetterPreserveField() throws Exception {
    String source =
        "@Data final class Box {private Object payload;}class Demo{void run(){Object"
            + " v=Api.make();Box b=new"
            + " Box();b.setPayload(v);if(Api.check(v))Api.release(b.getPayload());}}";
    assertEquals("OBSERVED", status(source, DEFAULTS, false));
    assertNotEquals("OBSERVED", status(source, null, false));
  }

  @Test
  public void realGenericFactoryWithSerializableAndClockKeepsIndependentPayload() throws Exception {
    String source =
        "@Data class Envelope<T> implements java.io.Serializable{private int code;private T"
            + " payload;private long timestamp;public"
            + " Envelope(){this.timestamp=System.currentTimeMillis();}public static <T> Envelope<T>"
            + " ok(T value){Envelope<T> e=new"
            + " Envelope<T>();e.setCode(200);e.setPayload(value);return e;}}class Demo{void"
            + " run(){Object v=Api.make();if(Api.check(v))Api.release(Envelope.ok(v));}}";
    assertEquals("OBSERVED", status(source, DEFAULTS, true));
    assertNotEquals("OBSERVED", status(source, null, true));
  }

  @Test
  public void wrongFieldWrongObjectAndPostCheckWriteCannotBorrowProof() throws Exception {
    assertNotEquals(
        "OBSERVED",
        status(
            "@Data class Box{private Object payload;private Object other;public Box(){}}class"
                + " Demo{void run(){Object v=Api.make();Box b=new"
                + " Box();b.setOther(v);b.setPayload(Api.make());if(Api.check(v))Api.release(b);}}",
            DEFAULTS,
            true));
    assertNotEquals(
        "OBSERVED",
        status(
            BOX
                + "class Demo{void run(){Object v=Api.make();Box a=new Box(),b=new"
                + " Box();a.setPayload(v);b.setPayload(Api.make());if(Api.check(v))Api.release(b);}}",
            DEFAULTS,
            true));
    assertNotEquals(
        "OBSERVED",
        status(
            BOX
                + "class Demo{void run(){Box b=new"
                + " Box();b.setPayload(Api.make());if(Api.check(b.getPayload())){b.setPayload(Api.make());Api.release(b);}}}",
            DEFAULTS,
            true));
  }

  @Test
  public void primitiveAndBoxedBooleanAccessorNamesAreDistinct() throws Exception {
    String source =
        "@Data final class Flags{boolean ready;boolean isOpen;Boolean boxed;public Flags(){}}class"
            + " Demo{void run(){Flags f=new"
            + " Flags();f.setReady(true);f.isReady();f.setOpen(true);f.isOpen();f.setBoxed(Boolean.TRUE);f.getBoxed();}}";
    BusinessFlow.Program program = adapt(source, DEFAULTS);
    for (String name : Arrays.asList("isReady", "isOpen", "getBoxed"))
      assertEquals("MEMBER", call(program, "Flags#" + name).kind);
    assertEquals("isOpen", call(program, "Flags#setOpen").name);
  }

  @Test
  public void fieldAndClassGetterSetterAnnotationsWorkWithoutData() throws Exception {
    String source =
        "@lombok.Getter @lombok.Setter final class Box{private Object payload;public Box(){}}class"
            + " Demo{void run(){Object v=Api.make();Box b=new"
            + " Box();b.setPayload(v);if(Api.check(v))Api.release(b.getPayload());}}";
    assertEquals("OBSERVED", status(source, DEFAULTS, false));
    assertEquals(
        "OBSERVED",
        status(
            source
                .replace("@lombok.Getter @lombok.Setter final", "final")
                .replace("private Object", "@lombok.Getter @lombok.Setter private Object"),
            DEFAULTS,
            false));
  }

  @Test
  public void customAccessorSettingsAndDisabledFieldsStayCalls() throws Exception {
    for (String prefix :
        Arrays.asList(
            "@lombok.experimental.Accessors(chain=true)",
            "@lombok.Getter(lombok.AccessLevel.NONE)",
            "@lombok.Setter(lombok.AccessLevel.PRIVATE)")) {
      BusinessFlow.Program program = adapt(prefix + BOX + FLOW, DEFAULTS);
      assertEquals("CALL", call(program, "Box#setPayload").kind);
    }
    assertEquals(
        "CALL",
        call(adapt(BOX + FLOW, DEFAULTS + "lombok.accessors.fluent = true\n"), "Box#setPayload")
            .kind);
    assertEquals(
        "CALL",
        call(adapt(BOX + FLOW, "import ../outside.config\n" + DEFAULTS), "Box#setPayload").kind);
  }

  @Test
  public void nonnullStaticFinalAndDollarFieldsAreNotDefaultSetters() throws Exception {
    for (String declaration :
        Arrays.asList(
            "@lombok.NonNull private Object payload;",
            "@javax.annotation.Nonnull private Object payload;",
            "private static Object payload;",
            "private final Object payload=null;")) {
      assertEquals(
          "CALL",
          call(
                  adapt("@Data class Box{" + declaration + "public Box(){}}" + FLOW, DEFAULTS),
                  "Box#setPayload")
              .kind);
    }
    assertEquals(
        "CALL",
        call(
                adapt(
                    "@Data final class Box{Object $payload;public Box(){}}class Demo{void run(){Box"
                        + " b=new Box();b.set$payload(Api.make());}}",
                    DEFAULTS),
                "Box#set$payload")
            .kind);
  }

  @Test
  public void explicitCaseInsensitiveAndVarargMethodsSuppressGeneration() throws Exception {
    for (String method :
        Arrays.asList("void SetPayload(Object v){}", "void setPayload(Object... values){}"))
      assertEquals(
          "CALL",
          call(
                  adapt(
                      "@Data class Box{Object payload;public Box(){}" + method + "}" + FLOW,
                      DEFAULTS),
                  "Box#setPayload")
              .kind);
    assertNotEquals(
        "OBSERVED",
        status(
            "@Data final class Box{Object payload;public Box(){}public void setPayload(Object"
                + " v){payload=Api.make();}}"
                + FLOW,
            DEFAULTS,
            true));
  }

  @Test
  public void localAnnotationSpoofAndSourceShadowCannotEnableSummary() throws Exception {
    assertEquals(
        "CALL", call(adapt("@interface Data{}" + BOX + FLOW, DEFAULTS), "Box#setPayload").kind);
    assertEquals(
        "CALL",
        call(
                adapt(
                    BOX + FLOW,
                    DEFAULTS,
                    new SourceFile("lombok/Data.java", "package lombok; public @interface Data{}")),
                "Box#setPayload")
            .kind);
  }

  @Test
  public void inheritedOrReassignedReceiverCannotBeTreatedAsExactObject() throws Exception {
    assertEquals(
        "CALL",
        call(
                adapt(
                    "class Parent{}@Data class Box extends Parent{Object payload;public Box(){}}"
                        + FLOW,
                    DEFAULTS),
                "Box#setPayload")
            .kind);
    assertEquals(
        "CALL",
        call(
                adapt(
                    BOX
                        + "class Demo{void run(Box other){Box b=new"
                        + " Box();b=other;b.setPayload(Api.make());}}",
                    DEFAULTS),
                "Box#setPayload")
            .kind);
    assertEquals(
        "CALL",
        call(
                adapt(BOX + "class Demo{void run(Box b){b.setPayload(Api.make());}}", DEFAULTS),
                "Box#setPayload")
            .kind);
  }

  @Test
  public void explicitSourceContractHasPriorityOverGeneratedSetter() throws Exception {
    BusinessPolicy policy =
        BusinessPolicy.parse(
            "bank-common",
            "{\"version\":2,\"contracts\":[{\"symbol\":\"sample.Box#setPayload\",\"kind\":\"source\",\"label\":\"model-output\",\"arity\":1}]}");
    List<SourceFile> files =
        Arrays.asList(
            new SourceFile("Example.java", "package sample;import lombok.Data;" + BOX + FLOW),
            new SourceFile("lombok.config", DEFAULTS));
    assertEquals(
        "CALL",
        call(BusinessJavaAnalysis.adapt(files, NONE, policy), "sample.Box#setPayload").kind);
  }

  @Test
  public void processingDisabledAndUnsupportedConstructorDoNotProduceExactShape() throws Exception {
    assertEquals(
        "CALL",
        call(
                adapt(
                    BOX + FLOW,
                    DEFAULTS,
                    new SourceFile(
                        "pom.xml",
                        "<project><properties><maven.compiler.proc>none</maven.compiler.proc></properties><configuration><proc>none</proc></configuration></project>")),
                "Box#setPayload")
            .kind);
    assertNotEquals(
        "OBSERVED",
        status(
            "@Data class Box{Object payload;long time;public Box(){this.time=Other.now();}}class"
                + " Other{static long now(){return 0;}}"
                + FLOW,
            DEFAULTS,
            true));
    assertNotEquals(
        "OBSERVED",
        status(
            "class System{static long currentTimeMillis(){return 0;}}@Data class Box{Object"
                + " payload;long time;public Box(){this.time=System.currentTimeMillis();}}"
                + FLOW,
            DEFAULTS,
            true));
  }

  @Test
  public void siblingConfigurationDoesNotCloseAncestorEvidenceGap() throws Exception {
    BusinessFlow.Expr setter =
        call(
            adapt(BOX + FLOW, null, new SourceFile("unrelated/lombok.config", DEFAULTS)),
            "Box#setPayload");
    assertTrue(setter.generatedMethodUncertain);
  }

  @Test
  public void otherGeneratorsCannotSilentlyChangeConstructionOrInitialization() throws Exception {
    for (String generator :
        Arrays.asList(
            "lombok.AllArgsConstructor",
            "lombok.NoArgsConstructor",
            "lombok.experimental.UtilityClass",
            "lombok.extern.slf4j.Slf4j")) {
      assertEquals(
          "CALL", call(adapt("@" + generator + " " + BOX + FLOW, DEFAULTS), "Box#setPayload").kind);
    }
  }

  @Test
  public void booleanAlternativeGetterAndSetterNamesSuppressGeneration() throws Exception {
    String source =
        "@Data final class Box{boolean isReady;public Box(){}boolean getReady(){return false;}void"
            + " setIsReady(boolean value){}}class Demo{void run(){Box b=new"
            + " Box();b.isReady();b.setReady(true);}}";
    BusinessFlow.Program program = adapt(source, DEFAULTS);
    assertEquals("CALL", call(program, "Box#isReady").kind);
    assertEquals("CALL", call(program, "Box#setReady").kind);
  }
}
