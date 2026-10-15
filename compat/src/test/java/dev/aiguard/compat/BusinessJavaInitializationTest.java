package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.Test;

public class BusinessJavaInitializationTest {
  private static final Cancel NONE =
      new Cancel() {
        public void check() {}
      };

  private BusinessAnalysis analyze(String body) throws Exception {
    List<Map<String, Object>> contracts = new ArrayList<Map<String, Object>>();
    contracts.add(
        Findings.map(
            "symbol", "edge.Port#make", "arity", 0, "kind", "source", "label", "model-output"));
    contracts.add(
        Findings.map(
            "symbol",
            "edge.Port#check",
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
    contracts.add(
        Findings.map(
            "symbol",
            "edge.Port#release",
            "arity",
            1,
            "kind",
            "sink",
            "channel",
            "release",
            "args",
            Arrays.asList(0)));
    contracts.add(
        Findings.map(
            "symbol",
            "edge.Release#<init>",
            "arity",
            1,
            "kind",
            "sink",
            "channel",
            "release",
            "args",
            Arrays.asList(0)));
    BusinessPolicy policy =
        BusinessPolicy.parse(
            "bank-common", Json.COMPACT.toJson(Findings.map("version", 2, "contracts", contracts)));
    BusinessFlow.Program program =
        BusinessJavaAnalysis.adapt(
            Arrays.asList(
                new SourceFile(
                    "src/Example.java", "import edge.Port; class Example { " + body + " }")),
            NONE,
            policy);
    return BusinessAnalysis.analyze(program, policy, NONE);
  }

  private void guard(String expected, BusinessAnalysis analysis) {
    for (Map<String, Object> assessment : analysis.assessments)
      if (BusinessPolicy.GUARD.equals(assessment.get("ruleId"))) {
        assertEquals(assessment.toString(), expected, assessment.get("disposition"));
        return;
      }
    fail("Missing Guard assessment");
  }

  @Test
  public void staticInitializerViolationCannotBeHiddenBySafeMethod() throws Exception {
    guard(
        "VIOLATED",
        analyze(
            "static { Port.release(Port.make()); } "
                + "void safe(){Object v=Port.make();if(Port.check(v))Port.release(v);}"));
  }

  @Test
  public void fieldInitializerCallsAreAssessed() throws Exception {
    guard("VIOLATED", analyze("Object output=Port.release(Port.make());"));
    guard("VIOLATED", analyze("static Object output=Port.release(Port.make());"));
  }

  @Test
  public void fieldAndBlockInitializersUseDeclarationOrder() throws Exception {
    guard(
        "OBSERVED",
        analyze(
            "static Object value=Port.make();"
                + "static {if(!Port.check(value))throw new IllegalStateException();}"
                + "static {Port.release(value);}"));
    guard(
        "VIOLATED",
        analyze(
            "static Object value=Port.make();"
                + "static {Port.release(value);}"
                + "static {if(!Port.check(value))throw new IllegalStateException();}"));
  }

  @Test
  public void instanceBlocksAndAnonymousInitializersCannotBeOmitted() throws Exception {
    guard("VIOLATED", analyze("{Port.release(Port.make());}"));
    guard("VIOLATED", analyze("Object value=new Object(){{Port.release(Port.make());}};"));
  }

  @Test
  public void initializerFieldWritesAndLocalAliasesKeepTheirOrder() throws Exception {
    guard(
        "OBSERVED",
        analyze(
            "Object value; {this.value=Port.make();Object"
                + " alias=this.value;if(!Port.check(alias))throw new IllegalStateException();}"
                + "{Port.release(value);}"));
    guard(
        "VIOLATED",
        analyze(
            "Object value=Port.make();"
                + "{if(!Port.check(value))throw new IllegalStateException();}"
                + "{value=Port.make();Port.release(value);}"));
  }

  @Test
  public void proofsNeverCrossInitializationAndConstructorBoundaries() throws Exception {
    guard(
        "UNKNOWN",
        analyze(
            "Object value=Port.make();"
                + "{if(!Port.check(value))throw new IllegalStateException();}"
                + "Example(){Port.release(value);}"));
    guard(
        "UNKNOWN",
        analyze(
            "static Object value=Port.make();"
                + "static {if(!Port.check(value))throw new IllegalStateException();}"
                + "{Port.release(value);}"));
    guard(
        "VIOLATED",
        analyze(
            "Object value=Port.make();"
                + "{if(!Port.check(value))throw new IllegalStateException();}"
                + "Example(){Port.release(Port.make());}"));
  }

  @Test
  public void unsupportedNonMethodAndDeferredCallsRemainUnknown() throws Exception {
    String safe = "void safe(){Object v=Port.make();if(Port.check(v))Port.release(v);}";
    guard("UNKNOWN", analyze("interface Deferred {Object v=Port.release(Port.make());}" + safe));
    guard("UNKNOWN", analyze("Runnable job=()->Port.release(Port.make());" + safe));
  }

  @Test
  public void unsupportedConstructorSinkCannotBeHiddenBySafeMethod() throws Exception {
    guard(
        "UNKNOWN",
        analyze(
            "interface Deferred {Object value=new edge.Release(Port.make());}"
                + "void safe(){Object v=Port.make();if(Port.check(v))Port.release(v);}"));
  }
}
