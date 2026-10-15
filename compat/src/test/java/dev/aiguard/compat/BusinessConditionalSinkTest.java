package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.*;
import org.junit.Test;

public class BusinessConditionalSinkTest {
  private static final Cancel NONE =
      new Cancel() {
        public void check() {}
      };

  private Map<String, Object> sink(Object equals) {
    return Findings.map(
        "symbol",
        "port.Events#emit",
        "arity",
        2,
        "kind",
        "sink",
        "channel",
        "release",
        "args",
        Arrays.asList(1),
        "valuePath",
        Arrays.asList("text"),
        "requiresLabel",
        "model-output",
        "when",
        Findings.map("arg", 0, "equals", equals));
  }

  private BusinessPolicy policy(Map<String, Object> sink) throws Exception {
    return BusinessPolicy.parse(
        "bank-all",
        new com.google.gson.GsonBuilder()
            .serializeNulls()
            .create()
            .toJson(
                Findings.map(
                    "version",
                    2,
                    "contracts",
                    Arrays.asList(
                        Findings.map(
                            "symbol",
                            "port.Model#make",
                            "arity",
                            0,
                            "kind",
                            "source",
                            "label",
                            "model-output"),
                        Findings.map(
                            "symbol",
                            "port.Guard#check",
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
                            "closed"),
                        sink))));
  }

  private Map<String, Object> scan(String body, Object equals) throws Exception {
    BusinessPolicy policy = policy(sink(equals));
    BusinessFlow.Program program =
        BusinessJavaAnalysis.adapt(
            Arrays.asList(
                new SourceFile(
                    "Sample.java",
                    "import port.Events; import port.Model; import port.Guard; import"
                        + " java.util.Map; class Sample {void run(String kind){"
                        + body
                        + "}}")),
            NONE,
            policy);
    for (Map<String, Object> item : BusinessAnalysis.analyze(program, policy, NONE).assessments)
      if (BusinessPolicy.GUARD.equals(item.get("ruleId"))) return item;
    throw new AssertionError();
  }

  @Test
  public void knownNonContentEventsAreExcludedButContentWithoutGuardIsViolated() throws Exception {
    assertEquals(
        0,
        scan("Events.emit(\"status\",Map.of(\"text\",Model.make()));", "content")
            .get("mappedPathOutcomes"));
    Map<String, Object> result =
        scan("Events.emit(\"content\",Map.of(\"text\",Model.make()));", "content");
    assertEquals(result.toString(), "VIOLATED", result.get("disposition"));
  }

  @Test
  public void unknownDiscriminatorIsRetainedAsCandidateNotSkipped() throws Exception {
    Map<String, Object> result =
        scan("Events.emit(kind,Map.of(\"text\",Model.make()));", "content");
    assertEquals("UNKNOWN", result.get("disposition"));
    assertTrue(result.get("unknownReasons").toString().contains("SINK_CONDITION_UNRESOLVED"));
    assertEquals(1, result.get("mappedPathOutcomes"));
  }

  @Test
  public void discriminatorDoesNotReplaceValueBoundGuard() throws Exception {
    assertEquals(
        "OBSERVED",
        scan(
                "String x=Model.make();if(!Guard.check(x))return;"
                    + "Events.emit(\"content\",Map.of(\"text\",x));",
                "content")
            .get("disposition"));
    assertEquals(
        "VIOLATED",
        scan(
                "String x=Model.make();if(!Guard.check(x))return;"
                    + "Events.emit(\"content\",Map.of(\"text\",Model.make()));",
                "content")
            .get("disposition"));
  }

  @Test
  public void scalarConditionsAreTypedAndNumericComparisonIsNormalized() throws Exception {
    for (Object[] example :
        Arrays.asList(
            new Object[] {"true", Boolean.TRUE},
            new Object[] {"null", null},
            new Object[] {"2L", Long.valueOf(2)})) {
      assertEquals(
          "VIOLATED",
          scan("Events.emit(" + example[0] + ",Map.of(\"text\",Model.make()));", example[1])
              .get("disposition"));
    }
    assertEquals(
        0, scan("Events.emit(\"2\",Map.of(\"text\",Model.make()));", 2).get("mappedPathOutcomes"));
  }

  @Test
  public void mutationPreventsReusingLiteralDiscriminator() throws Exception {
    Map<String, Object> result =
        scan(
            "String type=\"content\"; external.Unknown.mutate(type);"
                + "Events.emit(type,Map.of(\"text\",Model.make()));",
            "content");
    assertEquals("UNKNOWN", result.get("disposition"));
    assertTrue(result.get("unknownReasons").toString().contains("SINK_CONDITION_UNRESOLVED"));
  }

  @Test
  public void invalidConditionsAreRejectedRatherThanSilentlyIgnored() throws Exception {
    List<Map<String, Object>> invalid = new ArrayList<Map<String, Object>>();
    Map<String, Object> wrong = sink("content");
    wrong.put("when", Findings.map("arg", 2, "equals", "content"));
    invalid.add(wrong);
    wrong = sink("content");
    wrong.put("when", Findings.map("arg", -1, "equals", "content"));
    invalid.add(wrong);
    wrong = sink("content");
    wrong.put("boundary", "return");
    invalid.add(wrong);
    wrong = sink("content");
    wrong.put("when", Findings.map("arg", 0, "equals", Arrays.asList("content")));
    invalid.add(wrong);
    wrong = sink("content");
    wrong.put("when", Findings.map("arg", 0, "equals", "content", "extra", true));
    invalid.add(wrong);
    for (Map<String, Object> item : invalid) {
      try {
        policy(item);
        fail("invalid when accepted: " + item);
      } catch (IOException expected) {
      }
    }
  }
}
