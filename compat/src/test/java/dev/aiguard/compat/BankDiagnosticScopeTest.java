package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/** Diagnostic scope must not erase evidence from an independent mapped path. */
public class BankDiagnosticScopeTest {
  @Rule public TemporaryFolder temporary = new TemporaryFolder();

  private static final Cancel NEVER =
      new Cancel() {
        public void check() {}
      };
  private static final String UNGUARDED =
      "import edge\ndef run():\n    value = edge.make()\n    edge.release(value)\n";
  private static final String GUARDED =
      "import edge\ndef run():\n    value = edge.make()\n"
          + "    if edge.check(value):\n        edge.release(value)\n";

  private BankPolicy policy() throws Exception {
    return BankPolicy.parse(
        "bank-common",
        "{\"version\":2,\"contracts\":["
            + "{\"symbol\":\"edge.make\",\"arity\":0,\"kind\":\"source\",\"label\":\"model-output\"},"
            + "{\"symbol\":\"edge.check\",\"arity\":1,\"kind\":\"check\",\"control\":\"guard\","
            + "\"args\":[0],\"accept\":true,\"failureMode\":\"closed\"},"
            + "{\"symbol\":\"edge.release\",\"arity\":1,\"kind\":\"sink\","
            + "\"channel\":\"release\",\"args\":[0]}]}");
  }

  private Map<String, Object> scan(String source) throws Exception {
    return scan(source, null);
  }

  private Map<String, Object> scan(String source, String otherSource) throws Exception {
    Path root = temporary.newFolder().toPath().toRealPath();
    Files.write(root.resolve("workflow.py"), source.getBytes(StandardCharsets.UTF_8));
    if (otherSource != null)
      Files.write(root.resolve("other.py"), otherSource.getBytes(StandardCharsets.UTF_8));
    return new Scanner().scan(root, "diagnostic-scope", NEVER, policy());
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> guard(Map<String, Object> report) {
    for (Map<String, Object> item : (List<Map<String, Object>>) report.get("assessments"))
      if (BankPolicy.GUARD.equals(item.get("ruleId"))) return item;
    throw new AssertionError("Missing guard assessment");
  }

  @Test
  public void unrelatedPythonCallCannotDowngradeAnEstablishedBlockingViolation() throws Exception {
    Map<String, Object> before = scan(UNGUARDED);
    assertEquals("VIOLATED", guard(before).get("disposition"));
    assertEquals("BLOCK", before.get("gateDecision"));

    Map<String, Object> after = scan(UNGUARDED + "\ndef unrelated():\n    print('hello')\n");
    assertEquals("VIOLATED", guard(after).get("disposition"));
    assertEquals("BLOCK", after.get("gateDecision"));
  }

  @Test
  public void discardedSourceKeepsAggregateCoverageUnknown() throws Exception {
    Map<String, Object> report =
        scan(GUARDED, "import edge\ndef omitted[T](value: T):\n    edge.release(edge.make())\n");
    assertEquals("UNKNOWN", guard(report).get("disposition"));
    assertEquals("UNSUPPORTED", guard(report).get("unknownCategory"));
    assertEquals(
        Integer.valueOf(1), ((Map<?, ?>) report.get("mappingCoverage")).get("incompleteSourceFiles"));
  }

  @Test
  public void unrelatedUnsupportedFunctionDoesNotEraseObservedLocalControl() throws Exception {
    Map<String, Object> report = scan(GUARDED + "\ndef unrelated():\n    print('hello')\n");
    assertEquals("OBSERVED", guard(report).get("disposition"));
    assertFalse(((List<?>) report.get("diagnostics")).isEmpty());
  }

  @Test
  public void unknownCallTouchingTheCheckedValueStillMakesThePathUnknown() throws Exception {
    Map<String, Object> report =
        scan(
            "import edge\ndef run():\n    value = edge.make()\n"
                + "    if edge.check(value):\n        mutate(value)\n        edge.release(value)\n");
    assertEquals("UNKNOWN", guard(report).get("disposition"));
    assertEquals("UNSUPPORTED", guard(report).get("unknownCategory"));
  }

  @Test
  public void unsupportedLoopPreservesItsMappedSinkAsUnknown() throws Exception {
    Map<String, Object> report =
        scan(
            "import edge\ndef run(items):\n    value = edge.make()\n"
                + "    for item in items:\n        edge.release(value)\n");
    assertEquals("UNKNOWN", guard(report).get("disposition"));
    assertEquals("UNSUPPORTED", guard(report).get("unknownCategory"));
    assertFalse(((List<?>) guard(report).get("evidence")).isEmpty());
  }

  @Test
  public void discardedSourceCannotDowngradeAnIndependentlyEstablishedViolation() throws Exception {
    Map<String, Object> report =
        scan(UNGUARDED, "import edge\ndef omitted[T](value: T):\n    edge.release(edge.make())\n");
    assertEquals("VIOLATED", guard(report).get("disposition"));
    assertEquals("BLOCK", report.get("gateDecision"));
    assertEquals(
        Integer.valueOf(1), ((Map<?, ?>) report.get("mappingCoverage")).get("incompleteSourceFiles"));
  }
}
