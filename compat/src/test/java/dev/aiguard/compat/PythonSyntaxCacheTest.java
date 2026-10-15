package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import org.junit.Test;

public class PythonSyntaxCacheTest {
  private static final Cancel NEVER =
      new Cancel() {
        public void check() {}
      };
  private static final String MODEL_LOG =
      "from openai import OpenAI\nimport logging\nclient = OpenAI()\n"
          + "answer = client.chat.completions.create(model='model', messages=[])\n"
          + "logging.info(answer.choices[0].message.content)\n";

  @Test
  public void aSourceSnapshotHasOneSharedSyntaxUnit() {
    SourceFile file = new SourceFile("workflow.py", "value = 1\n");
    PythonSyntax.Cache cache = new PythonSyntax.Cache();
    PythonSyntax.Unit first = cache.parse(file, NEVER);
    assertNotNull(first.tree);
    assertEquals("", first.failureReason);
    assertSame(first, cache.parse(file, NEVER));
  }

  @Test
  public void theSamePathInAnotherSnapshotCannotReuseOldSyntax() {
    PythonSyntax.Cache cache = new PythonSyntax.Cache();
    PythonSyntax.Unit valid = cache.parse(new SourceFile("workflow.py", "value = 1\n"), NEVER);
    PythonSyntax.Unit changed = cache.parse(new SourceFile("workflow.py", "def broken(:\n"), NEVER);
    assertNotSame(valid, changed);
    assertNotNull(valid.tree);
    assertNull(changed.tree);
    assertEquals("SYNTAX", changed.failureReason);
  }

  @Test
  public void syntaxFailureAndFstringBoundaryAreSharedWithoutPartialTrees() {
    SourceFile file = new SourceFile("broken.py", "value = f'{unknown}'\ndef broken(:\n");
    PythonSyntax.Cache cache = new PythonSyntax.Cache();
    PythonSyntax.Unit unit = cache.parse(file, NEVER);
    assertNull(unit.tree);
    assertTrue(unit.fstrings);
    assertEquals("SYNTAX", unit.failureReason);
    assertSame(unit, cache.parse(file, NEVER));
    AnalysisResult generic = PythonAnalysis.analyze(Arrays.asList(file), NEVER, cache);
    BankFlow.Program bank =
        BankPythonAnalysis.adapt(Arrays.asList(file), NEVER, BankPolicy.generic(), cache);
    assertTrue(hasCode(generic.diagnostics, "PYTHON_PARSE_FAILED"));
    assertTrue(hasCode(generic.diagnostics, "PYTHON_FSTRING_BOUNDARY"));
    assertTrue(hasCode(bank.diagnostics, "BANK_PYTHON_PARSE_FAILED"));
    assertTrue(bank.functions.isEmpty());
    assertTrue(bank.incompletePaths.contains(file.path));
  }

  @Test
  public void tokenLimitFailureIsCachedWithoutPartialSyntax() {
    SourceFile file = repeatedAssignments(51000);
    PythonSyntax.Cache cache = new PythonSyntax.Cache();
    PythonSyntax.Unit unit = cache.parse(file, NEVER);
    assertNull(unit.tree);
    assertEquals("LIMIT", unit.failureReason);
    assertSame(unit, cache.parse(file, NEVER));
  }

  @Test(expected = CancellationException.class)
  public void cancellationStillAppliesToACacheHit() {
    SourceFile file = new SourceFile("workflow.py", "pass\n");
    PythonSyntax.Cache cache = new PythonSyntax.Cache();
    cache.parse(file, NEVER);
    cache.parse(
        file,
        new Cancel() {
          public void check() {
            throw new CancellationException();
          }
        });
  }

  @Test
  public void cancellationDoesNotBecomeACachedParseFailure() {
    SourceFile file = repeatedAssignments(200);
    PythonSyntax.Cache cache = new PythonSyntax.Cache();
    try {
      cache.parse(
          file,
          new Cancel() {
            int calls;

            public void check() {
              if (++calls >= 3) throw new CancellationException();
            }
          });
      fail("Expected cancellation during bounded parsing");
    } catch (CancellationException expected) {
    }
    PythonSyntax.Unit recovered = cache.parse(file, NEVER);
    assertNotNull(recovered.tree);
    assertEquals("", recovered.failureReason);
  }

  @Test
  public void sharedAndIndependentConsumersProduceEquivalentResults() throws Exception {
    SourceFile file =
        new SourceFile(
            "workflow.py",
            MODEL_LOG
                + "import edge\ndef run():\n    value = edge.make()\n"
                + "    if edge.check(value):\n        edge.release(value)\n");
    List<SourceFile> files = Arrays.asList(file);
    BankPolicy policy = policy();
    AnalysisResult independentGeneric = PythonAnalysis.analyze(files, NEVER);
    BankAnalysis independentBank =
        BankAnalysis.analyze(BankPythonAnalysis.adapt(files, NEVER, policy), policy, NEVER);
    PythonSyntax.Cache cache = new PythonSyntax.Cache();
    PythonSyntax.Unit unit = cache.parse(file, NEVER);
    String treeBefore = unit.tree.toStringTree();
    AnalysisResult sharedGeneric = PythonAnalysis.analyze(files, NEVER, cache);
    BankAnalysis sharedBank =
        BankAnalysis.analyze(BankPythonAnalysis.adapt(files, NEVER, policy, cache), policy, NEVER);
    assertEquals(Json.COMPACT.toJson(independentGeneric), Json.COMPACT.toJson(sharedGeneric));
    assertEquals(independentBank.assessments, sharedBank.assessments);
    assertEquals(independentBank.diagnostics, sharedBank.diagnostics);
    assertEquals(independentBank.mappingCoverage, sharedBank.mappingCoverage);
    assertTrue(hasDisposition(sharedGeneric.assessments, "AI-PY-003", "VIOLATED"));
    assertTrue(hasDisposition(sharedBank.assessments, BankPolicy.GUARD, "OBSERVED"));
    assertSame(unit, cache.parse(file, NEVER));
    assertEquals(treeBefore, unit.tree.toStringTree());
  }

  @Test
  public void aBankAdapterBudgetFailureCannotPoisonSharedSyntaxOrGenericAnalysis() {
    SourceFile repeated = repeatedAssignments(5000);
    SourceFile file = new SourceFile(repeated.path, repeated.content + MODEL_LOG);
    List<SourceFile> files = Arrays.asList(file);
    PythonSyntax.Cache cache = new PythonSyntax.Cache();
    PythonSyntax.Unit unit = cache.parse(file, NEVER);
    BankFlow.Program bank = BankPythonAnalysis.adapt(files, NEVER, BankPolicy.generic(), cache);
    assertTrue(hasCode(bank.diagnostics, "BANK_PYTHON_ANALYSIS_LIMIT"));
    assertTrue(bank.functions.isEmpty());
    assertTrue(bank.incompletePaths.contains(file.path));
    AnalysisResult generic = PythonAnalysis.analyze(files, NEVER, cache);
    assertTrue(hasDisposition(generic.assessments, "AI-PY-003", "VIOLATED"));
    assertFalse(hasCode(generic.diagnostics, "PYTHON_ANALYSIS_LIMIT"));
    assertNotNull(unit.tree);
    assertEquals("", unit.failureReason);
    assertSame(unit, cache.parse(file, NEVER));
  }

  @Test
  public void aGenericFlowBudgetFailureCannotPoisonBankControlAnalysis() throws Exception {
    StringBuilder source = new StringBuilder("class Flow:\n");
    for (int i = 0; i < 30; i++)
      source
          .append("    def hop")
          .append(i)
          .append("(self):\n        return self.hop")
          .append(i + 1)
          .append("()\n");
    source.append("    def hop30(self):\n        return 1\nflow = Flow()\nflow.hop0()\n");
    source.append(
        "import edge\ndef run():\n    value = edge.make()\n"
            + "    if edge.check(value):\n        edge.release(value)\n");
    SourceFile file = new SourceFile("chain.py", source.toString());
    List<SourceFile> files = Arrays.asList(file);
    PythonSyntax.Cache cache = new PythonSyntax.Cache();
    AnalysisResult generic = PythonAnalysis.analyze(files, NEVER, cache);
    assertTrue(hasCode(generic.diagnostics, "PYTHON_FLOW_LIMIT"));
    BankPolicy policy = policy();
    BankFlow.Program program = BankPythonAnalysis.adapt(files, NEVER, policy, cache);
    assertTrue(program.incompletePaths.isEmpty());
    BankAnalysis bank = BankAnalysis.analyze(program, policy, NEVER);
    assertTrue(hasDisposition(bank.assessments, BankPolicy.GUARD, "OBSERVED"));
    assertNotNull(cache.parse(file, NEVER).tree);
    assertEquals("", cache.parse(file, NEVER).failureReason);
  }

  private SourceFile repeatedAssignments(int count) {
    StringBuilder source = new StringBuilder();
    for (int i = 0; i < count; i++) source.append("value=1\n");
    return new SourceFile("bounded.py", source.toString());
  }

  private boolean hasCode(List<Map<String, Object>> diagnostics, String code) {
    for (Map<String, Object> diagnostic : diagnostics)
      if (code.equals(diagnostic.get("code"))) return true;
    return false;
  }

  private boolean hasDisposition(
      List<Map<String, Object>> assessments, String rule, String disposition) {
    for (Map<String, Object> assessment : assessments)
      if (rule.equals(assessment.get("ruleId")) && disposition.equals(assessment.get("disposition")))
        return true;
    return false;
  }

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
}
