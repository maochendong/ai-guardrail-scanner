package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.concurrent.CancellationException;
import org.junit.Test;

public class JavaSyntaxCacheTest {
  private static final Cancel NONE =
      new Cancel() {
        public void check() {}
      };

  @Test
  public void sameSnapshotIsParsedOnceButReplacementIsNotStale() {
    JavaSyntax.Cache cache = new JavaSyntax.Cache();
    SourceFile original = new SourceFile("src/A.java", "class A {void first(){}}");
    JavaSyntax.Unit first = cache.parse(original, NONE);
    final int[] checks = {0};
    assertSame(
        first,
        cache.parse(
            original,
            new Cancel() {
              public void check() {
                checks[0]++;
              }
            }));
    assertTrue(
        "A cache hit must still check cancellation without reparsing",
        checks[0] > 0 && checks[0] < 10);
    JavaSyntax.Unit replacement =
        cache.parse(new SourceFile("src/A.java", "class A {void second(){}}"), NONE);
    assertEquals("first", first.methods.get(0).name);
    assertEquals("second", replacement.methods.get(0).name);
  }

  @Test(expected = CancellationException.class)
  public void cancellationIsCheckedOnCacheHits() {
    JavaSyntax.Cache cache = new JavaSyntax.Cache();
    SourceFile file = new SourceFile("src/A.java", "class A {}");
    cache.parse(file, NONE);
    cache.parse(
        file,
        new Cancel() {
          public void check() {
            throw new CancellationException();
          }
        });
  }

  @Test
  public void failedParseRemainsFailedWhenShared() {
    JavaSyntax.Cache cache = new JavaSyntax.Cache();
    SourceFile file = new SourceFile("src/A.java", "class A { void broken( }");
    JavaSyntax.Unit failed = cache.parse(file, NONE);
    assertTrue(failed.syntaxErrors > 0);
    assertSame(failed, cache.parse(file, NONE));
    assertNull(failed.root);
  }

  @Test
  public void commonAndBankAdaptersKeepIndependentGraphState() {
    SourceFile file =
        new SourceFile(
            "src/A.java", "import remote.Port;class A{static{Port.send();}void f(){Port.send();}}");
    JavaSyntax.Cache cache = new JavaSyntax.Cache();
    JavaSyntax.Unit unit = cache.parse(file, NONE);
    AnalysisResult first = JavaAnalysis.analyze(Arrays.asList(file), NONE, cache);
    BankFlow.Program bank =
        BankJavaAnalysis.adapt(Arrays.asList(file), NONE, BankPolicy.generic(), cache);
    AnalysisResult again = JavaAnalysis.analyze(Arrays.asList(file), NONE, cache);
    assertSame(unit, cache.parse(file, NONE));
    assertEquals(2, bank.functions.size());
    assertEquals(first.assessments, again.assessments);
    assertEquals(first.diagnostics, again.diagnostics);
    assertEquals(JavaAnalysis.analyze(Arrays.asList(file), NONE).assessments, again.assessments);
  }
}
