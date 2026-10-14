package dev.aiguard.compat;

import static org.junit.Assert.*;

import dev.aiguard.compat.pygrammar.Python3Lexer;
import dev.aiguard.compat.pygrammar.Python3Parser;
import java.util.Arrays;
import java.util.Map;
import org.antlr.v4.runtime.BaseErrorListener;
import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.RecognitionException;
import org.antlr.v4.runtime.Recognizer;
import org.junit.Test;

public class PythonSyntaxTest {
  private int syntaxErrors(String source) {
    final int[] errors = {0};
    BaseErrorListener listener =
        new BaseErrorListener() {
          public void syntaxError(
              Recognizer<?, ?> recognizer,
              Object token,
              int line,
              int column,
              String message,
              RecognitionException cause) {
            errors[0]++;
          }
        };
    Python3Lexer lexer = new Python3Lexer(CharStreams.fromString(source));
    lexer.removeErrorListeners();
    lexer.addErrorListener(listener);
    Python3Parser parser = new Python3Parser(new CommonTokenStream(lexer));
    parser.removeErrorListeners();
    parser.addErrorListener(listener);
    parser.file_input();
    return errors[0];
  }

  @Test
  public void caseIsAnOrdinaryLoopAndUnpackingName() {
    assertEquals(
        0,
        syntaxErrors(
            "def collect(items):\n"
                + "    result = []\n"
                + "    for case in items:\n"
                + "        name, case = case.get('name'), case\n"
                + "        if case:\n"
                + "            result.append(case)\n"
                + "    return result\n"));
  }

  @Test
  public void softKeywordsWorkAsParametersAttributesAndImportAliases() {
    assertEquals(
        0,
        syntaxErrors(
            "from module import case as match\n"
                + "import package.case as case\n"
                + "class Container:\n"
                + "    def case(self, case, match, _):\n"
                + "        self.case = case\n"
                + "        return self.case(match=match, case=_, value=case)\n"));
  }

  @Test
  public void realMatchAndCaseBlocksRemainSupported() {
    assertEquals(
        0,
        syntaxErrors(
            "def choose(case):\n"
                + "    match case:\n"
                + "        case 1:\n"
                + "            return 'one'\n"
                + "        case _:\n"
                + "            return 'other'\n"));
  }

  @Test
  public void orphanAndMalformedCaseClausesAreRejected() {
    assertTrue(syntaxErrors("case 1:\n    pass\n") > 0);
    assertTrue(syntaxErrors("match value:\n    case :\n        pass\n") > 0);
    assertTrue(syntaxErrors("match value:\n    case 1\n        pass\n") > 0);
  }

  @Test
  public void hardKeywordsRemainReserved() {
    assertTrue(syntaxErrors("class = 1\n") > 0);
    assertTrue(syntaxErrors("def f(return):\n    pass\n") > 0);
  }

  @Test
  public void sdkClientAndResponseRenamingToCasePreservesEvidence() {
    String source =
        "from openai import OpenAI\n"
            + "import logging\n"
            + "client = OpenAI()\n"
            + "reply = client.chat.completions.create(model='model', messages=[])\n"
            + "logging.info(reply.choices[0].message.content)\n";
    assertRawLoggingEvidence(source);
    assertRawLoggingEvidence(source.replace("client", "case"));
    assertRawLoggingEvidence(source.replace("reply", "case"));
  }

  private void assertRawLoggingEvidence(String source) {
    AnalysisResult result =
        PythonAnalysis.analyze(
            Arrays.asList(new SourceFile("renamed.py", source)),
            new Cancel() {
              public void check() {}
            });
    for (Map<String, Object> diagnostic : result.diagnostics)
      assertNotEquals("PYTHON_PARSE_FAILED", diagnostic.get("code"));
    assertTrue(result.aiDetected);
    for (Map<String, Object> assessment : result.assessments)
      if ("AI-PY-003".equals(assessment.get("ruleId"))
          && "VIOLATED".equals(assessment.get("disposition"))) return;
    fail("Renaming an ordinary identifier must preserve proven model-to-log provenance");
  }
}
